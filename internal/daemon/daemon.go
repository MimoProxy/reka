// Package daemon assembles a running kernel: secret store, runtime engine,
// ConfigService, control API server and candidate-file watcher. The
// desktop command and the Android library both start it.
package daemon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"

	"github.com/MimoProxy/reka/internal/backend/sagernet"
	"github.com/MimoProxy/reka/internal/config/service"
	"github.com/MimoProxy/reka/internal/control"
	"github.com/MimoProxy/reka/internal/runtime/generation"
	"github.com/MimoProxy/reka/internal/secret"
)

// Options configure Start.
type Options struct {
	StateRoot string
	// Secrets defaults to the platform store for StateRoot.
	Secrets  secret.Store
	Logger   *slog.Logger
	LogLevel *slog.LevelVar
	// Protect is applied to every outbound socket (Android VpnService).
	Protect func(fd int) error
	// ControlAddress is where the control API listens. Empty uses the
	// local settings' control.listen, else the platform default; "-"
	// disables the socket (the Android binding calls the handler
	// directly).
	ControlAddress string
	// EditDir holds candidate files; empty disables them.
	EditDir        string
	InitialProfile []byte
	InitialLocal   []byte
}

// Kernel is a running kernel.
type Kernel struct {
	Service *service.Service
	Handler *control.Handler
	// ControlAddress is where the control API listens, if anywhere.
	ControlAddress string

	server *control.Server
	cancel context.CancelFunc
	wg     sync.WaitGroup
	once   sync.Once
}

// Start opens the state root, starts the active revision and serves the
// control API.
func Start(opts Options) (*Kernel, error) {
	if opts.StateRoot == "" {
		return nil, errors.New("state root is required")
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.Secrets == nil {
		s, err := secret.Default(opts.StateRoot)
		if err != nil {
			return nil, fmt.Errorf("secret store: %w", err)
		}
		opts.Secrets = s
	}
	bopts := sagernet.Options{Logger: opts.Logger, FindProcess: true}
	bopts.ProtectFD = opts.Protect
	eng := generation.NewEngine(generation.EngineOptions{Backend: bopts, LogLevel: opts.LogLevel})
	svc, err := service.Open(service.Options{
		StateRoot: opts.StateRoot, Secrets: opts.Secrets, Engine: eng, Logger: opts.Logger,
		InitialProfile: opts.InitialProfile, InitialLocal: opts.InitialLocal,
	})
	if err != nil {
		eng.Close()
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	k := &Kernel{Service: svc, Handler: control.NewHandler(svc), cancel: cancel}

	addr := opts.ControlAddress
	if addr == "" {
		if cfg := svc.GetConfiguration(false); cfg.Effective != nil && cfg.Effective.Control != "" {
			addr = cfg.Effective.Control
		} else {
			addr = control.DefaultAddress(opts.StateRoot)
		}
	}
	if addr != "-" {
		ln, err := control.Listen(addr)
		if err != nil {
			k.Close()
			return nil, fmt.Errorf("control API: %w", err)
		}
		k.ControlAddress = addr
		k.server = control.NewServer(k.Handler)
		k.wg.Add(1)
		go func() {
			defer k.wg.Done()
			if err := k.server.Serve(ln); err != nil && !errors.Is(err, net.ErrClosed) {
				opts.Logger.Error("control API stopped", "err", err)
			}
		}()
	}
	if opts.EditDir != "" {
		c := svc.NewCandidate(opts.EditDir)
		k.wg.Add(1)
		go func() {
			defer k.wg.Done()
			if err := c.Run(ctx); err != nil {
				opts.Logger.Error("candidate files stopped", "dir", opts.EditDir, "err", err)
			}
		}()
	}
	return k, nil
}

// Close stops the control API, the watcher and the runtime.
func (k *Kernel) Close() {
	k.once.Do(func() {
		k.cancel()
		if k.server != nil {
			k.server.Close()
		}
		k.wg.Wait()
		k.Service.Close()
	})
}
