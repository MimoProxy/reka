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
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/MimoProxy/reka/internal/backend/sagernet"
	"github.com/MimoProxy/reka/internal/config/service"
	"github.com/MimoProxy/reka/internal/control"
	"github.com/MimoProxy/reka/internal/platform"
	"github.com/MimoProxy/reka/internal/runtime/generation"
	"github.com/MimoProxy/reka/internal/secret"
)

// Options configure Start.
type Options struct {
	FailPoint          func(string) error
	InitialArchiveHash string
	ProfileRoot        string
	ProfileID          string
	ProfileNested      bool
	ProfileResume      bool
	DeferNetwork       bool
	ProcessInfoLookup  func(context.Context, sagernet.Metadata) (sagernet.ProcessInfo, bool)
	ProcessLookup      func(context.Context, sagernet.Metadata) (string, bool)
	TUNFD              int
	StateRoot          string
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
	InitialSources []byte
	InitialOverlay []byte
}

// Kernel is a running kernel.
type Kernel struct {
	stateLock *platform.StateLock
	Service   *service.Service
	Handler   *control.Handler
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
	var workspace *service.ProfileWorkspace
	runtimeRoot := opts.StateRoot
	if opts.ProfileRoot != "" {
		if opts.EditDir != "" {
			return nil, errors.New("profile workspace requires candidate-file watching disabled")
		}
		var err error
		workspace, err = service.OpenProfileWorkspace(opts.ProfileRoot, opts.ProfileID, opts.ProfileNested, opts.ProfileResume)
		if err != nil {
			return nil, err
		}
		opts.StateRoot, err = workspace.StateRoot()
		if err != nil {
			workspace.Close()
			return nil, err
		}
		runtimeRoot, err = workspace.RuntimeRoot()
		if err != nil {
			workspace.Close()
			return nil, err
		}
	}
	stateLock, err := platform.LockStateRoot(opts.StateRoot)
	if err != nil {
		if workspace != nil {
			workspace.Close()
		}
		return nil, err
	}
	success := false
	defer func() {
		if !success {
			stateLock.Close()
			if workspace != nil {
				workspace.Close()
			}
		}
	}()
	if workspace != nil {
		if err := workspace.LockRuntime(); err != nil {
			return nil, err
		}
	}
	if opts.LogLevel == nil {
		opts.LogLevel = new(slog.LevelVar)
	}
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: opts.LogLevel}))
	}
	if opts.Secrets == nil {
		s, err := secret.Default(opts.StateRoot)
		if err != nil {
			return nil, fmt.Errorf("secret store: %w", err)
		}
		opts.Secrets = s
	}
	logEvents := new(atomic.Pointer[service.Broker])
	opts.Logger = slog.New(&eventLogHandler{Handler: opts.Logger.Handler(), target: logEvents})
	bopts := sagernet.Options{Logger: opts.Logger, FindProcess: true}
	bopts.ProtectFD = opts.Protect
	bopts.ProcessLookup = opts.ProcessLookup
	bopts.ProcessInfoLookup = opts.ProcessInfoLookup
	var profileID string
	if workspace != nil {
		profileID = workspace.InitialProfileID()
	}
	eng := generation.NewEngine(generation.EngineOptions{ProfileID: profileID, Backend: bopts, LogLevel: opts.LogLevel, StateRoot: runtimeRoot, TUNFD: opts.TUNFD})
	if opts.InitialArchiveHash != "" {
		if err := service.InstallInitialProfileArchive(opts.StateRoot, opts.InitialArchiveHash, eng.ProcessLookup()); err != nil {
			eng.Close()
			return nil, err
		}
	}
	svc, err := service.Open(service.Options{
		DeferNetwork: opts.DeferNetwork, RuntimeStateRoot: runtimeRoot, FailPoint: opts.FailPoint,
		StateRoot: opts.StateRoot, Secrets: opts.Secrets, Engine: eng, Logger: opts.Logger,
		InitialProfile: opts.InitialProfile, InitialLocal: opts.InitialLocal, InitialSources: opts.InitialSources, InitialOverlay: opts.InitialOverlay,
	})
	if err != nil {
		eng.Close()
		return nil, err
	}
	if err = svc.BindProfiles(workspace); err != nil {
		svc.Close()
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	logEvents.Store(svc.Events())
	k := &Kernel{stateLock: stateLock, Service: svc, Handler: control.NewHandler(svc), cancel: cancel}

	if err := svc.StartSubscriptions(service.RefreshOptions{Client: eng.SubscriptionClient(), ClientFor: eng.SubscriptionProxyClient}); err != nil {
		k.Close()
		return nil, err
	}

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
	k.wg.Add(1)
	go func() {
		defer k.wg.Done()
		tick := time.NewTicker(5 * time.Second)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				eng.CheckNetwork()
			}
		}
	}()
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
	success = true
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
		k.stateLock.Close()
	})
}
