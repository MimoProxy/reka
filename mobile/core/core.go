// Package core is the Android library entry, independent of JNI so it can
// be tested on any platform. The host passes its private state directory
// and a set of callbacks; control API messages are the same JSON documents
// the socket transport carries, without the length prefix.
package core

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/MimoProxy/reka/internal/backend/sagernet"
	"log/slog"
	"sync"

	"github.com/MimoProxy/reka/internal/config/service"
	"github.com/MimoProxy/reka/internal/control"
	"github.com/MimoProxy/reka/internal/daemon"
	"github.com/MimoProxy/reka/internal/secret"
)

// Host is implemented by the embedding app.
type Host interface {
	// Protect excludes a socket from the VPN (VpnService.protect).
	Protect(fd int) bool
	// Seal and Open encrypt secrets at rest, for example with an Android
	// Keystore key.
	Seal(plain []byte) ([]byte, error)
	Open(sealed []byte) ([]byte, error)
	// OnMessage receives events (and nothing else) as JSON.
	OnMessage(msg []byte)
}

// Options for Start.
type Options struct {
	DeferNetwork   bool
	TUNFD          int
	StateRoot      string
	InitialProfile []byte
	InitialLocal   []byte
	InitialSources []byte
	InitialOverlay []byte
	// ControlSocket optionally also serves the API on a Unix socket in
	// the app's directory, for the app's other processes. Empty: none.
	ControlSocket string
	Logger        *slog.Logger
}

// Instance is a running kernel inside the host app.
type Instance struct {
	life    sync.RWMutex
	stopped bool
	vpnMu   sync.Mutex
	k       *daemon.Kernel
	sess    *control.Session
	host    Host

	mu      sync.Mutex
	waiting map[uint64]chan []byte
}

var errProtect = errors.New("VpnService.protect refused the socket")

// Start runs a kernel. Only one instance per state root may run.
func Start(opts Options, host Host) (*Instance, error) {
	sec, err := secret.NewHostStore(opts.StateRoot, secret.CallbackCipher{SealFunc: host.Seal, OpenFunc: host.Open})
	if err != nil {
		return nil, err
	}
	addr := "-"
	if opts.ControlSocket != "" {
		addr = "unix://" + opts.ControlSocket
	}
	level := new(slog.LevelVar)
	logger := opts.Logger
	k, err := daemon.Start(daemon.Options{
		DeferNetwork: opts.DeferNetwork,
		ProcessInfoLookup: func(ctx context.Context, md sagernet.Metadata) (sagernet.ProcessInfo, bool) {
			return processOwnerForHost(host, md)
		},
		TUNFD:     opts.TUNFD,
		StateRoot: opts.StateRoot, Secrets: sec, Logger: logger, LogLevel: level,
		ControlAddress: addr, InitialProfile: opts.InitialProfile, InitialLocal: opts.InitialLocal, InitialSources: opts.InitialSources, InitialOverlay: opts.InitialOverlay,
		Protect: func(fd int) error {
			if !host.Protect(fd) {
				return errProtect
			}
			return nil
		},
	})
	if err != nil {
		return nil, err
	}
	k.Service.Engine().SetTUNFD(0) // fd is borrowed only during this start call
	in := &Instance{k: k, host: host, waiting: map[uint64]chan []byte{}}
	in.sess = k.Handler.NewSession(in.send)
	return in, nil
}

// send routes a reply to the Call waiting for it and everything else
// (events) to the host.
func (in *Instance) send(b []byte) error {
	var head struct {
		ID    uint64          `json:"id"`
		Event json.RawMessage `json:"event"`
	}
	if json.Unmarshal(b, &head) == nil && head.Event == nil {
		in.mu.Lock()
		ch := in.waiting[head.ID]
		delete(in.waiting, head.ID)
		in.mu.Unlock()
		if ch != nil {
			ch <- b
			return nil
		}
	}
	in.host.OnMessage(b)
	return nil
}

// Call handles one request message and returns its response message.
// Calls may run concurrently if their IDs differ.
func (in *Instance) closedReply(request []byte) []byte {
	var r control.Request
	_ = json.Unmarshal(request, &r)
	b, _ := json.Marshal(control.Response{ID: r.ID, Error: &service.Error{Code: service.CodeBlocked, Message: "kernel stopped"}})
	return b
}
func (in *Instance) Call(request []byte) []byte {
	in.life.RLock()
	defer in.life.RUnlock()
	if in.stopped {
		return in.closedReply(request)
	}
	return in.call(request)
}
func (in *Instance) call(request []byte) []byte {
	var head struct {
		ID uint64 `json:"id"`
	}
	json.Unmarshal(request, &head)
	ch := make(chan []byte, 1)
	in.mu.Lock()
	in.waiting[head.ID] = ch
	in.mu.Unlock()
	in.sess.Handle(request)
	select {
	case b := <-ch:
		return b
	default:
		in.mu.Lock()
		delete(in.waiting, head.ID)
		in.mu.Unlock()
		b, _ := json.Marshal(control.Response{ID: head.ID, Error: &service.Error{Code: control.CodeInternal, Message: "no response"}})
		return b
	}
}

// Stop shuts the kernel down.
func (in *Instance) Stop() {
	in.life.Lock()
	defer in.life.Unlock()
	if in.stopped {
		return
	}
	in.stopped = true
	in.sess.Close()
	in.k.Close()
}

// ReconfigureVPN borrows a newly established descriptor for a synchronous
// configuration commit. The library duplicates it; the host retains ownership.
func (in *Instance) ReconfigureVPN(fd int, request []byte) []byte {
	in.vpnMu.Lock()
	defer in.vpnMu.Unlock()
	in.life.RLock()
	defer in.life.RUnlock()
	if in.stopped {
		return in.closedReply(request)
	}
	var req control.Request
	if err := json.Unmarshal(request, &req); err != nil || req.Method != "CommitConfiguration" || fd <= 0 {
		b, _ := json.Marshal(control.Response{ID: req.ID, Error: &service.Error{Code: service.CodeBadRequest, Message: "reconfigureVPN requires a valid fd and CommitConfiguration request"}})
		return b
	}
	eng := in.k.Service.Engine()
	before := eng.TUNSerial()
	eng.SetTUNFD(fd)
	defer eng.SetTUNFD(0)
	reply := in.call(request)
	var result struct {
		Result struct {
			State string `json:"state"`
		} `json:"result"`
	}
	if json.Unmarshal(reply, &result) == nil && result.Result.State == "committed" && eng.TUNSerial() == before {
		if err := eng.RebuildTUN(); err != nil {
			b, _ := json.Marshal(control.Response{ID: req.ID, Error: &service.Error{Code: "degraded", Message: err.Error()}})
			return b
		}
	}
	return reply
}
