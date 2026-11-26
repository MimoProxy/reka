package generation

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"path/filepath"
	"strings"
	"sync/atomic"

	"github.com/MimoProxy/reka/internal/api"
	"github.com/MimoProxy/reka/internal/backend/sagernet"
	"github.com/MimoProxy/reka/internal/config/compile"
	M "github.com/sagernet/sing/common/metadata"
)

type tailscaleNodeFactory func(string, sagernet.TailscaleOptions) (sagernet.TailscaleNode, error)

// A handle belongs to one node configuration. Outbounds can hold the handle
// across generations, while only the engine can replace or close the node.
type tailscaleLink struct {
	id   string
	tag  string
	opts sagernet.TailscaleOptions
	live atomic.Pointer[tailscaleLinkState]
}

type tailscaleLinkState struct {
	node  sagernet.TailscaleNode
	state string
	err   string
}

func (e *Engine) prepareTailscale(eff *compile.Effective) (*tailscaleLink, error) {
	var link *tailscaleLink
	for _, o := range eff.Outbounds {
		if o.Tailscale == nil {
			continue
		}
		if link != nil {
			return nil, errors.New("only one Tailscale link is supported")
		}
		cfg := o.Tailscale
		// A missing state directory fails only this link: the node reports
		// the error and its outbound rejects new flows.
		stateRoot := e.opts.TailscaleStateDir
		if stateRoot == "" && e.opts.StateRoot != "" {
			stateRoot = filepath.Join(e.opts.StateRoot, "tailscale")
		}
		stateDirectory := ""
		if stateRoot != "" {
			stateDirectory = filepath.Join(stateRoot, cfg.ID)
		}
		opts := sagernet.TailscaleOptions{
			StateDirectory: stateDirectory,
			ControlURL:     cfg.ControlURL,
			AuthKey:        cfg.AuthKey,
			Hostname:       cfg.Hostname,
			Ephemeral:      cfg.Ephemeral,
			AcceptRoutes:   cfg.AcceptRoutes,
			HostPacketFlow: e.opts.HostPacketFlow,
		}
		if active := e.tailscale.Load(); active != nil && active.tag == o.ID && active.opts == opts {
			link = active
		} else {
			link = &tailscaleLink{id: cfg.ID, tag: o.ID, opts: opts}
			link.live.Store(&tailscaleLinkState{state: api.TailscaleStarting})
		}
	}
	return link, nil
}

// replaceTailscale runs under the engine lock after activation succeeds.
// The old node finishes shutting down before the next one starts.
func (e *Engine) replaceTailscale(next *tailscaleLink) {
	previous := e.tailscale.Load()
	if next == previous {
		return
	}
	e.tailscale.Store(next)
	if previous != nil {
		state := previous.live.Swap(&tailscaleLinkState{state: api.TailscaleStopped})
		if state.node != nil {
			if err := state.node.Close(); err != nil {
				e.tailscaleLogger().Warn("close Tailscale link", "outbound", previous.tag, "err", previous.safeError(err))
			}
		}
	}
	if next == nil {
		return
	}
	e.startTailscale(next)
}

func (e *Engine) startTailscale(link *tailscaleLink) {
	node, err := e.opts.newTailscaleNode(link.tag, link.opts)
	if err != nil {
		message := link.safeError(err)
		link.live.Store(&tailscaleLinkState{state: api.TailscaleError, err: message})
		e.tailscaleLogger().Error("start Tailscale link", "outbound", link.tag, "err", message)
		return
	}
	link.live.Store(&tailscaleLinkState{node: node})
}

// retryTailscale retries a local startup failure on an explicit network reset.
// A started node handles network changes through its own monitor.
func (e *Engine) retryTailscale() {
	link := e.tailscale.Load()
	if link == nil || link.live.Load().state != api.TailscaleError {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.closed && link == e.tailscale.Load() && link.live.Load().state == api.TailscaleError {
		link.live.Store(&tailscaleLinkState{state: api.TailscaleStarting})
		e.startTailscale(link)
	}
}

func (e *Engine) tailscaleLogger() *slog.Logger {
	if e.opts.Backend.Logger != nil {
		return e.opts.Backend.Logger
	}
	return slog.Default()
}

func (l *tailscaleLink) safeError(err error) string {
	if l.opts.AuthKey != "" {
		return strings.ReplaceAll(err.Error(), l.opts.AuthKey, "[redacted]")
	}
	return err.Error()
}

func (l *tailscaleLink) node() (sagernet.TailscaleNode, error) {
	state := l.live.Load()
	if state.node != nil {
		return state.node, nil
	}
	if state.err != "" {
		return nil, fmt.Errorf("Tailscale link %s: %s: %s", l.id, state.state, state.err)
	}
	return nil, fmt.Errorf("Tailscale link %s: %s", l.id, state.state)
}

func (l *tailscaleLink) DialContext(ctx context.Context, network string, dest M.Socksaddr) (net.Conn, error) {
	node, err := l.node()
	if err != nil {
		return nil, err
	}
	return node.DialContext(ctx, network, dest)
}

func (l *tailscaleLink) ListenPacket(ctx context.Context, dest M.Socksaddr) (net.PacketConn, error) {
	node, err := l.node()
	if err != nil {
		return nil, err
	}
	return node.ListenPacket(ctx, dest)
}

// TailscaleStatus reports the current local link and never starts a node.
func (e *Engine) TailscaleStatus() api.TailscaleStatus {
	status := api.TailscaleStatus{State: api.TailscaleStopped}
	if link := e.tailscale.Load(); link != nil {
		live := link.live.Load()
		if live.node != nil {
			status = live.node.Status()
		} else {
			status.State = live.state
			status.LastError = live.err
		}
		status.ID = link.id
	}
	if status.State != api.TailscaleNeedsLogin {
		status.AuthURL = ""
	}
	if status.TailscaleIPs == nil {
		status.TailscaleIPs = []netip.Addr{}
	}
	if status.Peers == nil {
		status.Peers = []api.TailscalePeer{}
	}
	return status
}
