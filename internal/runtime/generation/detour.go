package generation

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"

	"github.com/MimoProxy/reka/internal/backend/sagernet"
	"github.com/MimoProxy/reka/internal/config/compile"
	"github.com/MimoProxy/reka/internal/router"
)

type outboundDetour struct {
	engine       *Engine
	prepared     *Prepared
	node, target string
	owner        atomic.Pointer[sagernet.Outbound]
	ready        atomic.Bool
	mu           sync.RWMutex
	closed       bool
	pins         map[string]*sagernet.PinnedOutbound
}

func (e *Engine) newDetour(p *Prepared, o compile.Outbound) *outboundDetour {
	return &outboundDetour{engine: e, prepared: p, node: o.ID, target: o.Dialer.Proxy, pins: map[string]*sagernet.PinnedOutbound{}}
}
func (d *outboundDetour) spec() *sagernet.DetourSpec {
	return &sagernet.DetourSpec{Dial: d.dial, Packet: d.packet, Release: d.close}
}
func (d *outboundDetour) attach() error {
	for _, id := range d.prepared.eff.DetourLeaves(d.target) {
		out := d.prepared.outbounds[id]
		if out == nil {
			continue
		} // reject/PASS are intentionally non-dialing.
		pin, err := out.Pin()
		if err != nil {
			return err
		}
		d.mu.Lock()
		d.pins[id] = pin
		d.mu.Unlock()
	}
	return nil
}
func (d *outboundDetour) parent(network, address string) (*sagernet.PinnedOutbound, error) {
	if !d.ready.Load() {
		return nil, errors.New("detour is not prepared")
	}
	eff, manager := d.prepared.eff, d.prepared.policies
	// Rule-only revisions retain the child. New connections then observe the
	// active policy manager, while the parent's immutable transport graph is
	// unchanged (dependency fingerprints enforce that invariant).
	current, g := d.engine.current()
	if current.Resources[d.node] == d.owner.Load() {
		eff, manager = g.eff, g.policies
	}
	id, chain, err := eff.Router.ResolveDynamic(d.target, func(group router.Group) string {
		if manager != nil {
			return manager.Choose(group.ID, "detour:"+address, group.Selected)
		}
		return group.Selected
	})
	if err != nil {
		return nil, errors.New("detour target unavailable")
	}
	if network == "udp" {
		for _, group := range chain {
			if eff.GroupUDPDisabled[group] {
				return nil, errors.New("detour group disables UDP")
			}
		}
		out, ok := eff.Outbound(id)
		if !ok || !out.UDP {
			return nil, errors.New("detour parent disables UDP")
		}
	}
	if manager != nil {
		manager.MarkUsed(id)
	}
	d.mu.RLock()
	pin, closed := d.pins[id], d.closed
	d.mu.RUnlock()
	if pin == nil || closed {
		return nil, errors.New("detour parent unavailable or rejected")
	}
	return pin, nil
}
func (d *outboundDetour) dial(ctx context.Context, network, address string) (net.Conn, error) {
	parent, err := d.parent(network, address)
	if err != nil {
		return nil, err
	}
	return parent.Dial(ctx, network, address)
}
func (d *outboundDetour) packet(ctx context.Context, address string) (net.PacketConn, error) {
	parent, err := d.parent("udp", address)
	if err != nil {
		return nil, err
	}
	return parent.ListenPacket(ctx, address)
}
func (d *outboundDetour) close() error {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return nil
	}
	d.closed = true
	pins := make([]*sagernet.PinnedOutbound, 0, len(d.pins))
	for _, pin := range d.pins {
		pins = append(pins, pin)
	}
	d.mu.Unlock()
	for _, pin := range pins {
		pin.Close()
	}
	return nil
}
func setSpecDetour(spec any, detour *sagernet.DetourSpec) any {
	switch value := spec.(type) {
	case sagernet.ProxySpec:
		value.Detour = detour
		return value
	case sagernet.VLESSSpec:
		value.Detour = detour
		return value
	}
	return spec
}
