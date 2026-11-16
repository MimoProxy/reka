package sagernet

import (
	"context"
	"errors"
	"net"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"
)

// DetourSpec supplies a generation-bound parent route without exposing the
// component API outside this package. Release drops the parent's dependency
// pins after this outbound's own scope has closed.
type DetourSpec struct {
	Dial    func(context.Context, string, string) (net.Conn, error)
	Packet  func(context.Context, string) (net.PacketConn, error)
	Release func() error
}

func (d *DetourSpec) Close() error {
	if d != nil && d.Release != nil {
		return d.Release()
	}
	return nil
}

type nativeDetour struct {
	outbound.Adapter
	spec *DetourSpec
}

func (d *nativeDetour) DialContext(ctx context.Context, network string, dst M.Socksaddr) (net.Conn, error) {
	return d.spec.Dial(ctx, network, dst.String())
}
func (d *nativeDetour) ListenPacket(ctx context.Context, dst M.Socksaddr) (net.PacketConn, error) {
	return d.spec.Packet(ctx, dst.String())
}
func detourContext(ctx context.Context, spec *DetourSpec) context.Context {
	if spec == nil {
		return ctx
	}
	ctx = service.ExtendContext(ctx)
	service.MustRegister[adapter.OutboundManager](ctx, &singleOutboundManager{out: &nativeDetour{outbound.NewAdapter("direct", "reka-detour", []string{"tcp", "udp"}, nil), spec}})
	return ctx
}

// PinnedOutbound retains one dependency lease. Its owner can retire while
// existing borrowed sockets keep the pin alive. New borrows stop at Close.
// This permits an old child to keep its exact parent after a configuration
// switch, without acquiring a new lease from a retired parent.
type PinnedOutbound struct {
	out        *Outbound
	mu         sync.Mutex
	references int
	closed     bool
}

func (o *Outbound) Pin() (*PinnedOutbound, error) {
	if !o.lease.Acquire() {
		return nil, errors.New("detour parent retired")
	}
	o.dependencyPins.Add(1)
	return &PinnedOutbound{out: o, references: 1}, nil
}
func (p *PinnedOutbound) retain() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return false
	}
	p.references++
	return true
}
func (p *PinnedOutbound) release() {
	p.mu.Lock()
	p.references--
	last := p.references == 0
	p.mu.Unlock()
	if last {
		p.out.dependencyPins.Add(-1)
		p.out.lease.Release()
	}
}
func (p *PinnedOutbound) Close() error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	p.mu.Unlock()
	p.release()
	return nil
}
func (p *PinnedOutbound) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	if !p.retain() {
		return nil, net.ErrClosed
	}
	c, err := p.out.out.DialContext(ctx, network, M.ParseSocksaddr(address))
	if err != nil {
		p.release()
		return nil, err
	}
	return &leasedConn{Conn: c, release: p.release}, nil
}
func (p *PinnedOutbound) ListenPacket(ctx context.Context, address string) (net.PacketConn, error) {
	if !p.retain() {
		return nil, net.ErrClosed
	}
	c, err := p.out.out.ListenPacket(ctx, M.ParseSocksaddr(address))
	if err != nil {
		p.release()
		return nil, err
	}
	return &pinnedPacketConn{PacketConn: c, release: p.release}, nil
}

type pinnedPacketConn struct {
	net.PacketConn
	release func()
	once    sync.Once
}

func (c *pinnedPacketConn) Close() error {
	err := c.PacketConn.Close()
	c.once.Do(c.release)
	return err
}
