package sagernet

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"

	"github.com/sagernet/sing-box/adapter"
	N "github.com/sagernet/sing/common/network"
)

// Destination is where a connection wants to go. Exactly one of Domain or
// Addr is set.
type Destination struct {
	Domain string
	Addr   netip.Addr
	Port   uint16
}

func (d Destination) String() string {
	if d.Domain != "" {
		return net.JoinHostPort(d.Domain, itoa(d.Port))
	}
	return netip.AddrPortFrom(d.Addr, d.Port).String()
}

// Metadata is the part of a connection Reka's router decides on.
type Metadata struct {
	Inbound     string
	Network     string // "tcp" or "udp"
	Source      netip.AddrPort
	Destination Destination
}

// RouteFunc picks the outbound for a new connection. Returning nil rejects it.
// It must be safe for concurrent use; it is called once per connection.
type RouteFunc func(Metadata) *Outbound

var errRejected = errors.New("reka: connection rejected by route")

// router is the adapter.Router handed to upstream inbounds. Upstream only
// calls the Route*Ex methods on it for mixed, socks and http inbounds; the
// rest of the interface is stubbed. Rule matching happens in Reka's RouteFunc,
// which can be swapped while inbounds keep running.
type router struct {
	backend *Backend
	route   atomic.Pointer[RouteFunc]
}

var _ adapter.Router = (*router)(nil)

func (r *router) setRoute(fn RouteFunc) {
	r.route.Store(&fn)
}

func (r *router) pick(metadata adapter.InboundContext) *Outbound {
	fn := r.route.Load()
	if fn == nil || *fn == nil {
		return nil
	}
	return (*fn)(toMetadata(metadata))
}

func toMetadata(m adapter.InboundContext) Metadata {
	md := Metadata{
		Inbound: m.Inbound,
		Network: m.Network,
		Source:  m.Source.AddrPort(),
	}
	md.Destination.Port = m.Destination.Port
	if m.Destination.IsDomain() {
		md.Destination.Domain = m.Destination.Fqdn
	} else {
		md.Destination.Addr = m.Destination.Addr.Unmap()
	}
	return md
}

func (r *router) RouteConnectionEx(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	metadata.Network = N.NetworkTCP
	out := r.pick(metadata)
	if out == nil {
		N.CloseOnHandshakeFailure(conn, onClose, errRejected)
		r.backend.logger.DebugContext(ctx, "reject ", metadata.Destination)
		return
	}
	r.backend.relayTCP(ctx, out, conn, metadata, onClose)
}

func (r *router) RoutePacketConnectionEx(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	metadata.Network = N.NetworkUDP
	out := r.pick(metadata)
	if out == nil {
		N.CloseOnHandshakeFailure(conn, onClose, errRejected)
		r.backend.logger.DebugContext(ctx, "reject ", metadata.Destination)
		return
	}
	r.backend.relayUDP(ctx, out, conn, metadata, onClose)
}

// The non-Ex variants are only used by legacy inbounds Reka does not enable.

func (r *router) RouteConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext) error {
	done := make(chan error, 1)
	r.RouteConnectionEx(ctx, conn, metadata, func(err error) { done <- err })
	return <-done
}

func (r *router) RoutePacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext) error {
	done := make(chan error, 1)
	r.RoutePacketConnectionEx(ctx, conn, metadata, func(err error) { done <- err })
	return <-done
}

func (r *router) Start(adapter.StartStage, *adapter.Scope) error { return nil }

func (r *router) PreMatch(adapter.InboundContext, []byte) adapter.PreMatchResult {
	return adapter.PreMatchResult{Action: adapter.PreMatchContinue}
}

func (r *router) HijackDNSPacket(context.Context, []byte, N.PacketWriter, adapter.InboundContext) {}
func (r *router) RuleSet(string) (adapter.RuleSet, bool)                                          { return nil, false }
func (r *router) Rules() []adapter.Rule                                                           { return nil }
func (r *router) NeedFindProcess() bool                                                           { return false }
func (r *router) NeedFindNeighbor() bool                                                          { return false }
func (r *router) NeighborResolver() adapter.NeighborResolver                                      { return nil }
func (r *router) AppendTracker(adapter.ConnectionTracker)                                         {}
func (r *router) ResetNetwork()                                                                   {}

func itoa(p uint16) string {
	var b [5]byte
	i := len(b)
	for {
		i--
		b[i] = byte('0' + p%10)
		p /= 10
		if p == 0 {
			return string(b[i:])
		}
	}
}
