package sagernet

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"

	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
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
	InboundType string
	Network     string // "tcp" or "udp"
	Source      netip.AddrPort
	Destination Destination
	// Local is the listener address the client connected to, used to find
	// the owning process. It may be invalid.
	Local netip.AddrPort
}

// Route is the routing decision for one connection.
type Route struct {
	Lookup      LookupFunc
	Destination *Destination
	// Outbound carries the connection, with a lease already taken (see
	// Outbound.Lease). Nil rejects the connection.
	Outbound *Outbound
	// Release gives the lease back; the relay calls it once when the
	// connection ends.
	Release func()
	// Info is opaque to the backend and shown in connection listings.
	Info any
}

// RouteFunc picks the outbound for a new connection. It must be safe for
// concurrent use; it is called once per TCP connection and once per UDP
// destination.
type RouteFunc func(ctx context.Context, md Metadata) Route

// Fixed routes every connection to out while out accepts leases.
func Fixed(out *Outbound) RouteFunc {
	return func(context.Context, Metadata) Route {
		if out == nil || !out.lease.Acquire() {
			return Route{}
		}
		return Route{Outbound: out, Release: out.lease.Release}
	}
}

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

func (r *router) pick(ctx context.Context, md Metadata) Route {
	fn := r.route.Load()
	if fn == nil || *fn == nil {
		return Route{}
	}
	rt := (*fn)(ctx, md)
	if rt.Outbound == nil {
		if rt.Release != nil {
			rt.Release()
		}
		return Route{Info: rt.Info}
	}
	release := rt.Release
	if release == nil {
		release = func() {}
	}
	var once sync.Once
	rt.Release = func() { once.Do(release) }
	return rt
}

func toMetadata(m adapter.InboundContext) Metadata {
	md := Metadata{
		Inbound:     m.Inbound,
		InboundType: m.InboundType,
		Network:     m.Network,
		Source:      m.Source.AddrPort(),
	}
	if m.OriginDestination.IsIP() {
		md.Local = m.OriginDestination.AddrPort()
	}
	md.Destination = toDestination(m.Destination)
	return md
}

func toDestination(d M.Socksaddr) Destination {
	out := Destination{Port: d.Port}
	if d.IsDomain() {
		out.Domain = d.Fqdn
	} else {
		out.Addr = d.Addr.Unmap()
	}
	return out
}

func (r *router) RouteConnectionEx(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	metadata.Network = N.NetworkTCP
	rt := r.pick(ctx, toMetadata(metadata))
	if rt.Outbound == nil {
		N.CloseOnHandshakeFailure(conn, onClose, errRejected)
		r.backend.logger.DebugContext(ctx, "reject ", metadata.Destination)
		return
	}
	r.backend.relayTCP(ctx, rt, conn, metadata, onClose)
}

func (r *router) RoutePacketConnectionEx(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	metadata.Network = N.NetworkUDP
	r.backend.relayUDP(ctx, r, conn, metadata, onClose)
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
