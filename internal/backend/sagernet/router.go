package sagernet

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/MimoProxy/reka/internal/history"
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
	InboundUser     string
	InboundPort     uint16
	InboundProtocol string
	Inbound         string
	InboundType     string
	Network         string // "tcp" or "udp"
	Source          netip.AddrPort
	Destination     Destination
	// SniffedDomain is a routing hint; Destination retains the original target.
	SniffedDomain string
	Protocol      string
	// Local is the listener address the client connected to, used to find
	// the owning process. It may be invalid.
	Local netip.AddrPort
	// ClientSource is the socket peer for MITM admission on TCP listeners.
	// Source can instead contain a proxy-supplied address.
	ClientSource netip.Addr
	// SkipMITM marks streams already handled by an HTTP proxy.
	SkipMITM bool
}

// Route is the routing decision for one connection.
type Route struct {
	Scope history.Scope
	Owner ProcessInfo
	// Context attaches generation-owned dependencies without replacing the
	// caller's cancellation or deadline.
	Context     func(context.Context) context.Context
	Lookup      LookupFunc
	Destination *Destination
	// Outbound carries the connection, with a lease already taken (see
	// Outbound.Lease). Nil rejects the connection.
	Outbound *Outbound
	// Release gives the lease back; the relay calls it once when the
	// connection ends.
	Release func()
	MITM    *MITMRoute
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
	routerServices
	backend    *Backend
	route      atomic.Pointer[RouteFunc]
	prepare    atomic.Pointer[PrepareFlowFunc]
	preMatchFn atomic.Pointer[PreMatchFunc]
	sniffOnce  sync.Once
	sniffSlots chan struct{}
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
	return normalizeRoute((*fn)(ctx, md))
}

func normalizeRoute(rt Route) Route {
	if rt.Outbound == nil {
		if rt.Release != nil {
			rt.Release()
		}
		return Route{Info: rt.Info, Scope: rt.Scope}
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
		InboundUser:   m.User,
		Inbound:       m.Inbound,
		InboundType:   m.InboundType,
		Network:       m.Network,
		Source:        m.Source.AddrPort(),
		SniffedDomain: m.Domain,
		Protocol:      m.Protocol,
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

func toFlowMetadata(ctx context.Context, metadata adapter.InboundContext) Metadata {
	md := toMetadata(metadata)
	md.InboundProtocol = inboundProtocol(ctx, md.InboundType)
	return md
}

func (r *router) RouteConnectionEx(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	metadata.Network = N.NetworkTCP
	md := toFlowMetadata(ctx, metadata)
	_, debugBridge := conn.(*debugBridge)
	md.SkipMITM = debugBridge
	if peer, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		md.ClientSource = peer.AddrPort().Addr()
	} else if md.InboundType == "http" || md.InboundType == "mixed" {
		// The HTTP inbound uses a pipe for parsed forward requests and
		// upgrades. A CONNECT tunnel keeps the original client socket.
		md.SkipMITM = true
	}
	if md.InboundType != "tun" && conn.LocalAddr() != nil {
		if address, err := netip.ParseAddrPort(conn.LocalAddr().String()); err == nil {
			md.InboundPort = address.Port()
		}
	}
	attempt := r.backend.beginConnection(ctx, md)
	ctx = withAttempt(ctx, attempt)
	prepared := r.prepareFlow(ctx, md)
	defer prepared.Release()
	if !debugBridge && prepared.Sniff.streamEligible(md) && r.takeSniffSlot() {
		start := time.Now()
		var observed sniffObservation
		conn, md, observed = sniffStream(ctx, conn, md, prepared.Sniff)
		attempt.sniffing(start, md, observed)
		r.releaseSniffSlot()
	}
	attempt.routing(time.Now())
	rt := prepared.pick(ctx, md)
	prepared.Release()
	if rt.Outbound == nil {
		attempt.setRoute(rt, md.Destination.Addr)
		bindRequestConnection(ctx, attempt)
		attempt.complete(connectionReason(ctx.Err(), "rejected"), "route")
		N.CloseOnHandshakeFailure(conn, onClose, errRejected)
		r.backend.logger.DebugContext(ctx, "reject ", metadata.Destination)
		return
	}
	if prepared.Sniff.OverrideDestination && md.SniffedDomain != "" {
		destination := Destination{Domain: md.SniffedDomain, Port: md.Destination.Port}
		rt.Destination = &destination
	}
	metadata.Domain, metadata.Protocol = md.SniffedDomain, md.Protocol
	attempt.setRoute(rt, md.Destination.Addr)
	bindRequestConnection(ctx, attempt)
	r.backend.relayTCP(ctx, rt, conn, metadata, onClose, attempt)
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

// Reka owns these services outside sing-box. Both inbound and outbound-only
// endpoint routers implement their connection handling separately.
type routerServices struct{}

func (routerServices) Start(adapter.StartStage, *adapter.Scope) error { return nil }

func (r *router) PreMatch(adapter.InboundContext, []byte) adapter.PreMatchResult {
	return adapter.PreMatchResult{Action: adapter.PreMatchContinue}
}

func (*router) HijackDNSPacket(context.Context, []byte, N.PacketWriter, adapter.InboundContext) {}

func (routerServices) RuleSet(string) (adapter.RuleSet, bool)     { return nil, false }
func (routerServices) Rules() []adapter.Rule                      { return nil }
func (routerServices) NeedFindProcess() bool                      { return false }
func (routerServices) NeedFindNeighbor() bool                     { return false }
func (routerServices) NeighborResolver() adapter.NeighborResolver { return nil }
func (routerServices) AppendTracker(adapter.ConnectionTracker)    {}
func (routerServices) ResetNetwork()                              {}

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
