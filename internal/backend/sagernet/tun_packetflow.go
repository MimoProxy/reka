//go:build with_gvisor

package sagernet

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/MimoProxy/reka/internal/platform"
	D "github.com/miekg/dns"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	tun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// AttachPacketFlow uses a host-owned network interface. DNS is relayed like
// other traffic unless the host supplies the engine's DNS exchange.
func (b *Backend) AttachPacketFlow(device tun.GVisorTun, mtu int, v4, v6 netip.Prefix, tcpLimit, udpLimit int, dns func(context.Context, *D.Msg) (*D.Msg, error)) (*PacketFlow, error) {
	ctx, cancel := context.WithCancel(b.ctx)
	inbound := &TUNInbound{
		b: b, dev: device, ctx: ctx, cancel: cancel,
		cfg: platform.TUNConfig{Address4: v4.String(), Address6: v6.String(), DNSHijack: dns != nil},
		dns: dns, slots: make(chan struct{}, tunDNSConcurrency),
	}
	handler := &packetFlowHandler{
		TUNInbound: inbound,
		tcp:        newPacketFlowTable(tcpLimit),
		udp:        newPacketFlowTable(udpLimit),
		logger:     newLogger(b.slog, "packet-flow"),
	}
	options := tun.Options{
		MTU: uint32(mtu), Inet4Address: []netip.Prefix{v4}, Inet6Address: []netip.Prefix{v6},
		EXP_DisableDNSHijack: dns == nil, Logger: handler.logger,
	}
	var err error
	inbound.stack, err = tun.NewGVisor(tun.StackOptions{
		Context: ctx, Tun: device, TunOptions: options, Handler: handler, Logger: options.Logger,
		UDPTimeout: 30 * time.Second, UDPMapping: tun.NATMappingAddressAndPortDependent,
		// Leave room for replacement flows while the selected victims close.
		UDPNATMax: uint32(max(1, 2*udpLimit)),
	})
	if err == nil {
		err = inbound.stack.Start()
	}
	if err != nil {
		_ = inbound.Close()
		return nil, err
	}
	return &PacketFlow{handler: handler}, nil
}

// PacketFlow is an attached packet tunnel and its admission statistics.
type PacketFlow struct {
	handler *packetFlowHandler
}

func (p *PacketFlow) Close() error { return p.handler.Close() }

// PacketFlowStats counts limit decisions over the lifetime of the tunnel.
type PacketFlowStats struct {
	TCPRejected uint64 `json:"tcpRejected"`
	UDPRejected uint64 `json:"udpRejected"`
	TCPEvicted  uint64 `json:"tcpEvicted"`
	UDPEvicted  uint64 `json:"udpEvicted"`
	DNSOverflow uint64 `json:"dnsOverflow"`
}

// Active returns the number of TCP and UDP flows currently admitted.
func (p *PacketFlow) Active() (tcp, udp int) {
	h := p.handler
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.tcp.flows), len(h.udp.flows)
}

func (p *PacketFlow) Stats() PacketFlowStats {
	h := p.handler
	h.mu.Lock()
	defer h.mu.Unlock()
	return PacketFlowStats{
		TCPRejected: h.tcp.rejected, UDPRejected: h.udp.rejected,
		TCPEvicted: h.tcp.evicted, UDPEvicted: h.udp.evicted,
		DNSOverflow: h.dnsOverflow.Load(),
	}
}

type packetFlowHandler struct {
	*TUNInbound
	logger *slogLogger

	mu          sync.Mutex
	tcp, udp    packetFlowTable
	lastWarning time.Time
}

// ObserveSyntheticICMPEchoReply forwards the stack's local-echo notification to
// the host device when it tracks diagnostic probes.
func (h *packetFlowHandler) ObserveSyntheticICMPEchoReply(sequence uint16, payload stack.PacketData) {
	if observer, ok := h.dev.(interface {
		ObserveSyntheticICMPEchoReply(uint16, stack.PacketData)
	}); ok {
		observer.ObserveSyntheticICMPEchoReply(sequence, payload)
	}
}

type packetFlowKey struct {
	source, target netip.AddrPort
}

type packetFlowTable struct {
	limit             int
	flows             map[packetFlowKey]*admittedPacketFlow
	rejected, evicted uint64
}

func newPacketFlowTable(limit int) packetFlowTable {
	return packetFlowTable{limit: limit, flows: make(map[packetFlowKey]*admittedPacketFlow)}
}

type admittedPacketFlow struct {
	handler  *packetFlowHandler
	table    *packetFlowTable
	key      packetFlowKey
	reserved time.Time
	last     atomic.Int64
	close    func()
	evicted  bool
}

func (f *admittedPacketFlow) touch() {
	f.last.Store(time.Now().UnixNano())
}

func (f *admittedPacketFlow) release() bool {
	f.handler.mu.Lock()
	defer f.handler.mu.Unlock()
	if f.table.flows[f.key] == f {
		if f.pending(time.Now()) {
			// A new transport for the same tuple may already be on its way.
			f.table.flows[f.key] = f.handler.reservation(f.table, f.key, f.reserved)
		} else {
			delete(f.table.flows, f.key)
		}
	}
	return f.evicted
}

const packetFlowEvictionIdle = 5 * time.Second

func (f *admittedPacketFlow) pending(now time.Time) bool {
	return !f.reserved.IsZero() && now.Sub(f.reserved) < packetFlowEvictionIdle
}

var errPacketFlowReservation = errors.New("packet tunnel reservation unavailable")

func (h *packetFlowHandler) JudgeFlow(protocol uint8, source, target netip.AddrPort, first []byte) tun.FlowVerdict {
	// Local DNS exchanges use their own bounded slots.
	if h.cfg.DNSHijack && target.Port() == 53 && protocol == uint8(header.UDPProtocolNumber) {
		return tun.FlowVerdict{Action: tun.ActionHijackDNS}
	}
	// Run TUN pre-matching before touching the admission tables.
	verdict := h.TUNInbound.JudgeFlow(protocol, source, target, first)
	if verdict.Action != tun.ActionAccept || (h.cfg.DNSHijack && target.Port() == 53) {
		return verdict
	}
	var table *packetFlowTable
	var network string
	switch protocol {
	case uint8(header.TCPProtocolNumber):
		table, network = &h.tcp, N.NetworkTCP
	case uint8(header.UDPProtocolNumber):
		table, network = &h.udp, N.NetworkUDP
	default:
		return verdict
	}
	action, warn := h.reserve(table, packetFlowKey{source, target})
	if warn {
		h.logger.Warn("Packet tunnel ", network, " connection limit reached (limit ", table.limit, ")")
	}
	return tun.FlowVerdict{Action: action}
}

func (h *packetFlowHandler) reserve(table *packetFlowTable, key packetFlowKey) (tun.FlowAction, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	now := time.Now()
	// The dispatcher and the transport forwarder can judge the same packet.
	if flow := table.flows[key]; flow != nil {
		flow.reserved = now
		return tun.ActionAccept, false
	}
	if len(table.flows) >= table.limit {
		var oldest *admittedPacketFlow
		var oldestLast int64
		for _, flow := range table.flows {
			if flow.pending(now) {
				continue
			}
			if flow.close == nil {
				// No transport callback arrived for this reservation.
				delete(table.flows, flow.key)
				continue
			}
			if last := flow.last.Load(); oldest == nil || last < oldestLast {
				oldest, oldestLast = flow, last
			}
		}
		if len(table.flows) >= table.limit {
			if oldest == nil || now.UnixNano()-oldest.last.Load() < int64(packetFlowEvictionIdle) {
				table.rejected++
				warn := now.Sub(h.lastWarning) >= time.Second
				if warn {
					h.lastWarning = now
				}
				return tun.ActionReject, warn
			}
			oldest.evicted = true
			table.evicted++
			delete(table.flows, oldest.key)
			go oldest.close()
		}
	}
	// Reserve the slot before handing the flow to the stack's next callback.
	table.flows[key] = h.reservation(table, key, now)
	return tun.ActionAccept, false
}

func (h *packetFlowHandler) reservation(table *packetFlowTable, key packetFlowKey, at time.Time) *admittedPacketFlow {
	return &admittedPacketFlow{handler: h, table: table, key: key, reserved: at}
}

func (h *packetFlowHandler) NewConnectionEx(ctx context.Context, c net.Conn, source, target M.Socksaddr, onClose N.CloseHandlerFunc) {
	if h.cfg.DNSHijack && target.Port == 53 {
		h.TUNInbound.NewConnectionEx(ctx, c, source, target, onClose)
		return
	}
	ctx, flow, done := h.claim(ctx, &h.tcp, c, source, target, onClose)
	if flow != nil {
		h.TUNInbound.NewConnectionEx(ctx, &packetFlowConn{Conn: c, flow: flow}, source, target, done)
	}
}

func (h *packetFlowHandler) NewPacketConnectionEx(ctx context.Context, c N.PacketConn, source, target M.Socksaddr, onClose N.CloseHandlerFunc) {
	ctx, flow, done := h.claim(ctx, &h.udp, c, source, target, onClose)
	if flow != nil {
		h.TUNInbound.NewPacketConnectionEx(ctx, &packetFlowPacketConn{PacketConn: c, flow: flow}, source, target, done)
	}
}

func (h *packetFlowHandler) claim(ctx context.Context, table *packetFlowTable, c io.Closer, source, target M.Socksaddr, onClose N.CloseHandlerFunc) (context.Context, *admittedPacketFlow, N.CloseHandlerFunc) {
	h.mu.Lock()
	key := packetFlowKey{source.AddrPort(), target.AddrPort()}
	flow := table.flows[key]
	if flow == nil || flow.reserved.IsZero() {
		h.mu.Unlock()
		_ = N.CloseOnHandshakeFailure(c, onClose, errPacketFlowReservation)
		return nil, nil, nil
	}
	if flow.close != nil {
		// The stack has opened a new transport for an already reserved tuple.
		go flow.close()
		flow = h.reservation(table, key, flow.reserved)
		table.flows[key] = flow
	}
	ctx, cancel := context.WithCancel(ctx)
	flow.reserved = time.Time{}
	flow.touch()
	flow.close = func() {
		cancel()
		_ = c.Close()
	}
	h.mu.Unlock()
	var once sync.Once
	return context.WithValue(ctx, packetFlowReleaseKey{}, flow.release), flow, func(err error) {
		once.Do(func() {
			flow.release()
			cancel()
			if onClose != nil {
				onClose(err)
			}
		})
	}
}

type packetFlowConn struct {
	net.Conn
	flow *admittedPacketFlow
}

func (c *packetFlowConn) Upstream() any { return c.Conn }

func (c *packetFlowConn) CloseWrite() error { return N.CloseWrite(c.Conn) }

func (c *packetFlowConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.flow.touch()
	}
	return n, err
}

func (c *packetFlowConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.flow.touch()
	}
	return n, err
}

type packetFlowPacketConn struct {
	N.PacketConn
	flow *admittedPacketFlow
}

func (c *packetFlowPacketConn) Upstream() any { return c.PacketConn }

func (c *packetFlowPacketConn) ReadPacket(b *buf.Buffer) (M.Socksaddr, error) {
	source, err := c.PacketConn.ReadPacket(b)
	if err == nil {
		c.flow.touch()
	}
	return source, err
}

func (c *packetFlowPacketConn) WritePacket(b *buf.Buffer, target M.Socksaddr) error {
	err := c.PacketConn.WritePacket(b, target)
	if err == nil {
		c.flow.touch()
	}
	return err
}
