package sagernet

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/MimoProxy/reka/internal/history"
	"github.com/MimoProxy/reka/internal/platform"
	D "github.com/miekg/dns"
	"github.com/sagernet/sing-box/adapter"
	tun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing-tun/gtcpip/header"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const (
	tunDNSConcurrency     = 64
	tunDNSTimeout         = 6 * time.Second
	tunDNSOverflowTimeout = 500 * time.Millisecond
)

type TUNInbound struct {
	b      *Backend
	cfg    platform.TUNConfig
	dev    tun.Tun
	stack  tun.Stack
	name   string
	cancel context.CancelFunc
	ctx    context.Context
	dns    func(context.Context, *D.Msg) (*D.Msg, error)
	slots  chan struct{}
	wg     sync.WaitGroup

	dnsOverflow    atomic.Uint64
	dnsLastWarning atomic.Pointer[time.Time]
}

// NewTUN routes packets through the same backend, connection table and leases
// as loopback listeners. sing-tun is the only route owner.
func (b *Backend) NewTUN(c platform.TUNConfig, fd int, g *SocketGuard, dns func(context.Context, *D.Msg) (*D.Msg, error)) (io.Closer, string, error) {
	ctx, cancel := context.WithCancel(b.ctx)
	t := &TUNInbound{b: b, cfg: c, ctx: ctx, cancel: cancel, dns: dns, slots: make(chan struct{}, tunDNSConcurrency)}
	opts := tun.Options{MTU: uint32(c.MTU), Logger: newLogger(b.slog, "tun"), FileDescriptor: fd, InterfaceFinder: g.finder, InterfaceMonitor: g.ifMon, EXP_DisableDNSHijack: true}
	p4, _ := netip.ParsePrefix(c.Address4)
	opts.Inet4Address = []netip.Prefix{p4}
	if c.Address6 != "" {
		p6, _ := netip.ParsePrefix(c.Address6)
		opts.Inet6Address = []netip.Prefix{p6}
	}
	if runtime.GOOS == "android" {
		if fd <= 0 {
			cancel()
			return nil, "", errors.New("TUN fd must be supplied by VpnService")
		}
	} else {
		opts.Name = tun.CalculateInterfaceName("")
		opts.AutoRoute = true
		for _, v := range c.Routes {
			p, _ := netip.ParsePrefix(v)
			if p.Addr().Is4() {
				opts.Inet4RouteAddress = append(opts.Inet4RouteAddress, p)
			} else {
				opts.Inet6RouteAddress = append(opts.Inet6RouteAddress, p)
			}
		}
		for _, v := range c.ExcludeRoutes {
			p, _ := netip.ParsePrefix(v)
			if p.Addr().Is4() {
				opts.Inet4RouteExcludeAddress = append(opts.Inet4RouteExcludeAddress, p)
			} else {
				opts.Inet6RouteExcludeAddress = append(opts.Inet6RouteExcludeAddress, p)
			}
		}
		// Windows uses the TUN gateway as interface DNS in hijack mode. Partial
		// routes without DNS hijack must not change the interface DNS.
		if c.DNSHijack {
			opts.EXP_DisableDNSHijack = false
			opts.DNSMode = tun.DNSModeHijack
		}
	}
	var err error
	if runtime.GOOS == "android" {
		opts.FileDescriptor, err = duplicateTUNFD(fd)
		if err != nil {
			cancel()
			return nil, "", err
		}
	}
	t.dev, err = tun.New(opts)
	if err != nil {
		if runtime.GOOS == "android" {
			closeTUNFD(opts.FileDescriptor)
		}
		cancel()
		return nil, "", err
	}
	t.name, _ = t.dev.Name()
	if g.ifMon != nil {
		g.ifMon.RegisterMyInterface(t.name)
	}
	t.stack, err = tun.NewStack(c.Stack, tun.StackOptions{Context: ctx, Tun: t.dev, TunOptions: opts, Handler: t, Logger: opts.Logger, UDPTimeout: 60 * time.Second, ForwarderBindInterface: runtime.GOOS == "darwin", InterfaceFinder: g.finder})
	if err == nil {
		err = t.stack.Start()
	}
	if err == nil {
		err = t.dev.Start()
	}
	if err != nil {
		t.Close()
		return nil, "", err
	}
	return t, t.name, nil
}
func (t *TUNInbound) Close() error {
	t.cancel()
	var errs []error
	if t.stack != nil {
		errs = append(errs, t.stack.Close())
	}
	if t.dev != nil {
		errs = append(errs, t.dev.Close())
	}
	t.wg.Wait()
	return errors.Join(errs...)
}
func (t *TUNInbound) self(a netip.Addr) bool {
	for _, s := range []string{t.cfg.Address4, t.cfg.Address6} {
		if p, err := netip.ParsePrefix(s); err == nil && p.Addr() == a.Unmap() {
			return true
		}
	}
	return false
}
func (t *TUNInbound) JudgeFlow(protocol uint8, source, target netip.AddrPort, _ []byte) tun.FlowVerdict {
	// DNS can target the gateway; DNS is consumed locally, never relayed.
	if target.Port() == 53 && t.cfg.DNSHijack {
		return tun.FlowVerdict{Action: tun.ActionAccept}
	}
	if t.self(target.Addr()) {
		return tun.FlowVerdict{Action: tun.ActionDrop}
	}
	var network string
	switch protocol {
	case uint8(header.TCPProtocolNumber):
		network = N.NetworkTCP
	case uint8(header.UDPProtocolNumber):
		network = N.NetworkUDP
	default:
		return tun.FlowVerdict{Action: tun.ActionAccept}
	}
	// TUN connections have no parser-supplied protocol in their context.
	metadata := t.metadata(M.SocksaddrFromNetIP(source), M.SocksaddrFromNetIP(target))
	metadata.Network = network
	md := toFlowMetadata(context.Background(), metadata)
	// Let cached verdicts expire on idle timeout; resetting the stack on generation changes would disrupt live flows.
	v := t.b.router.preMatch(md)
	var action tun.FlowAction
	switch v.Action {
	case PreMatchReject:
		action = tun.ActionReject
	case PreMatchDrop:
		action = tun.ActionDrop
	default:
		return tun.FlowVerdict{Action: tun.ActionAccept}
	}
	t.b.reportPreMatched(md, v)
	return tun.FlowVerdict{Action: action}
}
func (t *TUNInbound) tryDNSSlot() bool {
	select {
	case t.slots <- struct{}{}:
		return true
	default:
		return false
	}
}

func (t *TUNInbound) NewDNSPacket(payload []byte, source, dest M.Socksaddr, writer N.PacketWriter) {
	if !t.tryDNSSlot() {
		// Packet tunnel writes enqueue to a bounded, nonblocking link endpoint.
		if b, err := t.answerDNSPacket(payload, source, dest, true); err == nil {
			_ = writer.WritePacket(buf.As(b), dest)
		}
		return
	}
	// The stack can reuse the input buffer as soon as this callback returns.
	p := append([]byte(nil), payload...)
	t.wg.Go(func() {
		defer func() { <-t.slots }()
		if b, err := t.answerDNSPacket(p, source, dest, false); err == nil {
			_ = writer.WritePacket(buf.As(b), dest)
		}
	})
}

func (t *TUNInbound) answerDNSPacket(p []byte, source, destination M.Socksaddr, overloaded bool) ([]byte, error) {
	q := new(D.Msg)
	if err := q.Unpack(p); err != nil {
		return nil, err
	}
	m, err := t.answerDNS(q, N.NetworkUDP, source, destination, overloaded)
	if err != nil {
		return nil, err
	}
	return m.Pack()
}

func (t *TUNInbound) answerDNS(q *D.Msg, network string, source, destination M.Socksaddr, overloaded bool) (*D.Msg, error) {
	if q.Response || len(q.Question) != 1 {
		return nil, errors.New("invalid DNS question")
	}
	if overloaded {
		t.recordDNSOverflow()
	} else {
		ctx, cancel := context.WithTimeout(t.ctx, tunDNSTimeout)
		defer cancel()
		origin := history.DNSOrigin{Kind: "tun", Network: network, Client: source.String(), Requested: destination.String()}
		if m, err := t.dns(history.WithDNSOrigin(ctx, origin), q); err == nil {
			return m, nil
		}
	}
	return new(D.Msg).SetRcode(q, D.RcodeServerFailure), nil
}

func (t *TUNInbound) recordDNSOverflow() {
	t.dnsOverflow.Add(1)
	last := t.dnsLastWarning.Load()
	now := time.Now()
	if (last == nil || now.Sub(*last) >= time.Second) && t.dnsLastWarning.CompareAndSwap(last, &now) {
		t.b.logger.Warn("TUN DNS concurrency limit reached (limit ", cap(t.slots), ")")
	}
}

func (t *TUNInbound) serveDNSConnection(c io.Closer, onClose N.CloseHandlerFunc, serve func(overloaded bool)) {
	admitted := t.tryDNSSlot()
	run := func() {
		defer func() {
			if admitted {
				<-t.slots
			}
			_ = c.Close()
			if onClose != nil {
				onClose(nil)
			}
		}()
		serve(!admitted)
	}
	if admitted {
		t.wg.Go(run)
	} else {
		// sing-tun already runs these callbacks in per-connection goroutines.
		run()
	}
}

func (t *TUNInbound) metadata(src, dst M.Socksaddr) adapter.InboundContext {
	return adapter.InboundContext{Inbound: "tun", InboundType: "tun", Source: src, Destination: dst, OriginDestination: dst}
}
func (t *TUNInbound) NewConnectionEx(ctx context.Context, c net.Conn, src, dst M.Socksaddr, onClose N.CloseHandlerFunc) {
	if dst.Port == 53 && t.cfg.DNSHijack {
		t.serveDNSConnection(c, onClose, func(overloaded bool) {
			timeout := tunDNSTimeout
			if overloaded {
				timeout = tunDNSOverflowTimeout
			}
			if err := c.SetDeadline(time.Now().Add(timeout)); err != nil {
				return
			}
			dc := &D.Conn{Conn: c}
			for {
				q, err := dc.ReadMsg()
				if err != nil {
					return
				}
				reply, err := t.answerDNS(q, N.NetworkTCP, src, dst, overloaded)
				if err != nil || dc.WriteMsg(reply) != nil || overloaded {
					return
				}
			}
		})
		return
	}
	if t.self(dst.Addr) {
		N.CloseOnHandshakeFailure(c, onClose, fmt.Errorf("self-destined TUN flow"))
		return
	}
	t.b.router.RouteConnectionEx(ctx, c, t.metadata(src, dst), onClose)
}
func (t *TUNInbound) NewPacketConnectionEx(ctx context.Context, c N.PacketConn, src, dst M.Socksaddr, onClose N.CloseHandlerFunc) {
	if dst.Port == 53 && t.cfg.DNSHijack {
		t.serveDNSConnection(c, onClose, func(overloaded bool) {
			timeout := tunDNSTimeout
			if overloaded {
				timeout = tunDNSOverflowTimeout
			}
			for {
				deadline := time.Now().Add(timeout)
				if err := c.SetReadDeadline(deadline); err != nil {
					return
				}
				b := buf.NewPacket()
				to, err := c.ReadPacket(b)
				if err != nil {
					b.Release()
					return
				}
				p, err := t.answerDNSPacket(b.Bytes(), src, dst, overloaded)
				b.Release()
				if err == nil {
					if overloaded {
						// NAT writers without deadlines still run off the packet dispatch path.
						_ = c.SetWriteDeadline(deadline)
					}
					if err = c.WritePacket(buf.As(p), to); err != nil {
						return
					}
				}
				if overloaded {
					return
				}
			}
		})
		return
	}
	if t.self(dst.Addr) {
		N.CloseOnHandshakeFailure(c, onClose, fmt.Errorf("self-destined TUN flow"))
		return
	}
	t.b.router.RoutePacketConnectionEx(ctx, c, t.metadata(src, dst), onClose)
}
