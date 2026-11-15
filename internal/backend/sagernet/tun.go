package sagernet

import (
	"context"
	"errors"
	"fmt"
	"github.com/MimoProxy/reka/internal/platform"
	D "github.com/miekg/dns"
	"github.com/sagernet/sing-box/adapter"
	tun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"io"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"time"
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
}

// NewTUN routes packets through the same backend, connection table and leases
// as loopback listeners. sing-tun is the only route owner.
func (b *Backend) NewTUN(c platform.TUNConfig, fd int, g *SocketGuard, dns func(context.Context, *D.Msg) (*D.Msg, error)) (io.Closer, string, error) {
	ctx, cancel := context.WithCancel(b.ctx)
	t := &TUNInbound{b: b, cfg: c, ctx: ctx, cancel: cancel, dns: dns, slots: make(chan struct{}, 64)}
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
func (t *TUNInbound) JudgeFlow(_ uint8, _ netip.AddrPort, d netip.AddrPort, _ []byte) tun.FlowVerdict {
	// DNS can target the gateway; DNS is consumed locally, never relayed.
	if d.Port() == 53 && t.cfg.DNSHijack {
		return tun.FlowVerdict{Action: tun.ActionAccept}
	}
	if t.self(d.Addr()) {
		return tun.FlowVerdict{Action: tun.ActionDrop}
	}
	return tun.FlowVerdict{Action: tun.ActionAccept}
}
func (t *TUNInbound) NewDNSPacket(payload []byte, source, dest M.Socksaddr, writer N.PacketWriter) {
	// Called by stacks with a DNS fast path. Bound work before spawning.
	select {
	case t.slots <- struct{}{}:
	default:
		return
	}
	p := append([]byte{}, payload...)
	t.wg.Add(1)
	go func() {
		defer t.wg.Done()
		defer func() { <-t.slots }()
		if b, err := t.answer(p); err == nil {
			_ = writer.WritePacket(buf.As(b), dest)
		}
	}()
}
func (t *TUNInbound) answer(p []byte) ([]byte, error) {
	q := new(D.Msg)
	if err := q.Unpack(p); err != nil {
		return nil, err
	}
	if q.Response || len(q.Question) != 1 {
		return nil, errors.New("invalid DNS question")
	}
	ctx, cancel := context.WithTimeout(t.ctx, 6*time.Second)
	defer cancel()
	m, err := t.dns(ctx, q)
	if err != nil {
		m = new(D.Msg)
		m.SetRcode(q, D.RcodeServerFailure)
	}
	return m.Pack()
}
func (t *TUNInbound) metadata(src, dst M.Socksaddr) adapter.InboundContext {
	return adapter.InboundContext{Inbound: "tun", InboundType: "tun", Source: src, Destination: dst, OriginDestination: dst}
}
func (t *TUNInbound) NewConnectionEx(ctx context.Context, c net.Conn, src, dst M.Socksaddr, onClose N.CloseHandlerFunc) {
	if dst.Port == 53 && t.cfg.DNSHijack {
		select {
		case t.slots <- struct{}{}:
		default:
			N.CloseOnHandshakeFailure(c, onClose, errors.New("DNS busy"))
			return
		}
		t.wg.Add(1)
		go func() {
			defer t.wg.Done()
			defer func() {
				<-t.slots
				c.Close()
				if onClose != nil {
					onClose(nil)
				}
			}()
			_ = c.SetDeadline(time.Now().Add(6 * time.Second))
			dc := &D.Conn{Conn: c}
			for {
				q, err := dc.ReadMsg()
				if err != nil {
					return
				}
				p, err := q.Pack()
				if err != nil {
					return
				}
				p, err = t.answer(p)
				if err != nil {
					return
				}
				m := new(D.Msg)
				if m.Unpack(p) != nil || dc.WriteMsg(m) != nil {
					return
				}
			}
		}()
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
		select {
		case t.slots <- struct{}{}:
		default:
			N.CloseOnHandshakeFailure(c, onClose, errors.New("DNS busy"))
			return
		}
		t.wg.Add(1)
		go func() {
			defer t.wg.Done()
			defer func() {
				<-t.slots
				c.Close()
				if onClose != nil {
					onClose(nil)
				}
			}()
			for {
				_ = c.SetReadDeadline(time.Now().Add(6 * time.Second))
				b := buf.NewPacket()
				to, err := c.ReadPacket(b)
				if err != nil {
					b.Release()
					return
				}
				p, err := t.answer(b.Bytes())
				b.Release()
				if err == nil {
					if err = c.WritePacket(buf.As(p), to); err != nil {
						return
					}
				}
			}
		}()
		return
	}
	if t.self(dst.Addr) {
		N.CloseOnHandshakeFailure(c, onClose, fmt.Errorf("self-destined TUN flow"))
		return
	}
	t.b.router.RoutePacketConnectionEx(ctx, c, t.metadata(src, dst), onClose)
}
