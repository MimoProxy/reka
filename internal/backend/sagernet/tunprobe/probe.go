// Package tunprobe is a minimal sing-tun harness used to check TUN support
// on each platform: create the device, route a few test prefixes into it,
// accept TCP and UDP on both address families, and relay them out through a
// socket that bypasses the TUN (bound to the physical interface on desktop,
// protect()ed on Android). If the bypass fails, the relay's own connection
// re-enters the TUN; the probe counts that as a loop.
//
// It lives under backend/sagernet because it imports sing-tun directly.
package tunprobe

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"runtime"
	"sync/atomic"
	"syscall"
	"time"

	tun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/bufio"
	"github.com/sagernet/sing/common/control"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// Options configures a probe.
type Options struct {
	// Stack is "gvisor", "system" or "mixed" (default).
	Stack        string
	Inet4Address netip.Prefix
	Inet6Address netip.Prefix
	MTU          uint32
	// Routes are the prefixes sent into the TUN. Keep them narrow (single
	// test hosts) so the rest of the machine is unaffected. Ignored on
	// Android, where the VpnService builder sets routes.
	Routes []netip.Prefix
	// FileDescriptor is the TUN fd from Android's VpnService; zero on
	// desktop, where the probe creates the device itself.
	FileDescriptor int
	// Protect is called for every relay socket on Android
	// (VpnService.protect). Desktop binds to the default interface instead.
	Protect func(fd int) bool
	// BindInterface overrides the interface relay sockets bind to.
	BindInterface string
	Logger        *slog.Logger
}

// Stats counts what the probe saw.
type Stats struct {
	TCP4, TCP6, UDP4, UDP6 int64 // connections accepted from the TUN
	// SelfDestined counts flows addressed to the TUN's own addresses. They
	// mean the OS reflected packets meant for local delivery back into the
	// TUN; they are dropped instead of relayed.
	SelfDestined       int64
	RelayFailures      int64
	ProtectCalls       int64
	ProtectFailures    int64
	BytesUp, BytesDown int64
}

type Probe struct {
	opts     Options
	logger   *slog.Logger
	tunIf    tun.Tun
	stack    tun.Stack
	netMon   tun.NetworkUpdateMonitor
	ifMon    tun.DefaultInterfaceMonitor
	finder   *control.DefaultInterfaceFinder
	name     string
	bindName string

	tcp4, tcp6, udp4, udp6 atomic.Int64
	selfDestined           atomic.Int64
	relayFailures          atomic.Int64
	protectCalls           atomic.Int64
	protectFailures        atomic.Int64
	up, down               atomic.Int64
}

func (p *Probe) Name() string          { return p.name }
func (p *Probe) BindInterface() string { return p.bindName }

func (p *Probe) Stats() Stats {
	return Stats{
		TCP4: p.tcp4.Load(), TCP6: p.tcp6.Load(), UDP4: p.udp4.Load(), UDP6: p.udp6.Load(),
		SelfDestined: p.selfDestined.Load(), RelayFailures: p.relayFailures.Load(), ProtectCalls: p.protectCalls.Load(),
		ProtectFailures: p.protectFailures.Load(), BytesUp: p.up.Load(), BytesDown: p.down.Load(),
	}
}

// Start creates the TUN, the stack and the monitors.
func Start(opts Options) (*Probe, error) {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.MTU == 0 {
		opts.MTU = 9000
	}
	if opts.Stack == "" {
		opts.Stack = "mixed"
	}
	p := &Probe{opts: opts, logger: opts.Logger, finder: control.NewDefaultInterfaceFinder()}
	log := slogAdapter{opts.Logger}
	ok := false
	defer func() {
		if !ok {
			p.Close()
		}
	}()

	android := runtime.GOOS == "android"
	if !android {
		var err error
		p.netMon, err = tun.NewNetworkUpdateMonitor(log)
		if err != nil {
			return nil, fmt.Errorf("network monitor: %w", err)
		}
		p.ifMon, err = tun.NewDefaultInterfaceMonitor(p.netMon, log, tun.DefaultInterfaceMonitorOptions{InterfaceFinder: p.finder})
		if err != nil {
			return nil, fmt.Errorf("interface monitor: %w", err)
		}
		if err := p.netMon.Start(); err != nil {
			return nil, fmt.Errorf("start network monitor: %w", err)
		}
		if err := p.ifMon.Start(); err != nil {
			return nil, fmt.Errorf("start interface monitor: %w", err)
		}
		if err := p.finder.Update(); err != nil {
			return nil, err
		}
		p.bindName = opts.BindInterface
		if p.bindName == "" {
			if def := p.ifMon.DefaultInterface(); def != nil {
				p.bindName = def.Name
			}
		}
		if p.bindName == "" {
			return nil, errors.New("no default interface to bind relay sockets to")
		}
	}

	tunOpts := tun.Options{
		MTU:                  opts.MTU,
		InterfaceFinder:      p.finder,
		InterfaceMonitor:     p.ifMon,
		FileDescriptor:       opts.FileDescriptor,
		Logger:               log,
		EXP_DisableDNSHijack: true,
	}
	if opts.Inet4Address.IsValid() {
		tunOpts.Inet4Address = []netip.Prefix{opts.Inet4Address}
	}
	if opts.Inet6Address.IsValid() {
		tunOpts.Inet6Address = []netip.Prefix{opts.Inet6Address}
	}
	if !android {
		tunOpts.Name = tun.CalculateInterfaceName("")
		tunOpts.AutoRoute = true
		for _, r := range opts.Routes {
			if r.Addr().Is4() {
				tunOpts.Inet4RouteAddress = append(tunOpts.Inet4RouteAddress, r)
			} else {
				tunOpts.Inet6RouteAddress = append(tunOpts.Inet6RouteAddress, r)
			}
		}
	}
	var err error
	p.tunIf, err = tun.New(tunOpts)
	if err != nil {
		return nil, fmt.Errorf("create tun: %w", err)
	}
	if p.name, err = p.tunIf.Name(); err != nil {
		p.name = tunOpts.Name
	}
	p.stack, err = tun.NewStack(opts.Stack, tun.StackOptions{
		Context:                context.Background(),
		Tun:                    p.tunIf,
		TunOptions:             tunOpts,
		UDPTimeout:             30 * time.Second,
		Handler:                p,
		Logger:                 log,
		ForwarderBindInterface: runtime.GOOS == "darwin",
		InterfaceFinder:        p.finder,
	})
	if err != nil {
		return nil, fmt.Errorf("create %s stack: %w", opts.Stack, err)
	}
	if err := p.stack.Start(); err != nil {
		return nil, fmt.Errorf("start stack: %w", err)
	}
	if err := p.tunIf.Start(); err != nil {
		return nil, fmt.Errorf("start tun: %w", err)
	}
	ok = true
	return p, nil
}

func (p *Probe) Close() error {
	var errs []error
	if p.stack != nil {
		errs = append(errs, p.stack.Close())
	}
	if p.tunIf != nil {
		errs = append(errs, p.tunIf.Close())
	}
	if p.ifMon != nil {
		errs = append(errs, p.ifMon.Close())
	}
	if p.netMon != nil {
		errs = append(errs, p.netMon.Close())
	}
	return errors.Join(errs...)
}

// control makes relay sockets skip the TUN.
func (p *Probe) control(network, address string, c syscall.RawConn) error {
	if p.opts.Protect != nil {
		var protected bool
		err := c.Control(func(fd uintptr) {
			p.protectCalls.Add(1)
			protected = p.opts.Protect(int(fd))
		})
		if err != nil {
			return err
		}
		if !protected {
			p.protectFailures.Add(1)
			return errors.New("protect failed")
		}
		return nil
	}
	return control.BindToInterface(p.finder, p.bindName, -1)(network, address, c)
}

// JudgeFlow accepts every flow into the stack.
func (p *Probe) JudgeFlow(uint8, netip.AddrPort, netip.AddrPort, []byte) tun.FlowVerdict {
	return tun.FlowVerdict{Action: tun.ActionAccept}
}

func (p *Probe) NewDNSPacket([]byte, M.Socksaddr, M.Socksaddr, N.PacketWriter) {}

// isSelfDestined reports (and counts) a flow addressed to the TUN itself.
func (p *Probe) isSelfDestined(network string, source, destination M.Socksaddr) bool {
	a := destination.Addr.Unmap()
	if a == p.opts.Inet4Address.Addr() || a == p.opts.Inet6Address.Addr() {
		p.selfDestined.Add(1)
		p.logger.Debug("self-destined flow", "network", network, "source", source.String(), "destination", destination.String())
		return true
	}
	return false
}

func (p *Probe) NewConnectionEx(ctx context.Context, conn net.Conn, source, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	if p.isSelfDestined("tcp", source, destination) {
		N.CloseOnHandshakeFailure(conn, onClose, errors.New("self-destined flow"))
		return
	}
	if destination.Addr.Unmap().Is4() {
		p.tcp4.Add(1)
	} else {
		p.tcp6.Add(1)
	}
	p.logger.Debug("tcp flow", "source", source.String(), "destination", destination.String())
	d := net.Dialer{Timeout: 10 * time.Second, Control: p.control}
	remote, err := d.DialContext(ctx, "tcp", destination.String())
	if err != nil {
		p.relayFailures.Add(1)
		p.logger.Warn("relay dial failed", "destination", destination.String(), "error", err)
		N.CloseOnHandshakeFailure(conn, onClose, err)
		return
	}
	go func() {
		err := bufio.CopyConn(ctx, countConn{conn, &p.up, &p.down}, remote)
		if onClose != nil {
			onClose(err)
		}
	}()
}

func (p *Probe) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	if p.isSelfDestined("udp", source, destination) {
		N.CloseOnHandshakeFailure(conn, onClose, errors.New("self-destined flow"))
		return
	}
	if destination.Addr.Unmap().Is4() {
		p.udp4.Add(1)
	} else {
		p.udp6.Add(1)
	}
	p.logger.Debug("udp flow", "source", source.String(), "destination", destination.String())
	lc := net.ListenConfig{Control: p.control}
	network := "udp4"
	if !destination.Addr.Unmap().Is4() {
		network = "udp6"
	}
	pc, err := lc.ListenPacket(ctx, network, "")
	if err != nil {
		p.relayFailures.Add(1)
		p.logger.Warn("relay listen failed", "destination", destination.String(), "error", err)
		N.CloseOnHandshakeFailure(conn, onClose, err)
		return
	}
	go func() {
		err := bufio.CopyPacketConn(ctx, conn, bufio.NewPacketConn(pc))
		if onClose != nil {
			onClose(err)
		}
	}()
}

// countConn counts bytes read from (up) and written to (down) the TUN side.
type countConn struct {
	net.Conn
	up, down *atomic.Int64
}

func (c countConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.up.Add(int64(n))
	return n, err
}

func (c countConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	c.down.Add(int64(n))
	return n, err
}

// slogAdapter feeds sing-tun's logger into slog.
type slogAdapter struct{ l *slog.Logger }

var _ logger.ContextLogger = slogAdapter{}

func (s slogAdapter) out(level slog.Level, args []any) {
	if s.l.Enabled(context.Background(), level) {
		s.l.Log(context.Background(), level, fmt.Sprint(args...), "component", "sing-tun")
	}
}
func (s slogAdapter) Trace(a ...any) { s.out(slog.LevelDebug-4, a) }
func (s slogAdapter) Debug(a ...any) { s.out(slog.LevelDebug, a) }
func (s slogAdapter) Info(a ...any)  { s.out(slog.LevelInfo, a) }
func (s slogAdapter) Warn(a ...any)  { s.out(slog.LevelWarn, a) }
func (s slogAdapter) Error(a ...any) { s.out(slog.LevelError, a) }
func (s slogAdapter) Fatal(a ...any) { s.out(slog.LevelError, a) }
func (s slogAdapter) Panic(a ...any) { s.out(slog.LevelError, a) }
func (s slogAdapter) TraceContext(_ context.Context, a ...any) {
	s.Trace(a...)
}
func (s slogAdapter) DebugContext(_ context.Context, a ...any) { s.Debug(a...) }
func (s slogAdapter) InfoContext(_ context.Context, a ...any)  { s.Info(a...) }
func (s slogAdapter) WarnContext(_ context.Context, a ...any)  { s.Warn(a...) }
func (s slogAdapter) ErrorContext(_ context.Context, a ...any) { s.Error(a...) }
func (s slogAdapter) FatalContext(_ context.Context, a ...any) { s.Fatal(a...) }
func (s slogAdapter) PanicContext(_ context.Context, a ...any) { s.Panic(a...) }
