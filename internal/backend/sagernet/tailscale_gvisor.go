//go:build with_gvisor

package sagernet

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"

	"github.com/MimoProxy/reka/internal/api"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/bufio"
	"github.com/sagernet/sing/common/control"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/tailscale/health"
	"github.com/sagernet/tailscale/ipn"
	"github.com/sagernet/tailscale/ipn/ipnlocal"
	"github.com/sagernet/tailscale/ipn/ipnstate"
	"github.com/sagernet/tailscale/ipn/store"
	"github.com/sagernet/tailscale/net/netns"
	"github.com/sagernet/tailscale/net/tsaddr"
	"github.com/sagernet/tailscale/tsconst"
	"github.com/sagernet/tailscale/tsnet"
	"github.com/sagernet/tailscale/types/nettype"
)

// tsnet socket and network monitor hooks are process-wide, including when
// multiple engines live in the same host process.
var tailscaleInProcess atomic.Bool

type tailscaleNode struct {
	scope     *adapter.Scope
	server    *tsnet.Server
	local     *ipnlocal.LocalBackend
	dns       adapter.DNSRouter
	lastError atomic.Pointer[string]
	closed    atomic.Bool
	closeOnce sync.Once
	closeErr  error
	statusMu  sync.RWMutex
}

// NewTailscaleNode starts the userspace server immediately. Control plane
// authentication and synchronization proceed on the server's own workers.
func (b *Backend) NewTailscaleNode(tag string, opts TailscaleOptions) (_ TailscaleNode, err error) {
	if opts.StateDirectory == "" {
		return nil, errors.New("Tailscale requires a state directory")
	}
	if opts.AuthKey == "" {
		// A blank Server.AuthKey inherits credentials from the process
		// environment. Require the link to name the credentials it uses.
		for _, name := range []string{"TS_AUTHKEY", "TS_AUTH_KEY", "TS_CLIENT_SECRET", "TS_CLIENT_ID", "TS_ID_TOKEN", "TS_AUDIENCE"} {
			if os.Getenv(name) != "" {
				return nil, fmt.Errorf("clear %s to use interactive Tailscale login", name)
			}
		}
	}
	if !tailscaleInProcess.CompareAndSwap(false, true) {
		return nil, errors.New("a Tailscale node is already active in this process")
	}
	logger := b.componentLogger("endpoint", tailscaleType, tag)
	scope := adapter.NewScope(b.ctx, logger)
	scope.Add(func() error {
		tailscaleInProcess.Store(false)
		return nil
	})
	defer func() {
		if err != nil {
			_ = scope.Close()
			err = errors.New(redactTailscaleKey(err.Error(), opts.AuthKey))
		}
	}()
	if err = os.MkdirAll(opts.StateDirectory, 0o700); err != nil {
		return nil, fmt.Errorf("create Tailscale state directory: %w", err)
	}
	logf := func(format string, args ...any) {
		logger.Trace(redactTailscaleKey(fmt.Sprintf(format, args...), opts.AuthKey))
	}
	state, err := store.New(logf, filepath.Join(opts.StateDirectory, "tailscaled.state"))
	if err != nil {
		return nil, fmt.Errorf("open Tailscale state: %w", err)
	}
	hostname := opts.Hostname
	if hostname == "" {
		hostname, _ = os.Hostname()
		hostname = strings.TrimSpace(hostname)
		if hostname == "" {
			hostname = "reka"
		}
	}
	underlay := b.tailscaleUnderlay(scope, opts.HostPacketFlow)
	if err = installTailscaleInterfaceGetter(scope); err != nil {
		return nil, err
	}
	httpTransport := &http.Transport{
		ForceAttemptHTTP2: true,
		DialContext:       underlay.dialer.DialContext,
	}
	scope.Add(func() error {
		httpTransport.CloseIdleConnections()
		return nil
	})
	server := &tsnet.Server{
		Dir:                 opts.StateDirectory,
		Store:               state,
		Hostname:            hostname,
		AuthKey:             opts.AuthKey,
		ControlURL:          cmp.Or(opts.ControlURL, ipn.DefaultControlURL),
		Ephemeral:           opts.Ephemeral,
		Dialer:              underlay,
		PeerDNSQueryHandler: rejectTailscalePeerDNS{},
		HTTPClient:          &http.Client{Transport: httpTransport},
		LookupHook: func(ctx context.Context, host string) ([]netip.Addr, error) {
			return underlay.resolver.LookupNetIP(ctx, "ip", host)
		},
		Logf: logf,
		UserLogf: func(format string, args ...any) {
			logger.Debug(redactTailscaleKey(fmt.Sprintf(format, args...), opts.AuthKey))
		},
	}
	// The native userspace UDP fallback drops datagrams without an explicit
	// tsnet listener. TCP uses the same reject router as WireGuard.
	router := endpointRouter{}
	removeFallback := server.RegisterFallbackTCPHandler(func(src, dst netip.AddrPort) (func(net.Conn), bool) {
		return func(conn net.Conn) {
			router.RouteConnectionEx(scope.Context(), conn, adapter.InboundContext{
				Inbound:     tag,
				InboundType: tailscaleType,
				Source:      M.SocksaddrFromNetIP(src),
				Destination: M.SocksaddrFromNetIP(dst),
			}, nil)
		}, true
	})
	scope.Add(func() error {
		removeFallback()
		return nil
	})
	node := &tailscaleNode{
		scope: scope, server: server, dns: service.FromContext[adapter.DNSRouter](b.ctx),
	}
	scope.Add(func() error {
		node.statusMu.Lock()
		defer node.statusMu.Unlock()
		sys := server.Sys()
		if sys == nil {
			return nil
		}
		if node.local == nil {
			// A failed Start can leave an engine without a LocalBackend
			// to shut it down. Close it before the server closes the bus.
			if engine, ok := sys.Engine.GetOK(); ok {
				engine.Close()
			}
		}
		return server.Close()
	})
	err = server.Start()
	node.local = server.ExportLocalBackend()
	if err != nil {
		return nil, fmt.Errorf("start Tailscale: %w", err)
	}
	local := node.local
	// tsnet starts with fresh preferences and keeps the persisted identity.
	// Enable the outbound-only filter and keep OS DNS settings untouched.
	_, err = local.EditPrefs(&ipn.MaskedPrefs{
		Prefs:        ipn.Prefs{RouteAll: opts.AcceptRoutes, ShieldsUp: true},
		RouteAllSet:  true,
		ShieldsUpSet: true,
		CorpDNSSet:   true,
	})
	if err != nil {
		return nil, fmt.Errorf("configure Tailscale: %w", err)
	}
	watchDone := make(chan struct{})
	go func() {
		defer close(watchDone)
		var lastLoginError string
		const watch = ipn.NotifyInitialState | ipn.NotifyInitialHealthState | ipn.NotifyInProcessNoDisconnect
		local.WatchNotifications(scope.Context(), watch, nil, func(n *ipn.Notify) bool {
			var message string
			if n.Health != nil {
				loginError := n.Health.Warnings[tsconst.HealthWarnableLoginState].Args[health.ArgError]
				if loginError != lastLoginError {
					lastLoginError, message = loginError, loginError
				}
			}
			if n.ErrMessage != nil {
				message = *n.ErrMessage
			}
			if message != "" {
				message = redactTailscaleKey(message, opts.AuthKey)
				node.lastError.Store(&message)
			}
			return true
		})
	}()
	scope.Add(func() error {
		<-watchDone
		return nil
	})
	b.endpointListeners.add(scope, node)
	return node, nil
}

type rejectTailscalePeerDNS struct{}

func (rejectTailscalePeerDNS) HandlePeerDNSQuery(context.Context, []byte, netip.AddrPort, func(string) bool) ([]byte, error) {
	return nil, errEndpointInbound
}

func redactTailscaleKey(message, authKey string) string {
	if authKey != "" {
		return strings.ReplaceAll(message, authKey, "[redacted]")
	}
	return message
}

type tailscaleUnderlay struct {
	dialer   net.Dialer
	listener net.ListenConfig
	resolver *net.Resolver
}

func (b *Backend) tailscaleUnderlay(scope *adapter.Scope, hostPacketFlow bool) *tailscaleUnderlay {
	var protect control.Func
	packetTunnel := runtime.GOOS == "ios" && hostPacketFlow
	if packetTunnel {
		// NECP excludes Provider sockets from the tunnel. Suppress
		// Tailscale's default interface bind, which would choose utun.
		protect = func(string, string, syscall.RawConn) error { return nil }
	} else {
		protect = b.registerEndpointControl(scope, true)
	}
	underlay := &tailscaleUnderlay{
		dialer:   net.Dialer{Control: protect},
		listener: net.ListenConfig{Control: control.Append(protect, control.DisableUDPNetReset())},
	}
	if packetTunnel || runtime.GOOS == "android" {
		// Android has no resolv.conf; the Go resolver would query loopback.
		// Match tsnet's native hostname lookup on mobile. The resulting
		// control, relay, and peer sockets still use the guard on Android.
		underlay.resolver = net.DefaultResolver
	} else {
		dnsDialer := &net.Dialer{Control: protect}
		underlay.resolver = &net.Resolver{PreferGo: true, Dial: dnsDialer.DialContext}
	}
	underlay.dialer.Resolver = underlay.resolver
	if protect != nil {
		netns.SetControlFunc(protect)
		if !packetTunnel {
			listener := nettype.MakePacketListenerWithNetIP(&underlay.listener)
			netns.SetListenPacketFunc(listener.ListenPacket)
		}
		scope.Add(func() error {
			netns.SetListenPacketFunc(nil)
			netns.SetControlFunc(nil)
			return nil
		})
	}
	return underlay
}

func (d *tailscaleUnderlay) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return d.dialer.DialContext(ctx, network, destination.String())
}

func (d *tailscaleUnderlay) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	network := "udp4"
	if destination.IsIPv6() {
		network = "udp6"
	}
	return d.listener.ListenPacket(ctx, network, "")
}

func (n *tailscaleNode) InterfaceUpdated(context.Context) {
	if monitor, ok := n.server.Sys().NetMon.GetOK(); ok && monitor != nil {
		monitor.InjectEvent()
	}
}

func (n *tailscaleNode) Close() error {
	n.closeOnce.Do(func() {
		n.closed.Store(true)
		n.closeErr = n.scope.Close()
	})
	return n.closeErr
}

func (n *tailscaleNode) Status() api.TailscaleStatus {
	n.statusMu.RLock()
	defer n.statusMu.RUnlock()
	state := &ipnstate.Status{BackendState: ipn.Stopped.String()}
	if !n.closed.Load() {
		state = n.local.Status()
	}
	var lastError string
	if last := n.lastError.Load(); last != nil {
		lastError = *last
	}
	return tailscaleStatus(state, lastError)
}

func tailscaleStatus(status *ipnstate.Status, lastError string) api.TailscaleStatus {
	result := api.TailscaleStatus{
		State:        tailscaleState(status.BackendState),
		TailscaleIPs: append([]netip.Addr{}, status.TailscaleIPs...),
		Peers:        make([]api.TailscalePeer, 0, len(status.Peer)),
		LastError:    lastError,
	}
	if result.State == api.TailscaleNeedsLogin {
		result.AuthURL = status.AuthURL
	} else if result.State == api.TailscaleStarting && lastError != "" {
		result.State = api.TailscaleError
	}
	peers := make([]*ipnstate.PeerStatus, 0, len(status.Peer))
	for _, peer := range status.Peer {
		peers = append(peers, peer)
	}
	ipnstate.SortPeers(peers)
	for _, peer := range peers {
		details := api.TailscalePeer{
			Hostname:      peer.HostName,
			TailscaleIPs:  append([]netip.Addr{}, peer.TailscaleIPs...),
			Online:        peer.Online,
			DirectAddress: peer.CurAddr,
		}
		if details.DirectAddress == "" {
			details.DERPRegion = peer.Relay
		}
		result.Peers = append(result.Peers, details)
	}
	return result
}

func tailscaleState(state string) string {
	switch state {
	case ipn.NoState.String(), ipn.Starting.String():
		return api.TailscaleStarting
	case ipn.NeedsLogin.String(), ipn.NeedsMachineAuth.String():
		return api.TailscaleNeedsLogin
	case ipn.Running.String():
		return api.TailscaleRunning
	case ipn.Stopped.String(), ipn.InUseOtherUser.String():
		return api.TailscaleStopped
	default:
		return api.TailscaleError
	}
}

func (n *tailscaleNode) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if n.closed.Load() {
		return nil, fmt.Errorf("Tailscale node is stopped: %w", net.ErrClosed)
	}
	if state := tailscaleState(n.local.State().String()); state != api.TailscaleRunning {
		return nil, fmt.Errorf("Tailscale node is not running (%s)", state)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if destination.IsDomain() {
		addrs, err := n.dns.Lookup(ctx, destination.Fqdn, adapter.DNSQueryOptions{})
		if err != nil {
			return nil, err
		}
		return N.DialSerial(ctx, n, network, destination, addrs)
	}
	addr := destination.Addr.Unmap()
	if !addr.IsValid() || addr == tsaddr.TailscaleServiceIP() || addr == tsaddr.TailscaleServiceIPv6() {
		return nil, errors.New("invalid Tailscale destination or disabled Tailscale service address")
	}
	ip4, ip6 := n.server.TailscaleIPs()
	source := ip4
	if addr.Is6() {
		source = ip6
	}
	if !source.IsValid() {
		return nil, errors.New("Tailscale node has no address for the destination family")
	}
	dest := netip.AddrPortFrom(addr, destination.Port)
	stack := n.server.ExportNetstack()
	// The public tsnet dial waits during login and can fall back to the
	// host network. Dial the userspace stack directly for this outbound.
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		ctx, cancel := context.WithCancel(ctx)
		defer cancel()
		stop := context.AfterFunc(n.scope.Context(), cancel)
		defer stop()
		conn, err := stack.DialContextTCPWithBind(ctx, source, dest)
		if err != nil {
			return nil, err
		}
		return conn, nil
	case N.NetworkUDP:
		conn, err := stack.DialContextUDPWithBind(ctx, source, dest)
		if err != nil {
			return nil, err
		}
		return conn, nil
	default:
		return nil, fmt.Errorf("%w: %s", N.ErrUnknownNetwork, network)
	}
}

// ListenPacket returns an unconnected socket, as the sing-box endpoint does,
// so one flow can send to several destinations inside the tailnet.
func (n *tailscaleNode) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if n.closed.Load() {
		return nil, fmt.Errorf("Tailscale node is stopped: %w", net.ErrClosed)
	}
	if state := tailscaleState(n.local.State().String()); state != api.TailscaleRunning {
		return nil, fmt.Errorf("Tailscale node is not running (%s)", state)
	}
	target := destination
	if destination.IsDomain() {
		addrs, err := n.dns.Lookup(ctx, destination.Fqdn, adapter.DNSQueryOptions{})
		if err != nil {
			return nil, err
		}
		if len(addrs) == 0 {
			return nil, fmt.Errorf("no addresses for %s", destination.Fqdn)
		}
		target = M.SocksaddrFrom(addrs[0], destination.Port)
	}
	addr := target.Addr.Unmap()
	if !addr.IsValid() {
		return nil, errors.New("invalid Tailscale destination")
	}
	ip4, ip6 := n.server.TailscaleIPs()
	network, source := "udp4", ip4
	if addr.Is6() {
		network, source = "udp6", ip6
	}
	if !source.IsValid() {
		return nil, errors.New("Tailscale node has no address for the destination family")
	}
	conn, err := n.server.ExportNetstack().ListenPacket(network, netip.AddrPortFrom(source, 0).String())
	if err != nil {
		return nil, err
	}
	if target != destination {
		return bufio.NewNATPacketConn(bufio.NewPacketConn(conn), target, destination), nil
	}
	return conn, nil
}
