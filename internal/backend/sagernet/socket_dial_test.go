package sagernet

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/MimoProxy/reka/internal/api"
	"github.com/MimoProxy/reka/internal/history"
	"github.com/MimoProxy/reka/internal/testnet"
	"github.com/sagernet/sing-box/adapter"
	MX "github.com/sagernet/sing-box/common/mux"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/shadowsocks"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
)

func TestSocketDialTimingLifecycle(t *testing.T) {
	t.Run("success and failure", func(t *testing.T) {
		ctx, observation := withSocketDial(t.Context())
		trace := httptrace.ContextClientTrace(ctx)
		peer := "192.0.2.1:443"
		for range 10 * maxSocketTimings {
			trace.ConnectStart("tcp4", peer)
			trace.ConnectDone("tcp4", peer, errors.New("dial refused"))
		}
		if len(observation.connects) != 0 {
			t.Fatalf("failed dials left %d entries", len(observation.connects))
		}
		trace.ConnectStart("tcp4", peer)
		trace.ConnectDone("tcp4", peer, nil)
		if len(observation.connects) != 1 {
			t.Fatalf("successful dial recorded %d entries", len(observation.connects))
		}
		timing := observation.connects[0]
		if timing.network != "tcp" || timing.address.String() != peer ||
			timing.started.IsZero() || timing.finished.Before(timing.started) {
			t.Fatalf("unexpected connect timing: %+v", timing)
		}
		observation.finish(nil, errors.New("proxy handshake failed"))
		trace.ConnectStart("tcp", peer)
		trace.ConnectDone("tcp", peer, nil)
		if observation.connects != nil {
			t.Fatalf("callbacks retained timings after the dial finished: %+v", observation.connects)
		}
	})

	t.Run("overlap", func(t *testing.T) {
		var observation socketDial
		peer := "192.0.2.1:443"
		observation.connectStart("tcp4", peer)
		observation.connectStart("tcp", peer)
		observation.connectDone("tcp", peer, nil)
		observation.connectDone("tcp4", peer, errors.New("dial cancelled"))
		if len(observation.connects) != 1 || !observation.connects[0].ambiguous || !observation.connects[0].finished.IsZero() {
			t.Fatalf("overlapping dials were treated as one socket: %+v", observation.connects)
		}
	})

	t.Run("default dialer failure", func(t *testing.T) {
		ctx, observation := withSocketDial(t.Context())
		blocked := errors.New("protect refused the socket")
		var started bool
		backend := New(Options{Logger: testLogger(t), ProtectFD: func(int) error {
			observation.mu.Lock()
			started = len(observation.connects) == 1 && !observation.connects[0].started.IsZero()
			observation.mu.Unlock()
			return blocked
		}})
		defer backend.Close()
		out, err := backend.NewOutbound("direct", DirectSpec{})
		if err != nil {
			t.Fatal(err)
		}
		defer out.Close()
		_, err = out.out.DialContext(ctx, "tcp", M.ParseSocksaddr("127.0.0.1:1"))
		if !errors.Is(err, blocked) || !started || len(observation.connects) != 0 {
			t.Fatalf("default dialer failed with %v, connect started = %v, entries left = %d", err, started, len(observation.connects))
		}
		observation.finish(nil, err)
	})

	t.Run("bounded under concurrent dials", func(t *testing.T) {
		var observation socketDial
		var workers sync.WaitGroup
		for i := range 4 * maxSocketTimings {
			peer := netip.AddrPortFrom(netip.MustParseAddr("192.0.2.1"), uint16(i+1)).String()
			workers.Go(func() { observation.connectStart("tcp", peer) })
		}
		workers.Wait()
		if len(observation.connects) > maxSocketTimings || !observation.timingOverflow {
			t.Fatalf("unexpected timing table after saturation: %d entries", len(observation.connects))
		}
		for i := range 4 * maxSocketTimings {
			peer := netip.AddrPortFrom(netip.MustParseAddr("192.0.2.1"), uint16(i+1)).String()
			workers.Go(func() { observation.connectDone("tcp", peer, nil) })
		}
		observation.finish(nil, nil)
		workers.Wait()
		if observation.connects != nil {
			t.Fatal("finished dial retained connect entries")
		}
	})
}

func TestSocketEventsUseRecordedTimesAndEndpoints(t *testing.T) {
	attempt := (&Backend{}).beginConnection(t.Context(), Metadata{Network: "tcp"})
	start := attempt.Start.Add(time.Millisecond)
	attempt.dialing(start, &Outbound{tag: "direct", typ: "direct"})
	attempt.mu.Lock()
	attempt.appendEventAtLocked(start.Add(4*time.Millisecond), connectionEvent{kind: eventServerDNS})
	attempt.mu.Unlock()
	attempt.dialed(start, start.Add(7*time.Millisecond), nil, socketDialResult{
		server:        netip.MustParseAddrPort("192.0.2.10:443"),
		local:         netip.MustParseAddrPort("192.0.2.20:49999"),
		interfaceName: "test0",
		tcp:           true,
		connect: socketConnect{
			started:  start.Add(time.Millisecond),
			finished: start.Add(3 * time.Millisecond),
		},
		tls: []socketTLS{{
			finished: start.Add(6 * time.Millisecond),
			event:    connectionEvent{kind: eventTLS, code: "tls", name: "proxy.test", duration: 3 * time.Millisecond, hasDuration: true},
		}},
	}, true)
	trace := attempt.trace()
	checkConnectionEventKinds(t, trace.Events, "accepted", "dial", "connect", "connected", "server_dns", "tls", "ready")
	connect, connected, tls := trace.Events[2], trace.Events[3], trace.Events[5]
	if connect.T != 2000 || connected.T != 4000 || connected.MS == nil || *connected.MS != 2 ||
		connect.Addr != trace.ServerAddr || connected.Addr != trace.ServerAddr ||
		connected.Peer != trace.LocalAddr || connected.Name != trace.Interface ||
		tls.T != 7000 || tls.MS == nil || *tls.MS != 3 ||
		trace.DialPeer != trace.ServerAddr || trace.TargetIP != "192.0.2.10" {
		t.Fatalf("unexpected socket events: %+v", trace)
	}
}

func TestSocketDialReuseKeepsOnlyMuxEvent(t *testing.T) {
	attempt := (&Backend{}).beginConnection(t.Context(), Metadata{Network: "tcp"})
	ctx, observation := withSocketDial(withAttempt(t.Context(), attempt))
	start := time.Now()
	attempt.dialing(start, &Outbound{tag: "xhttp", typ: "vless"})
	observeTLS(ctx, nil, start, time.Now(), "proxy.test", "tls")
	observation.multiplex(nil, false)
	observation.xhttpConnSelected(httptrace.GotConnInfo{Reused: true})
	attempt.dialed(start, time.Now(), nil, observation.finish(nil, nil), false)
	trace := attempt.trace()
	checkConnectionEventKinds(t, trace.Events, "accepted", "dial", "mux", "ready")
	checkSocketTraceMux(t, trace, "reuse")
}

func TestSocketInterfaceSnapshotThrottlesMisses(t *testing.T) {
	peer := netip.MustParseAddr("192.0.2.2")
	nextRefresh := time.Now().Add(interfaceRefreshInterval)
	snapshot := interfaceSnapshot{nextRefresh: nextRefresh, names: map[netip.Addr]string{peer: "test0"}}
	if name := snapshot.lookup(netip.MustParseAddr("::ffff:192.0.2.2")); name != "test0" {
		t.Fatalf("mapped address lookup = %q", name)
	}
	if name := snapshot.lookup(netip.MustParseAddr("192.0.2.3")); name != "" || snapshot.nextRefresh != nextRefresh {
		t.Fatalf("miss refreshed the snapshot early: %q %v", name, snapshot.nextRefresh)
	}
}

func TestSocketTraceLoopbackTCP(t *testing.T) {
	target := echoServer(t)
	t.Run("direct", func(t *testing.T) {
		backend, out := socketTraceOutbound(t, DirectSpec{})
		trace := socketTraceTCP(t, backend, out, target)
		checkTCPSocketTrace(t, trace, target)
		if trace.TargetIP != target.Addr().String() {
			t.Fatalf("direct target IP = %q", trace.TargetIP)
		}
	})
	t.Run("shadowsocks", func(t *testing.T) {
		peer := socketTraceShadowsocks(t)
		backend, out := socketTraceOutbound(t, ShadowsocksSpec{Server: "localhost", Port: peer.Port(), Method: "aes-128-gcm", Password: "test"})
		checkTCPSocketTrace(t, socketTraceTCP(t, backend, out, target), peer)
	})
	for _, protocol := range []string{"vless", "vmess", "trojan"} {
		t.Run(protocol, func(t *testing.T) {
			node, peer, opts := carrierNode(t, protocol, "")
			defer node.Close()
			backend, out := socketTraceOutbound(t, ProxySpec{
				Type: protocol, Server: peer.Addr().String(), Port: peer.Port(), UUID: testUUID, Password: "inner-secret", Options: opts,
			})
			checkTCPSocketTrace(t, socketTraceTCP(t, backend, out, target), peer)
		})
	}
}

func TestSocketTraceLoopbackUDP(t *testing.T) {
	server, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	go func() {
		var p [64]byte
		for {
			n, peer, err := server.ReadFrom(p[:])
			if err != nil {
				return
			}
			_, _ = server.WriteTo(p[:n], peer)
		}
	}()
	target := server.LocalAddr().(*net.UDPAddr)
	t.Run("unconnected direct socket", func(t *testing.T) {
		backend, out := socketTraceOutbound(t, DirectSpec{})
		trace := socketTraceUDP(t, backend, out, target)
		if trace.ServerAddr != "" || trace.LocalAddr != "" || trace.Interface != "" {
			t.Fatalf("wildcard socket reported concrete addresses: %+v", trace)
		}
		checkConnectionEventKinds(t, trace.Events, "udp_first", "matched", "dial", "ready")
	})
	t.Run("connected shadowsocks socket", func(t *testing.T) {
		peer := socketTraceShadowsocks(t)
		backend, out := socketTraceOutbound(t, ShadowsocksSpec{Server: peer.Addr().String(), Port: peer.Port(), Method: "aes-128-gcm", Password: "test"})
		trace := socketTraceUDP(t, backend, out, target)
		checkConnectionEventKinds(t, trace.Events, "udp_first", "matched", "dial", "connect", "connected", "ready")
		checkSocketEndpoints(t, trace, peer)
		if connected := trace.Events[4]; connected.MS != nil {
			t.Fatalf("UDP socket reported TCP timing: %+v", connected)
		}
	})
}

func TestSocketTraceLoopbackMultiplex(t *testing.T) {
	target := echoServer(t)
	var node *Server
	peer := testnet.RetryAddr(t, func(listen netip.AddrPort) (err error) {
		node, err = startNode(testLogger(t), func(b *Backend) (adapter.Inbound, string, error) {
			logger := b.componentLogger("inbound", "shadowsocks", "mux")
			mux, err := MX.NewRouterWithOptions(b.router, logger, option.InboundMultiplexOptions{Enabled: true})
			if err != nil {
				return nil, "shadowsocks", err
			}
			router := &multiplexTestRouter{Router: b.router, mux: mux}
			in, err := shadowsocks.NewInbound(b.ctx, router, logger, "mux", option.ShadowsocksInboundOptions{
				ListenOptions: listenOpts(listen), Method: "aes-128-gcm", Password: "test",
			})
			return in, "shadowsocks", err
		})
		return err
	})
	defer node.Close()
	for _, protocol := range []string{"h2mux", "smux", "yamux"} {
		t.Run(protocol, func(t *testing.T) {
			opts := []byte(`{"multiplex":{"enabled":true,"protocol":"` + protocol + `","max_connections":1}}`)
			backend, out := socketTraceOutbound(t, ProxySpec{
				Type: "shadowsocks", Server: peer.Addr().String(), Port: peer.Port(),
				Method: "aes-128-gcm", Password: "test", Options: opts,
			})
			first := socketTraceTCP(t, backend, out, target)
			checkTCPSocketTrace(t, first, peer)
			checkSocketTraceMux(t, first, "new")
			second := socketTraceTCP(t, backend, out, target)
			checkSocketTraceMux(t, second, "reuse")
			checkConnectionEventKinds(t, second.Events, "accepted", "matched", "dial", "mux", "ready")
		})
	}
}

func TestSocketTraceLoopbackTLS(t *testing.T) {
	target := echoServer(t)
	t.Run("reality", func(t *testing.T) {
		peer, key, sid := realityServer(t, testUUID, "")
		backend, out := socketTraceOutbound(t, realitySpec(peer, testUUID, "", key, sid))
		trace := socketTraceTCP(t, backend, out, target)
		checkTCPSocketTrace(t, trace, peer)
		checkSocketTraceTLS(t, trace, "reality", "reality.test")
	})
	t.Run("shadowtls carrier", func(t *testing.T) {
		node, inner, opts := carrierNode(t, "trojan", "")
		defer node.Close()
		plugin := SSPluginSpec{Type: "shadow-tls", Host: "plugin.test", Version: 3, Password: "outer-secret", TLS: &TLSSpec{Fingerprint: "chrome"}}
		port, security := pluginTestPeer(t, plugin, inner)
		security.Carrier = &TLSCarrierSpec{Type: plugin.Type, Version: plugin.Version, Password: plugin.Password}
		backend, out := socketTraceOutbound(t, ProxySpec{
			Type: "trojan", Server: "127.0.0.1", Port: port, Password: "inner-secret", TLS: security, Options: opts,
		})
		trace := socketTraceTCP(t, backend, out, target)
		checkTCPSocketTrace(t, trace, loopback(port))
		checkSocketTraceTLS(t, trace, "shadowtls", "plugin.test")
	})
}

func TestSocketTraceLoopbackXHTTPReuse(t *testing.T) {
	node := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	node.EnableHTTP2 = true
	node.StartTLS()
	defer node.Close()
	peer := node.Listener.Addr().(*net.TCPAddr).AddrPort()
	backend := New(Options{Logger: testLogger(t)})
	defer backend.Close()
	client, err := buildXHTTPStream(backend.ctx, backend.logger, map[string]any{"reka_xhttp": map[string]any{
		"mode": "packet-up", "host": "xhttp.test", "xmux": map[string]any{"max-connections": "1"},
	}}, peer.Addr().String(), peer.Port(), &TLSSpec{Insecure: true, ServerName: "xhttp.test", ALPN: []string{"h2"}})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	for i, code := range []string{"new", "reuse"} {
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		attempt := backend.beginConnection(ctx, Metadata{Network: "tcp"})
		ctx, observation := withSocketDial(withAttempt(ctx, attempt))
		start := time.Now()
		attempt.dialing(start, &Outbound{tag: "xhttp", typ: "vless"})
		conn, err := dialXHTTP(ctx, client)
		finished := time.Now()
		observed := observation.finish(conn, err)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		attempt.dialed(start, finished, nil, observed, false)
		trace := attempt.trace()
		checkSocketTraceMux(t, trace, code)
		if i == 0 {
			checkTCPSocketTrace(t, trace, peer)
			checkSocketTraceTLS(t, trace, "tls", "xhttp.test")
		} else {
			checkConnectionEventKinds(t, trace.Events, "accepted", "dial", "mux", "ready")
		}
	}
}

func socketTraceShadowsocks(t *testing.T) netip.AddrPort {
	t.Helper()
	var server *Server
	peer := testnet.RetryAddr(t, func(listen netip.AddrPort) (err error) {
		server, err = StartShadowsocksServer(listen, "aes-128-gcm", "test", testLogger(t))
		return err
	})
	t.Cleanup(func() { server.Close() })
	return peer
}

func socketTraceOutbound(t *testing.T, spec any) (*Backend, *Outbound) {
	t.Helper()
	b := New(Options{History: history.New(), Logger: testLogger(t)})
	t.Cleanup(func() { b.Close() })
	out, err := b.NewOutbound("observed", spec)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { out.Close() })
	b.SetRoute(Fixed(out))
	return b, out
}

func socketTraceTCP(t *testing.T, b *Backend, out *Outbound, target netip.AddrPort) api.ConnectionTrace {
	t.Helper()
	client, inbound := connectionEventPipe(t)
	done := make(chan struct{})
	client.SetDeadline(time.Now().Add(5 * time.Second))
	go b.router.RouteConnectionEx(t.Context(), inbound, adapter.InboundContext{
		InboundType: "tun", Destination: M.SocksaddrFromNetIP(target),
	}, func(error) { close(done) })
	socketTraceEcho(t, client)
	id := b.conns.next.Load()
	trace, ok := b.ConnectionTrace(id, "")
	if !ok || trace.Outbound != out.Tag() {
		t.Fatalf("missing active socket trace: %+v", trace)
	}
	closeConnectionEventFlow(t, b, id, done)
	closed := readClosedConnectionEventTrace(t, b.history, id)
	if closed.ServerAddr != trace.ServerAddr || closed.LocalAddr != trace.LocalAddr || closed.Interface != trace.Interface {
		t.Fatalf("socket metadata changed on close: %+v", closed)
	}
	return trace
}

func socketTraceUDP(t *testing.T, b *Backend, out *Outbound, target *net.UDPAddr) api.ConnectionTrace {
	t.Helper()
	client, inbound := connectionEventPipe(t)
	done := make(chan struct{})
	client.SetDeadline(time.Now().Add(5 * time.Second))
	b.router.RoutePacketConnectionEx(t.Context(), bufio.NewPacketConn(eventTestPacketConn{eventTestConn{inbound, target}}),
		adapter.InboundContext{InboundType: "tun"}, func(error) { close(done) })
	socketTraceEcho(t, client)
	id := b.conns.next.Load()
	trace, ok := b.ConnectionTrace(id, "")
	if !ok || trace.Outbound != out.Tag() {
		t.Fatalf("missing active socket trace: %+v", trace)
	}
	client.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("UDP session did not close")
	}
	return trace
}

func socketTraceEcho(t *testing.T, conn net.Conn) {
	t.Helper()
	const payload = "socket trace"
	if _, err := io.WriteString(conn, payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil || string(got) != payload {
		t.Fatalf("echo = %q, error = %v", got, err)
	}
}

func checkSocketEndpoints(t *testing.T, trace api.ConnectionTrace, peer netip.AddrPort) {
	t.Helper()
	local, err := netip.ParseAddrPort(trace.LocalAddr)
	if trace.ServerAddr != peer.String() || err != nil || !local.Addr().IsLoopback() || local.Port() == 0 || trace.Interface == "" {
		t.Fatalf("unexpected socket endpoints and interface: %+v", trace)
	}
}

func checkTCPSocketTrace(t *testing.T, trace api.ConnectionTrace, peer netip.AddrPort) {
	t.Helper()
	checkSocketEndpoints(t, trace, peer)
	var connect, connected api.ConnEvent
	for _, event := range trace.Events {
		switch event.Kind {
		case "connect":
			connect = event
		case "connected":
			connected = event
		}
	}
	if trace.DialPeer != trace.ServerAddr || connect.Addr != trace.ServerAddr || connected.Addr != trace.ServerAddr ||
		connected.Peer != trace.LocalAddr || connected.Name != trace.Interface || connected.MS == nil ||
		*connected.MS < 0 || connected.T < connect.T {
		t.Fatalf("missing or incomplete TCP socket events: %+v", trace.Events)
	}
}

func checkSocketTraceMux(t *testing.T, trace api.ConnectionTrace, code string) {
	t.Helper()
	var count int
	for _, event := range trace.Events {
		if event.Kind == "mux" && event.Code == code {
			count++
		}
	}
	if count != 1 || (code == "reuse" && (trace.ServerAddr != "" || trace.LocalAddr != "" || trace.Interface != "" || trace.DialPeer != "")) {
		t.Fatalf("unexpected multiplex observation: %+v", trace)
	}
}

func checkSocketTraceTLS(t *testing.T, trace api.ConnectionTrace, code, name string) {
	t.Helper()
	for _, event := range trace.Events {
		if event.Kind == "tls" && event.Code == code && event.Name == name && event.MS != nil && *event.MS >= 0 {
			return
		}
	}
	t.Fatalf("missing TLS observation for %q: %+v", code, trace.Events)
}
