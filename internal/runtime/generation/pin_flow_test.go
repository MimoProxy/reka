package generation

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MimoProxy/reka/internal/backend/sagernet"
	"github.com/MimoProxy/reka/internal/config/compile"
	RD "github.com/MimoProxy/reka/internal/dns"
	"github.com/MimoProxy/reka/internal/policy"
	D "github.com/miekg/dns"
	"golang.org/x/net/proxy"
)

func pinFlowApply(t *testing.T, e *Engine, profile, local string, revision uint64) *Prepared {
	t.Helper()
	eff, ds := compile.Compile([]byte(profile), []byte(local), compile.Options{})
	if ds.HasErrors() {
		t.Fatal(ds)
	}
	p, err := e.Prepare(eff)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.Activate(p, revision); err != nil {
		t.Fatal(err)
	}
	return p
}

func pinFlowDNS(t *testing.T) (string, *atomic.Int32) {
	t.Helper()
	var packet net.PacketConn
	var listener net.Listener
	for range 64 {
		var err error
		packet, err = net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			continue
		}
		listener, err = net.Listen("tcp", packet.LocalAddr().String())
		if err == nil {
			break
		}
		_ = packet.Close()
	}
	if listener == nil {
		t.Fatal("no TCP/UDP DNS fixture address")
	}
	queries := &atomic.Int32{}
	handler := D.HandlerFunc(func(w D.ResponseWriter, q *D.Msg) {
		queries.Add(1)
		m := new(D.Msg)
		m.SetReply(q)
		switch q.Question[0].Qtype {
		case D.TypeA:
			m.Answer = []D.RR{&D.A{Hdr: D.RR_Header{Name: q.Question[0].Name, Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 30}, A: net.IPv4(127, 0, 0, 1)}}
		case D.TypeHTTPS:
			m.Answer = []D.RR{&D.HTTPS{SVCB: D.SVCB{Hdr: D.RR_Header{Name: q.Question[0].Name, Rrtype: D.TypeHTTPS, Class: D.ClassINET, Ttl: 30}, Priority: 1, Target: ".", Value: []D.SVCBKeyValue{&D.SVCBECHConfig{ECH: []byte{0, 1, 2}}}}}}
		}
		_ = w.WriteMsg(m)
	})
	server := &D.Server{PacketConn: packet, Handler: handler}
	tcpServer := &D.Server{Listener: listener, Handler: handler}
	started := make(chan struct{})
	tcpStarted := make(chan struct{})
	server.NotifyStartedFunc = func() { close(started) }
	tcpServer.NotifyStartedFunc = func() { close(tcpStarted) }
	go server.ActivateAndServe()
	go tcpServer.ActivateAndServe()
	<-started
	<-tcpStarted
	t.Cleanup(func() { _ = server.Shutdown(); _ = tcpServer.Shutdown() })
	return packet.LocalAddr().String(), queries
}

func pinFlowListenerAddress(t *testing.T) netip.AddrPort {
	t.Helper()
	for range 64 {
		packet, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			continue
		}
		listener, err := net.Listen("tcp", packet.LocalAddr().String())
		address := packet.LocalAddr().(*net.UDPAddr).AddrPort()
		_ = packet.Close()
		if err == nil {
			_ = listener.Close()
			return address
		}
	}
	t.Fatal("no shared TCP/UDP fixture port")
	return netip.AddrPort{}
}

func pinFlowWaitDrained(t *testing.T, outbound *sagernet.Outbound) {
	t.Helper()
	select {
	case <-outbound.Lease().Drained():
	case <-time.After(3 * time.Second):
		t.Fatalf("outbound %s retained a lease: active=%d total=%d", outbound.Tag(), outbound.Active(), outbound.Lease().Active())
	}
}

func TestPreparedFlowActualDialUsesRetiredResolverAndDrainsUnrelatedNodes(t *testing.T) {
	dnsAddress, queries := pinFlowDNS(t)
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		conn, err := echo.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = io.Copy(conn, conn)
	}()
	listen := pinFlowListenerAddress(t)
	local := fmt.Sprintf("listeners: [{id: mixed, type: mixed, listen: %q}]", listen.String())
	e := NewEngine(EngineOptions{})
	defer e.Close()
	old := pinFlowApply(t, e, fmt.Sprintf("schema-version: 1\nsniff: {enabled: true, timeout-ms: 2000}\noutbounds: [{id: selected, type: direct}, {id: resolver, type: direct}, {id: unrelated, type: direct}]\ndns: {nameserver: [%q]}\nrules: [{match: {all: true}, outbound: selected}]\n", "udp://"+dnsAddress+"#resolver"), local, 1)
	captured := make(chan struct{})
	var captureOnce sync.Once
	e.backend.SetPrepareFlow(func(ctx context.Context, md sagernet.Metadata) sagernet.PreparedFlow {
		flow := e.prepareFlow(ctx, md)
		captureOnce.Do(func() { close(captured) })
		return flow
	})
	dialer, err := proxy.SOCKS5("tcp", listen.String(), nil, &net.Dialer{Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	_, port, _ := net.SplitHostPort(echo.Addr().String())
	conn, err := dialer.Dial("tcp", net.JoinHostPort("after-route.test", port))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	<-captured
	// Commit while the accepted flow is waiting for its first payload. Its rule
	// matches without DNS; the query must happen later, inside actual dialing.
	pinFlowApply(t, e, "schema-version: 1\nrules: [{match: {all: true}, outbound: reject}]\n", local, 2)
	if queries.Load() != 0 {
		t.Fatal("fixture queried DNS before route selection")
	}
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	payload := []byte("GET / HTTP/1.1\r\nHost: after-route.test\r\n\r\n")
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil || !bytes.Equal(got, payload) {
		t.Fatal("post-selection dialing lost the retired resolver or changed bytes", err)
	}
	if queries.Load() == 0 {
		t.Fatal("dialing did not exercise the captured DNS")
	}
	if old.outbounds["selected"].Active() != 1 || old.outbounds["resolver"].Active() != 0 {
		t.Fatalf("flow/dependency counts: selected=%d resolver=%d", old.outbounds["selected"].Active(), old.outbounds["resolver"].Active())
	}
	pinFlowWaitDrained(t, old.outbounds["unrelated"])
	select {
	case <-old.outbounds["resolver"].Lease().Drained():
		t.Fatal("live flow released its resolver dependency")
	default:
	}
	conn.Close()
	pinFlowWaitDrained(t, old.outbounds["selected"])
	pinFlowWaitDrained(t, old.outbounds["resolver"])
}

func TestPreparedFlowResolverCanAlsoBeSelectedAndContextPreservesECH(t *testing.T) {
	dnsAddress, _ := pinFlowDNS(t)
	e := NewEngine(EngineOptions{})
	defer e.Close()
	old := pinFlowApply(t, e, fmt.Sprintf("schema-version: 1\nsniff: {enabled: true}\noutbounds: [{id: selected, type: direct}, {id: direct, type: direct, udp: false}]\ndns: {nameserver: [%q], proxy-server-nameserver: [%q]}\nrules: [{match: {all: true}, outbound: selected}]\n", "udp://"+dnsAddress+"#selected", "tcp://"+dnsAddress), "", 1)
	_, captured := e.current()
	md := sagernet.Metadata{Network: "tcp", Destination: sagernet.Destination{Domain: "selected-resolver.test", Port: 443}}
	prepared := e.prepareFlow(context.Background(), md)
	defer prepared.Release()
	pinFlowApply(t, e, "schema-version: 1\nrules: [{match: {all: true}, outbound: reject}]\n", "", 2)
	if !old.outbounds["direct"].Lease().Retired() {
		t.Fatal("ECH DNS fixture did not retire its direct transport")
	}
	result := prepared.Route(context.Background(), md)
	if result.Outbound == nil {
		t.Fatal("captured route was lost")
	}
	defer result.Release()
	prepared.Release()
	if result.Outbound.Active() != 1 || result.Outbound.Lease().Active() != 2 {
		t.Fatalf("selected/DNS pins conflated: active=%d total=%d", result.Outbound.Active(), result.Outbound.Lease().Active())
	}
	if _, err := result.Lookup(context.Background(), "lookup-after-selection.test"); err != nil {
		t.Fatal("returned Lookup lost its DNS pin", err)
	}
	if result.Context == nil {
		t.Fatal("dial context missing resolver pins")
	}
	ech, err := sagernet.ResolveECH(result.Context(context.Background()), "ech-after-selection.test", func(ctx context.Context, q *D.Msg) (*D.Msg, error) {
		return captured.dns.Exchange(ctx, q, "proxy", false)
	})
	if err != nil || !bytes.Equal(ech, []byte{0, 1, 2}) {
		t.Fatal("automatic ECH lost its resolver pin", ech, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	decorated := result.Context(ctx)
	cancel()
	if decorated.Err() != context.Canceled {
		t.Fatal("dial context replaced caller cancellation")
	}
	result.Release()
	result.Release()
	pinFlowWaitDrained(t, old.outbounds["selected"])
	pinFlowWaitDrained(t, old.outbounds["direct"])
	if old.outbounds["selected"].Active() != 0 {
		t.Fatal("flow release corrupted active count")
	}
	if _, err := result.Lookup(context.Background(), "uncached-after-flow-close.test"); err == nil {
		t.Fatal("closed flow borrowed an obsolete resolver")
	}
}

func TestSniffDNSDependencySetCoversListsGroupsAndRespectRules(t *testing.T) {
	profile := "schema-version: 1\noutbounds: [{id: ns, type: direct}, {id: direct-dns, type: direct}, {id: fallback-dns, type: direct}, {id: policy-one, type: direct}, {id: policy-two, type: direct}, {id: unrelated, type: direct}]\ngroups: [{id: dns-pool, type: select, members: [policy-one, nested]}, {id: nested, type: select, members: [policy-two]}]\nrules: [{match: {all: true}, outbound: direct}]\n"
	eff, ds := compile.Compile([]byte(profile), nil, compile.Options{})
	if ds.HasErrors() {
		t.Fatal(ds)
	}
	eff.DNS = &RD.Config{
		Nameservers: []string{"udp://127.0.0.1#ns"}, Bootstrap: []string{"tcp://127.0.0.1"}, Proxy: []string{"tls://127.0.0.1"},
		Direct: []string{"udp://127.0.0.1#direct-dns"}, Fallback: []string{"udp://127.0.0.1#fallback-dns"},
		Policies: []RD.Policy{{ID: "policy", Pattern: "policy.test", Servers: []string{"udp://127.0.0.1#dns-pool"}}},
	}
	resources := map[string]*sagernet.Outbound{}
	for _, id := range []string{"ns", "direct", "direct-dns", "fallback-dns", "policy-one", "policy-two", "unrelated"} {
		resources[id] = &sagernet.Outbound{}
	}
	g := &generation{eff: eff, dns: &RD.Service{}}
	needed := sniffDNSDependencies(g, resources)
	if len(needed) != 6 || needed[resources["unrelated"]] {
		t.Fatal("missing a DNS scope/group member or retained an unrelated node", len(needed))
	}
	eff.DNS.RespectRules = true
	if needed := sniffDNSDependencies(g, resources); len(needed) != len(resources) {
		t.Fatal("respect-rules did not retain all possible routing targets")
	}
}

func TestPinnedFlowTransferCloseRaceDoesNotLeakOrDoubleCount(t *testing.T) {
	b := sagernet.New(sagernet.Options{})
	defer b.Close()
	for i := range 100 {
		out, err := b.NewOutbound(fmt.Sprintf("pin-%d", i), sagernet.DirectSpec{})
		if err != nil {
			t.Fatal(err)
		}
		pin, err := out.Pin()
		if err != nil {
			t.Fatal(err)
		}
		out.Lease().Retire()
		var release func()
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); release, _ = pin.TransferToFlow() }()
		go func() { defer wg.Done(); _ = pin.Close() }()
		wg.Wait()
		if release != nil {
			release()
			release()
		}
		pinFlowWaitDrained(t, out)
		if out.Active() != 0 || out.Lease().Active() != 0 {
			t.Fatal("transfer/close race corrupted accounting", out.Active(), out.Lease().Active())
		}
		_ = out.Close()
	}
}

func TestPreparedFlowDetourUsesCapturedChoiceWhileOrdinaryFlowUsesActiveChoice(t *testing.T) {
	e := NewEngine(EngineOptions{})
	defer e.Close()
	eff, ds := compile.Compile([]byte("schema-version: 1\nsniff: {enabled: true}\noutbounds: [{id: child, type: socks, server: 127.0.0.1, port: 1080, dialer: {proxy: hop}}, {id: a, type: direct}, {id: b, type: direct}]\ngroups: [{id: hop, type: fallback, members: [a,b], lazy: true, url: 'https://example.test/'}]\nrules: [{match: {all: true}, outbound: child}]\n"), nil, compile.Options{})
	if ds.HasErrors() {
		t.Fatal(ds)
	}
	activate := func(choice string, revision uint64) *Prepared {
		t.Helper()
		p, err := e.Prepare(eff)
		if err != nil {
			t.Fatal(err)
		}
		if p.policies != nil {
			p.policies.Close()
		}
		// Isolate the observed choice from probe timing. Identical transport and
		// group configuration lets the child survive the intervening revision.
		p.policies = policy.New([]policy.Group{{ID: "hop", Type: "fallback", Members: []string{"a", "b"}, Selected: choice, Lazy: true}}, func(context.Context, string, string) error { return nil })
		if _, err := e.Activate(p, revision); err != nil {
			t.Fatal(err)
		}
		return p
	}
	old := activate("a", 1)
	md := sagernet.Metadata{Network: "tcp", Destination: sagernet.Destination{Addr: netip.MustParseAddr("192.0.2.8"), Port: 443}}
	prepared := e.prepareFlow(context.Background(), md)
	defer prepared.Release()
	current := activate("b", 2)
	if old.outbounds["child"] != current.outbounds["child"] {
		t.Fatal("group selection unnecessarily replaced child transport")
	}
	result := prepared.Route(context.Background(), md)
	if result.Outbound == nil || result.Context == nil {
		t.Fatal("prepared route lost captured detour context")
	}
	defer result.Release()
	prepared.Release()
	bridge := old.detours[0]
	if parent, err := bridge.parent(result.Context(context.Background()), "tcp", "target.test:443"); err != nil || parent != bridge.pins["a"] {
		t.Fatal("prepared flow's parent changed to the new group's selection", err)
	}
	ordinary := e.route(context.Background(), md)
	if ordinary.Outbound == nil {
		t.Fatal("new ordinary route rejected")
	}
	defer ordinary.Release()
	ctx := context.Background()
	if ordinary.Context != nil {
		ctx = ordinary.Context(ctx)
	}
	if parent, err := bridge.parent(ctx, "tcp", "target.test:443"); err != nil || parent != bridge.pins["b"] {
		t.Fatal("ordinary new flow did not observe active group selection", err)
	}
}
