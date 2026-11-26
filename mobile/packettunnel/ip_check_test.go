//go:build with_gvisor

package packettunnel

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/MimoProxy/reka/internal/backend/sagernet"
	"github.com/MimoProxy/reka/internal/runtime/generation"
	"github.com/MimoProxy/reka/internal/testnet"
	"github.com/MimoProxy/reka/mobile/profile"
	quic "github.com/sagernet/quic-go"
)

// ipCheckSuccessTimeoutMS is the product default IP check budget, used by
// tests whose probes are all expected to succeed.
const ipCheckSuccessTimeoutMS = 5000

func TestIPCheckLocalOnly(t *testing.T) {
	snapshot := prepareSnapshot(t, `
schema-version: 1
outbounds: [{id: direct, type: direct, dialer: {proxy: reject}}]
routing: {block-quic: proxy}
`)
	session, err := StartProbeProfile(snapshot, profile.Controls{BlockQUIC: "all"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(session.Close)
	var op Operation
	if err := json.Unmarshal(fmt.Appendf(nil, `{
		"action":"ipCheck","url4":"http://127.0.0.1:1","url6":"http://[::1]:1",
		"local4":[%q],"local6":["[::1]:1"],"localQuic":[%q],"timeout_ms":1500
	}`, ipCheckTestListener(t, "tcp4", "127.0.0.1:0"), ipCheckTestQUICListener(t)), &op); err != nil {
		t.Fatal(err)
	}
	result := runIPCheck(t, session, op)
	if result.Node != nil || result.IPVersion != "" || result.DNSMode != "fake-ip" || result.Local.IPv6.Status != "failed" {
		t.Fatalf("unexpected local-only result %+v", result)
	}
	assertIPCheckOK(t, result.Local.IPv4)
	if result.Recommendation == nil || result.Recommendation.IPVersion != "ipv4" || result.Recommendation.Reason != "local-ipv6-unavailable" {
		t.Fatalf("unexpected recommendation %+v", result.Recommendation)
	}
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]json.RawMessage
	if err := json.Unmarshal(data, &wire); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"local", "dnsMode", "ipVersion", "recommendation", "quic"} {
		if _, ok := wire[field]; !ok {
			t.Fatalf("missing %s in %s", field, data)
		}
	}
	if len(wire) != 5 || string(wire["ipVersion"]) != `""` {
		t.Fatalf("unexpected local-only JSON %s", data)
	}
	var quicWire map[string]json.RawMessage
	if err := json.Unmarshal(wire["quic"], &quicWire); err != nil {
		t.Fatal(err)
	}
	if len(quicWire) != 2 || string(quicWire["blockQuic"]) != `"all"` {
		t.Fatalf("unexpected local-only QUIC JSON %s", wire["quic"])
	}
	var localQUIC generation.IPCheck
	if err := json.Unmarshal(quicWire["local"], &localQUIC); err != nil {
		t.Fatal(err)
	}
	assertIPCheckOK(t, localQUIC)
}

func TestIPCheckPacketFlowUsesSelectedLeaf(t *testing.T) {
	origin := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	server6 := ipCheckTestHTTPServer(t, "tcp6", "[::1]:0", origin)
	server4 := ipCheckTestHTTPServer(t, "tcp4", "127.0.0.1:0", origin)
	want4, want6 := server4.Listener.Addr().String(), server6.Listener.Addr().String()
	var connects atomic.Int32
	proxy := ipCheckTestHTTPServer(t, "tcp4", "127.0.0.1:0", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect || (r.Host != want4 && r.Host != want6) {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		conn, rw, err := http.NewResponseController(w).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		_, _ = rw.WriteString("HTTP/1.1 200 Connection established\r\n\r\n")
		if err := rw.Flush(); err != nil {
			return
		}
		request, err := http.ReadRequest(rw.Reader)
		if err != nil || request.Method != http.MethodGet {
			return
		}
		_ = request.Body.Close()
		connects.Add(1)
		body := "ip=203.0.113.7\nloc=SG\n"
		if r.Host == want6 {
			body = "2001:db8::7\n"
		}
		_, _ = fmt.Fprintf(rw, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
		_ = rw.Flush()
	}))
	snapshot := prepareSnapshot(t, fmt.Sprintf(`
schema-version: 1
outbounds: [{id: relay, name: Relay, type: http, server: 127.0.0.1, port: %d}]
groups: [{id: choice, type: select, members: [direct, relay]}]
rules: [{match: {all: true}, outbound: reject}]
dns: {ipv6: true, enhanced-mode: fake-ip, nameserver: [system]}
`, proxy.Listener.Addr().(*net.TCPAddr).Port))
	controls := profile.Controls{IPVersion: "ipv4", Selections: map[string]string{"choice": "relay"}}
	session, err := StartProfile(snapshot, controls, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(session.Close)
	quicTarget := ipCheckTestQUICListener(t)
	op := Operation{
		Action: "ipCheck", Member: "choice", URL4: server4.URL, URL6: server6.URL,
		Local4: []string{ipCheckTestListener(t, "tcp4", "127.0.0.1:0")}, Local6: []string{ipCheckTestListener(t, "tcp6", "[::1]:0")},
		// The product's 5 s budget: these probes all succeed, and slow
		// runners have needed more than 2 s for the HTTP and QUIC handshakes.
		LocalQUIC: []string{quicTarget}, NodeQUIC: []string{quicTarget}, TimeoutMS: ipCheckSuccessTimeoutMS,
	}
	result := runIPCheck(t, session, op)
	if result.DNSMode != "fake-ip" || result.IPVersion != "ipv4" {
		t.Fatalf("unexpected DNS or IP version %+v", result)
	}
	node := result.Node
	if node == nil || node.Member != "choice" || node.Resolved != "relay" || node.Name != "Relay" || node.Type != "http" {
		t.Fatalf("wrong leaf metadata %+v", node)
	}
	if node.Host != "127.0.0.1" || node.Port != uint16(proxy.Listener.Addr().(*net.TCPAddr).Port) || node.UDP {
		t.Fatalf("wrong server metadata %+v", node)
	}
	for _, check := range []generation.IPCheck{result.Local.IPv4, result.Local.IPv6, node.Server.IPv4, node.Exit.IPv4, node.Exit.IPv6} {
		assertIPCheckOK(t, check)
	}
	if node.Server.IPv6.Status != "unavailable" || connects.Load() != 2 {
		t.Fatalf("unexpected server or exit checks %+v, CONNECTs: %d", node, connects.Load())
	}
	if !slices.Equal(node.Server.IPv4.Addresses, []string{"127.0.0.1"}) ||
		!slices.Equal(node.Exit.IPv4.Addresses, []string{"203.0.113.7"}) || node.Exit.IPv4.Country != "SG" ||
		!slices.Equal(node.Exit.IPv6.Addresses, []string{"2001:db8::7"}) || node.Exit.IPv6.Country != "" {
		t.Fatalf("wrong server or exit address metadata %+v", node)
	}
	if result.Recommendation == nil || result.Recommendation.IPVersion != "ipv4-prefer" || result.Recommendation.Reason != "server-ipv4-only" {
		t.Fatalf("unexpected recommendation %+v", result.Recommendation)
	}
	assertIPCheckOK(t, result.QUIC.Local)
	if result.QUIC.Node == nil || result.QUIC.Node.Status != "failed" || result.QUIC.Node.Error != "udp unsupported" {
		t.Fatalf("unexpected node QUIC check %+v", result.QUIC.Node)
	}
	if rec := result.QUIC.Recommendation; result.QUIC.BlockQUIC != "off" || rec == nil || rec.BlockQUIC != "proxy" || rec.Reason != "node-quic-unavailable" {
		t.Fatalf("unexpected QUIC settings or recommendation %+v", result.QUIC)
	}
	session.SetRealDNS(true)
	op.Member = ""
	if result := runIPCheck(t, session, op); result.DNSMode != "normal" {
		t.Fatalf("DNS mode with real DNS enabled = %q", result.DNSMode)
	}
}

func TestIPCheckQUICUsesSelectedUDPNode(t *testing.T) {
	quicTarget := netip.MustParseAddrPort(ipCheckTestQUICListener(t))
	// The node forwards an otherwise silent loopback address to the QUIC server.
	nodeTarget := netip.MustParseAddrPort(ipCheckTestSilentUDP(t))
	var relay *sagernet.Server
	listen := testnet.RetryAddr(t, func(address netip.AddrPort) error {
		var err error
		relay, err = sagernet.StartShadowsocksTestServer(address, "aes-128-gcm", "test", nil, map[netip.AddrPort]netip.AddrPort{nodeTarget: quicTarget})
		return err
	})
	t.Cleanup(func() { _ = relay.Close() })
	snapshot := prepareSnapshot(t, fmt.Sprintf(`
schema-version: 1
outbounds:
  - {id: relay, type: shadowsocks, server: 127.0.0.1, port: %d, method: aes-128-gcm, password: test, udp: true}
groups: [{id: choice, type: select, members: [relay]}]
`, listen.Port()))
	session, err := StartProbeProfile(snapshot, profile.Controls{BlockQUIC: "proxy"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(session.Close)
	result := runIPCheck(t, session, Operation{
		Action: "ipCheck", Member: "choice", URL4: "http://127.0.0.1:1", URL6: "http://127.0.0.1:1",
		Local4: []string{"127.0.0.1:1"}, Local6: []string{"[::1]:1"},
		LocalQUIC: []string{quicTarget.String()}, NodeQUIC: []string{nodeTarget.String()}, TimeoutMS: ipCheckSuccessTimeoutMS,
	})
	if result.QUIC.Node == nil {
		t.Fatal("missing selected node's QUIC check")
	}
	assertIPCheckOK(t, result.QUIC.Local)
	assertIPCheckOK(t, *result.QUIC.Node)
	if rec := result.QUIC.Recommendation; rec == nil || rec.BlockQUIC != "off" || rec.Reason != "quic-ok" {
		t.Fatalf("unexpected QUIC recommendation %+v", rec)
	}
}

func TestIPCheckStartsAllHTTPProbesAndReturnsAfterHeaders(t *testing.T) {
	local6 := ipCheckTestListener(t, "tcp6", "[::1]:0")
	var requests atomic.Int32
	all := make(chan struct{})
	server := ipCheckTestHTTPServer(t, "tcp4", "127.0.0.1:0", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requests.Add(1) == 2 {
			close(all)
		}
		select {
		case <-all:
		case <-r.Context().Done():
			return
		}
		w.Header().Set("Content-Length", "16")
		w.WriteHeader(http.StatusForbidden)
		_ = http.NewResponseController(w).Flush()
		<-r.Context().Done()
	}))
	session, err := StartProbeProfile(prepareSnapshot(t, "schema-version: 1\n"), profile.Controls{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(session.Close)
	quicTarget := ipCheckTestQUICListener(t)
	start := time.Now()
	result := runIPCheck(t, session, Operation{
		Action: "ipCheck", Member: "direct", URL4: server.URL, URL6: server.URL,
		Local4: []string{ipCheckTestListener(t, "tcp4", "127.0.0.1:0")}, Local6: []string{local6},
		LocalQUIC: []string{quicTarget}, NodeQUIC: []string{quicTarget}, TimeoutMS: 4000,
	})
	if elapsed := time.Since(start); elapsed >= 3*time.Second {
		t.Fatalf("probe delayed by body or other checks: %s", elapsed)
	}
	if result.Node == nil || requests.Load() != 2 {
		t.Fatalf("expected two HTTP exit checks, got %+v and %d requests", result, requests.Load())
	}
	for _, check := range []generation.IPCheck{result.Local.IPv4, result.Local.IPv6, result.Node.Exit.IPv4, result.Node.Exit.IPv6} {
		assertIPCheckOK(t, check)
	}
}

func TestIPCheckDirectMemberDoesNotAffectRecommendation(t *testing.T) {
	session, err := StartProbeProfile(prepareSnapshot(t, "schema-version: 1\n"), profile.Controls{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(session.Close)
	quicTarget := ipCheckTestQUICListener(t)
	result := runIPCheck(t, session, Operation{
		Action: "ipCheck", Member: "direct", URL4: "http://127.0.0.1:1", URL6: "http://[::1]:1",
		Local4:    []string{ipCheckTestListener(t, "tcp4", "127.0.0.1:0")},
		Local6:    []string{ipCheckTestListener(t, "tcp6", "[::1]:0")},
		LocalQUIC: []string{quicTarget}, NodeQUIC: []string{quicTarget},
		TimeoutMS: 2000,
	})
	if result.Node == nil || result.Node.Type != "direct" || result.Node.Exit.IPv6.Status != "failed" {
		t.Fatalf("expected a failed direct exit check, got %+v", result.Node)
	}
	if result.Node.Host != "" || result.Node.Port != 0 || !result.Node.UDP {
		t.Fatalf("wrong direct outbound metadata %+v", result.Node)
	}
	if result.Recommendation == nil || result.Recommendation.Reason != "dual-ok" {
		t.Fatalf("direct exit results should not drive the recommendation: %+v", result.Recommendation)
	}
	assertIPCheckOK(t, result.QUIC.Local)
	if result.QUIC.Node != nil || result.QUIC.Recommendation != nil {
		t.Fatalf("unexpected QUIC node check or recommendation for direct %+v", result.QUIC)
	}
}

func TestIPCheckDeadlineAndSessionCancellation(t *testing.T) {
	started := make(chan struct{}, 1)
	server := ipCheckTestHTTPServer(t, "tcp4", "127.0.0.1:0", http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		select {
		case started <- struct{}{}:
		default:
		}
		<-r.Context().Done()
	}))
	session, err := StartProbeProfile(prepareSnapshot(t, "schema-version: 1\n"), profile.Controls{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(session.Close)
	quicTarget := ipCheckTestSilentUDP(t)
	op := Operation{
		Action: "ipCheck", Member: "direct", URL4: server.URL, URL6: server.URL,
		Local4: []string{"127.0.0.1:1"}, Local6: []string{"[::1]:1"},
		LocalQUIC: []string{quicTarget}, NodeQUIC: []string{quicTarget}, TimeoutMS: 250,
	}
	start := time.Now()
	result := runIPCheck(t, session, op)
	if elapsed := time.Since(start); elapsed >= time.Second {
		t.Fatalf("shared timeout exceeded: %s", elapsed)
	}
	if result.Recommendation != nil || result.Node == nil {
		t.Fatalf("unexpected timed out result %+v", result)
	}
	for _, check := range []generation.IPCheck{result.Local.IPv4, result.Local.IPv6} {
		// Closed loopback TCP ports refuse at once.
		if check.Status != "failed" || check.DelayMS != nil {
			t.Fatalf("unexpected local check %+v", check)
		}
	}
	for _, check := range []generation.IPCheck{result.Node.Exit.IPv4, result.Node.Exit.IPv6, result.QUIC.Local} {
		if check.Status != "failed" || check.Error != "timeout" || check.DelayMS != nil {
			t.Fatalf("unexpected timeout check %+v", check)
		}
	}
	select {
	case <-started:
	default:
	}
	op.TimeoutMS = 5000
	done := make(chan error, 1)
	go func() {
		_, err := session.RunOperation(op)
		done <- err
	}()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("no request started")
	}
	session.Close()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("operation returned %v after cancellation", err)
		}
	case <-time.After(time.Second):
		t.Fatal("operation did not stop after session cancellation")
	}
}

func ipCheckTestHTTPServer(t *testing.T, network, address string, handler http.Handler) *httptest.Server {
	t.Helper()
	listener, err := net.Listen(network, address)
	if network == "tcp6" && (errors.Is(err, syscall.EAFNOSUPPORT) || errors.Is(err, syscall.EADDRNOTAVAIL)) {
		t.Skip("IPv6 loopback unavailable")
	}
	if err != nil {
		t.Fatal(err)
	}
	server := &httptest.Server{Listener: listener, Config: &http.Server{Handler: handler}}
	server.Start()
	t.Cleanup(server.Close)
	return server
}

func runIPCheck(t *testing.T, session *Session, op Operation) generation.IPCheckResult {
	t.Helper()
	value, err := session.RunOperation(op)
	if err != nil {
		t.Fatal(err)
	}
	result, ok := value.(generation.IPCheckResult)
	if !ok {
		t.Fatalf("unexpected result type %T", value)
	}
	return result
}

func assertIPCheckOK(t *testing.T, check generation.IPCheck) {
	t.Helper()
	if check.Status != "ok" || check.DelayMS == nil || *check.DelayMS < 1 || check.Error != "" {
		t.Fatalf("expected successful check with latency, got %+v", check)
	}
}

func ipCheckTestQUICListener(t *testing.T) string {
	t.Helper()
	https := httptest.NewTLSServer(http.NotFoundHandler())
	cert := https.TLS.Certificates[0]
	https.Close()
	listener, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert}, NextProtos: []string{"h3"},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	return listener.Addr().String()
}

func ipCheckTestSilentUDP(t *testing.T) string {
	t.Helper()
	packet, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = packet.Close() })
	return packet.LocalAddr().String()
}

// ipCheckTestListener serves TLS handshakes until the test ends and returns
// its address.
func ipCheckTestListener(t *testing.T, network, address string) string {
	t.Helper()
	listener, err := net.Listen(network, address)
	if network == "tcp6" && (errors.Is(err, syscall.EAFNOSUPPORT) || errors.Is(err, syscall.EADDRNOTAVAIL)) {
		t.Skip("IPv6 loopback unavailable")
	}
	if err != nil {
		t.Fatal(err)
	}
	server := &httptest.Server{Listener: listener, Config: &http.Server{Handler: http.NotFoundHandler()}}
	server.StartTLS()
	t.Cleanup(server.Close)
	return listener.Addr().String()
}
