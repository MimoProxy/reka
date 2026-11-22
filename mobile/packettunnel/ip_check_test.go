//go:build with_gvisor

package packettunnel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/MimoProxy/reka/internal/runtime/generation"
	"github.com/MimoProxy/reka/mobile/profile"
)

func TestIPCheckLocalOnly(t *testing.T) {
	server := ipCheckTestHTTPServer(t, "tcp4", "127.0.0.1:0", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	snapshot := prepareSnapshot(t, `
schema-version: 1
outbounds: [{id: direct, type: direct, dialer: {proxy: reject}}]
`)
	session, err := StartProbeProfile(snapshot, profile.Controls{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(session.Close)
	var op Operation
	if err := json.Unmarshal(fmt.Appendf(nil, `{"action":"ipCheck","local4":[%q],"local6":["[::1]:1"],"timeout_ms":1500}`, server.Listener.Addr().String()), &op); err != nil {
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
	for _, field := range []string{"local", "dnsMode", "ipVersion", "recommendation"} {
		if _, ok := wire[field]; !ok {
			t.Fatalf("missing %s in %s", field, data)
		}
	}
	if len(wire) != 4 || string(wire["ipVersion"]) != `""` {
		t.Fatalf("unexpected local-only JSON %s", data)
	}
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
		_, _ = rw.WriteString("HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
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
	op := Operation{Action: "ipCheck", Member: "choice", URL4: server4.URL, URL6: server6.URL, Local4: []string{want4}, Local6: []string{want6}, TimeoutMS: 2000}
	result := runIPCheck(t, session, op)
	if result.DNSMode != "fake-ip" || result.IPVersion != "ipv4" {
		t.Fatalf("unexpected DNS or IP version %+v", result)
	}
	node := result.Node
	if node == nil || node.Member != "choice" || node.Resolved != "relay" || node.Name != "Relay" || node.Type != "http" {
		t.Fatalf("wrong leaf metadata %+v", node)
	}
	for _, check := range []generation.IPCheck{result.Local.IPv4, result.Local.IPv6, node.Server.IPv4, node.Exit.IPv4, node.Exit.IPv6} {
		assertIPCheckOK(t, check)
	}
	if node.Server.IPv6.Status != "unavailable" || connects.Load() != 2 {
		t.Fatalf("unexpected server or exit checks %+v, CONNECTs: %d", node, connects.Load())
	}
	if result.Recommendation == nil || result.Recommendation.IPVersion != "ipv4-prefer" || result.Recommendation.Reason != "server-ipv4-only" {
		t.Fatalf("unexpected recommendation %+v", result.Recommendation)
	}
	session.SetRealDNS(true)
	op.Member = ""
	if result := runIPCheck(t, session, op); result.DNSMode != "normal" {
		t.Fatalf("DNS mode with real DNS enabled = %q", result.DNSMode)
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
	start := time.Now()
	result := runIPCheck(t, session, Operation{
		Action: "ipCheck", Member: "direct", URL4: server.URL, URL6: server.URL,
		Local4: []string{server.Listener.Addr().String()}, Local6: []string{local6}, TimeoutMS: 4000,
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
	op := Operation{
		Action: "ipCheck", Member: "direct", URL4: server.URL, URL6: server.URL,
		Local4: []string{"127.0.0.1:1"}, Local6: []string{"[::1]:1"}, TimeoutMS: 250,
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
		// Closed loopback ports refuse at once, so only the exit checks reach the deadline.
		if check.Status != "failed" || check.DelayMS != nil {
			t.Fatalf("unexpected local check %+v", check)
		}
	}
	for _, check := range []generation.IPCheck{result.Node.Exit.IPv4, result.Node.Exit.IPv6} {
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

// ipCheckTestListener accepts and closes connections until the test ends.
func ipCheckTestListener(t *testing.T, network, address string) string {
	t.Helper()
	listener, err := net.Listen(network, address)
	if err != nil {
		if errors.Is(err, syscall.EADDRNOTAVAIL) || errors.Is(err, syscall.EAFNOSUPPORT) {
			t.Skipf("%s loopback unavailable: %v", network, err)
		}
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	return listener.Addr().String()
}
