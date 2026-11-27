//go:build !ios

package generation

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/MimoProxy/reka/internal/backend/sagernet"
	"github.com/MimoProxy/reka/internal/config/compile"
	"github.com/MimoProxy/reka/internal/mitm/ca"
	"github.com/MimoProxy/reka/internal/testnet"
	"golang.org/x/net/proxy"
)

// Each request on a kept-alive connection is routed by its own URL and user
// agent, and a request no URL rule matches falls through to later rules.
func TestPlainHTTPRequestRulesKeepAlive(t *testing.T) {
	var mu sync.Mutex
	var paths []string
	origin := scriptWireUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.RequestURI())
		mu.Unlock()
		io.WriteString(w, "origin")
	}, false)
	target := origin.Listener.Addr().(*net.TCPAddr).AddrPort()
	routes := make(chan RouteObservation, 32)
	engine := NewEngine(EngineOptions{ObserveRoute: func(observation RouteObservation) { routes <- observation }})
	t.Cleanup(engine.Close)
	profile := `schema-version: 1
outbounds: [{id: second, type: direct}]
rules:
  - {match: {domain: never.test}, outbound: direct}
  - {match: {and: [{url-regex: '^http://127\.0\.0\.1:[0-9]+/d\?'}, {user-agent: 'Example*'}]}, outbound: direct}
  - {match: {url-regex: '^http://127\.0\.0\.1:[0-9]+/d\?'}, outbound: reject}
  - {match: {user-agent: 'Allowed*'}, outbound: second}
  - {match: {all: true}, outbound: reject}
`
	listener := testnet.RetryAddr(t, func(addr netip.AddrPort) error {
		local := fmt.Appendf(nil, "listeners: [{id: proxy, type: mixed, listen: %q}]", addr)
		eff, diagnostics := compile.Compile([]byte(profile), local, compile.Options{})
		if diagnostics.HasErrors() {
			t.Fatal(diagnostics)
		}
		prepared, err := engine.Prepare(eff)
		if err != nil {
			return err
		}
		_, err = engine.Activate(prepared, 1)
		return err
	})
	dialer, err := proxy.SOCKS5("tcp", listener.String(), nil, &net.Dialer{Timeout: 3 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	client, err := dialer.(proxy.ContextDialer).DialContext(t.Context(), "tcp", target.String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(10 * time.Second))
	reader := bufio.NewReader(client)
	cases := []struct {
		path, agent, outbound string
		status                int
	}{
		{"/d?dn=example.org", "Example/1.0", "direct", http.StatusOK},
		{"/d?dn=example.org", "Other/1.0", "reject", http.StatusNotFound},
		{"/index.html", "Other/1.0", "reject", http.StatusNotFound},
		{"/index.html", "Allowed/2.0", "second", http.StatusOK},
		{"/d?dn=example.net", "Example/2.0", "direct", http.StatusOK},
	}
	for i, tt := range cases {
		req, err := http.NewRequest(http.MethodGet, "http://"+target.String()+tt.path, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("User-Agent", tt.agent)
		if err := req.Write(client); err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			// The connection's own route rejects it; its requests are
			// still routed one by one.
			if route := <-routes; route.Decision.Outbound != "reject" || !route.Decision.HTTPPending {
				t.Fatalf("connection route = %+v", route.Decision)
			}
		}
		res, err := http.ReadResponse(reader, req)
		if err != nil {
			t.Fatalf("%s with %s: %v", tt.path, tt.agent, err)
		}
		data, err := io.ReadAll(res.Body)
		res.Body.Close()
		if err != nil || res.StatusCode != tt.status || tt.status == http.StatusOK && string(data) != "origin" {
			t.Fatalf("%s with %s = %d %q, %v", tt.path, tt.agent, res.StatusCode, data, err)
		}
		select {
		case route := <-routes:
			if route.Decision.Outbound != tt.outbound || route.Decision.HTTPPending {
				t.Fatalf("%s with %s routed to %+v", tt.path, tt.agent, route.Decision)
			}
		case <-time.After(time.Second):
			t.Fatalf("%s with %s was not routed", tt.path, tt.agent)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if want := []string{"/d?dn=example.org", "/index.html", "/d?dn=example.net"}; fmt.Sprint(paths) != fmt.Sprint(want) {
		t.Fatalf("origin requests = %q, want %q", paths, want)
	}
	if status := engine.MITMStatus(); status.PlainHTTPConnections != 1 || status.PlainHTTPRequests != uint64(len(cases)) {
		t.Fatalf("HTTP engine status = %+v", status)
	}
}

// Rules see decrypted HTTPS requests. A connection routed before any request
// rule keeps its route for every request.
func TestMITMRequestRules(t *testing.T) {
	upstream := mitmWireOrigin(t, mitmWireHost, "original")
	mitmCA := mitmWireAuthority(t, "Request rule test CA")
	store := mitmWireStore(t)
	if err := ca.Save(store, mitmCA); err != nil {
		t.Fatal(err)
	}
	roots := mitmWireRoots(t, mitmCA)
	routes := make(chan RouteObservation, 32)
	engine := NewEngine(EngineOptions{ObserveRoute: func(observation RouteObservation) { routes <- observation }})
	t.Cleanup(engine.Close)
	profile := `schema-version: 1
sniff: {enabled: true, protocols: [tls]}
mitm: {hostnames: ['` + mitmWireHost + `:0'], h2: false, skip-server-cert-verify: true}
outbounds: [{id: second, type: direct}]
rules:
  - {match: {url-regex: '^https://origin\.test:[0-9]+/ads/'}, outbound: reject}
  - {match: {or: [{url-regex: '/alternate$'}, {user-agent: 'Second*'}]}, outbound: second}
  - {match: {all: true}, outbound: direct}
`
	listen := testnet.RetryAddr(t, func(listen netip.AddrPort) error {
		return mitmWireApply(t, engine, store, listen, profile, true, 1)
	})
	client, err := mitmWireConnect(t, listen, upstream.address, roots)
	if err != nil {
		t.Fatal(err)
	}
	if route := <-routes; route.Decision.Outbound != "direct" || !route.Decision.HTTPPending {
		t.Fatalf("connection route = %+v", route.Decision)
	}
	for _, tt := range []struct {
		path, outbound string
		status         int
	}{
		{"/ads/banner", "reject", http.StatusNotFound},
		{"/alternate", "second", http.StatusOK},
		{"/index.html", "direct", http.StatusOK},
	} {
		client.check(t, tt.path, tt.status, map[bool]string{true: "original"}[tt.status == http.StatusOK])
		select {
		case route := <-routes:
			if route.Decision.Outbound != tt.outbound || route.Domain != mitmWireHost {
				t.Fatalf("%s routed to %+v for %q", tt.path, route.Decision, route.Domain)
			}
		case <-time.After(time.Second):
			t.Fatalf("%s was not routed", tt.path)
		}
	}
	if status := engine.MITMStatus(); status.Connections != 1 || status.Requests != 3 {
		t.Fatalf("MITM status = %+v", status)
	}
}

// Connections decided before any request rule are not routed per request,
// and admission to the HTTP engine stays as it was.
func TestRequestRulesAdmission(t *testing.T) {
	engine := NewEngine(EngineOptions{})
	t.Cleanup(engine.Close)
	activatePlainHTTPConfig(t, engine, `schema-version: 1
rules:
  - {match: {domain: early.test}, outbound: direct}
  - {match: {url-regex: '^http://late[.]test/'}, outbound: reject}
`, "", compile.Options{}, 1)
	for _, tt := range []struct {
		domain   string
		port     uint16
		admitted bool
	}{
		{"early.test", 80, false},
		{"late.test", 80, true},
		{"late.test", 8080, true},
	} {
		md := sagernet.Metadata{Network: "tcp", Protocol: "http", Destination: sagernet.Destination{Domain: tt.domain, Port: tt.port}}
		route := engine.route(t.Context(), md)
		if (route.MITM != nil) != tt.admitted || tt.admitted && (route.MITM.RouteRequest == nil || route.MITM.Reroute == nil) {
			t.Fatalf("%s:%d route = %+v", tt.domain, tt.port, route.MITM)
		}
		if tt.admitted {
			// A rejected request has no outbound.
			if rt, changed := route.MITM.RouteRequest(t.Context(), sagernet.HTTPRequestInfo{URL: "http://late.test/x"}); !changed || rt.Outbound != nil {
				t.Fatalf("request route = %+v, changed %v", rt, changed)
			}
			if _, changed := route.MITM.RouteRequest(t.Context(), sagernet.HTTPRequestInfo{URL: "http://other.test/"}); changed {
				t.Fatal("unmatched request changed route")
			}
		}
		if route.Release != nil {
			route.Release()
		}
	}
	_, g := engine.current()
	if !g.maySniffPlainHTTP("", 80) || g.maySniffPlainHTTP("", 8080) {
		t.Fatal("request rules should extend HTTP sniffing to port 80 only")
	}
}
