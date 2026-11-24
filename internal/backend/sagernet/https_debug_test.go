package sagernet

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MimoProxy/reka/internal/api"
	"github.com/MimoProxy/reka/internal/history"
)

func TestDebugCertificatesUseSessionExpiry(t *testing.T) {
	expires := time.Now().UTC().Truncate(time.Second).Add(time.Minute)
	publicCA, certificates, err := newDebugCertificates([]string{"ORIGIN.test.", "origin.test:444"}, expires)
	if err != nil {
		t.Fatal(err)
	}
	block, rest := pem.Decode([]byte(publicCA))
	if block == nil || block.Type != "CERTIFICATE" || len(rest) != 0 {
		t.Fatal("expected a single public CA certificate")
	}
	root, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if root.Subject.CommonName != "Mimo Reka HTTPS Debug" || !root.NotAfter.Equal(expires) {
		t.Fatal("unexpected debug CA subject or expiry")
	}
	pool := x509.NewCertPool()
	pool.AddCert(root)
	first := certificates[debugAuthority{host: "origin.test", port: "443"}].Leaf
	second := certificates[debugAuthority{host: "origin.test", port: "444"}].Leaf
	if first == nil || second == nil || first.SerialNumber.Cmp(second.SerialNumber) == 0 {
		t.Fatal("expected a distinct leaf per target")
	}
	for _, leaf := range []*x509.Certificate{first, second} {
		if !leaf.NotAfter.Equal(expires) {
			t.Fatal("debug leaf does not expire with the session")
		}
		if _, err := leaf.Verify(x509.VerifyOptions{DNSName: "origin.test", Roots: pool}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestHTTPSDebugAuthorizedCaptureAndNativeRoute(t *testing.T) {
	const responseText = "HTTPS fixture response"
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		if r.Header.Get("Authorization") != "Bearer origin-only-token" || r.Header.Get("Proxy-Authorization") != "" {
			http.Error(w, "incorrect credential forwarding", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Set-Cookie", "secret=origin-cookie")
		w.WriteHeader(http.StatusAccepted)
		_, _ = io.WriteString(w, responseText)
	}))
	defer origin.Close()
	_, port, _ := net.SplitHostPort(origin.Listener.Addr().String())
	host := "origin.test"
	target := net.JoinHostPort(host, port)
	root, certs, err := newDebugCertificates([]string{target}, time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	origin.TLS = &tls.Config{Certificates: []tls.Certificate{certs[debugAuthority{host, port}]}}
	origin.EnableHTTP2 = true
	origin.StartTLS()
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(root)) {
		t.Fatal("fixture CA is invalid")
	}

	records := history.New()
	scope := history.Scope{ProfileID: "debug-profile", Generation: 1, Revision: 1}
	b := New(Options{History: records, HistoryScope: func() history.Scope { return scope }, Logger: testLogger(t)})
	defer b.Close()
	direct, err := b.NewOutbound("direct", DirectSpec{})
	if err != nil {
		t.Fatal(err)
	}
	defer direct.Close()
	var forwards atomic.Int32
	b.SetRoute(func(ctx context.Context, md Metadata) Route {
		// Only this request can dial. The host is deliberately absent from the
		// machine resolver, so a bypass could never reach the fixture.
		if md.Inbound != debugInbound || md.Destination.String() != target {
			return Route{}
		}
		forwards.Add(1)
		route := Fixed(direct)(ctx, md)
		route.Scope = scope
		route.Lookup = func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
		}
		return route
	})

	status, err := b.startHTTPSDebug(api.HTTPSDebugRequest{Targets: []string{target}, CaptureBody: true}, roots)
	if err != nil || !status.Running || !strings.HasPrefix(status.Address, "127.0.0.1:") ||
		strings.Contains(status.Certificate, "PRIVATE KEY") {
		t.Fatal("invalid debug endpoint", err)
	}
	clientRoots := x509.NewCertPool()
	if !clientRoots.AppendCertsFromPEM([]byte(status.Certificate)) {
		t.Fatal("debug CA is invalid")
	}
	proxyURL := &url.URL{Scheme: "http", Host: status.Address}
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL), ForceAttemptHTTP2: true,
		TLSClientConfig: &tls.Config{RootCAs: clientRoots}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	if resp, err := client.Get("https://" + target); err == nil {
		resp.Body.Close()
		t.Fatal("proxy accepted a client without the session password")
	}

	proxyURL.User = url.UserPassword(status.Username, status.Password)
	if resp, err := client.Get("https://outside.test/"); err == nil {
		resp.Body.Close()
		t.Fatal("proxy accepted an unauthorized domain")
	}
	body := strings.Repeat("a", 9<<10)
	url := "https://" + target + "/items?token=private-query"
	req, _ := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer origin-only-token")
	req.Header.Set("Content-Type", "text/plain")
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(res.Body)
	res.Body.Close()
	if err != nil || res.StatusCode != http.StatusAccepted || res.ProtoMajor != 2 || string(got) != responseText {
		t.Fatal(res.StatusCode, res.Proto, string(got), err)
	}

	page, err := records.List(history.Requests, scope.ProfileID, history.ListOptions{})
	if err != nil || len(page.Rows) != 1 {
		t.Fatal(page, err)
	}
	var record requestRecord
	if err := json.Unmarshal(page.Rows[0].Data, &record); err != nil {
		t.Fatal(err)
	}
	if record.StatusCode != http.StatusAccepted || record.ConnectionID == 0 || record.TLSMS == nil ||
		record.TTFBMS == nil || record.DialMS == nil || record.DNSMS == nil || record.Path != "/items" ||
		record.HTTPVersion != "HTTP/2.0" || record.UpstreamHTTP != "HTTP/2.0" || record.RequestBytes != int64(len(body)) {
		t.Fatalf("unexpected summary %+v", record)
	}
	raw, ok := records.Detail(history.Requests, scope.ProfileID, page.Rows[0].Cursor)
	var detail requestDetail
	if !ok || json.Unmarshal(raw, &detail) != nil || detail.Request.Body == nil || detail.Response.Body == nil ||
		!detail.Request.Body.Truncated || len(detail.Request.Body.Data) != 8<<10 ||
		detail.Request.Body.Size != int64(len(body)) || detail.Response.Body.Data != responseText ||
		strings.Contains(string(raw), "origin-cookie") || strings.Contains(string(raw), "origin-only-token") {
		t.Fatal("invalid captured detail")
	}
	if _, ok = records.Detail(history.Requests, "other-profile", page.Rows[0].Cursor); ok {
		t.Fatal("cross-profile detail lookup")
	}

	req, _ = http.NewRequest(http.MethodGet, url, nil)
	req.Host = "outside.test"
	res, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusMisdirectedRequest {
		t.Fatal("authorized tunnel accepted a different authority", res.Status)
	}

	http1 := &http.Transport{Proxy: http.ProxyURL(proxyURL), TLSClientConfig: &tls.Config{RootCAs: clientRoots}}
	defer http1.CloseIdleConnections()
	legacy := &http.Client{Transport: http1, Timeout: 5 * time.Second}
	req, _ = http.NewRequest(http.MethodGet, url, nil)
	req.Header.Set("Authorization", "Bearer origin-only-token")
	res, err = legacy.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	got, err = io.ReadAll(res.Body)
	res.Body.Close()
	if err != nil || res.ProtoMajor != 1 || res.StatusCode != http.StatusAccepted || string(got) != responseText {
		t.Fatal(res.Proto, res.Status, string(got), err)
	}

	b.SetRoute(Fixed(nil))
	res, err = client.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusBadGateway || forwards.Load() != 2 {
		t.Fatal("a subsequent request bypassed the active native rule", res.Status, forwards.Load())
	}
	b.StopHTTPSDebug()
	if b.HTTPSDebugStatus().Running {
		t.Fatal("debug session did not stop")
	}
	if c, err := net.DialTimeout("tcp", status.Address, time.Second); err == nil {
		c.Close()
		t.Fatal("debug listener remained open")
	}
}

func TestDebugHTTPRequiresOptInAndAuthorizedAuthority(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Proxy-Authorization") != "" {
			t.Error("received proxy credentials")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer origin.Close()
	_, port, _ := net.SplitHostPort(origin.Listener.Addr().String())
	target := net.JoinHostPort("origin.test", port)
	records := history.New()
	b := New(Options{History: records, Logger: testLogger(t)})
	defer b.Close()
	direct, err := b.NewOutbound("direct", DirectSpec{})
	if err != nil {
		t.Fatal(err)
	}
	defer direct.Close()
	b.SetRoute(func(ctx context.Context, md Metadata) Route {
		if md.Inbound != debugInbound || md.Destination.String() != target {
			return Route{}
		}
		route := Fixed(direct)(ctx, md)
		route.Lookup = func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
		}
		return route
	})

	check := func(proxyURL *url.URL, host string, expected int) {
		t.Helper()
		transport := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
		defer transport.CloseIdleConnections()
		client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
		response, err := client.Get("http://" + host + "/fixture")
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != expected {
			t.Fatalf("status %d, want %d", response.StatusCode, expected)
		}
	}
	legacy, err := b.StartHTTPSDebug(api.HTTPSDebugRequest{Targets: []string{target}})
	if err != nil {
		t.Fatal(err)
	}
	check(&url.URL{Scheme: "http", Host: legacy.Address, User: url.UserPassword(legacy.Username, legacy.Password)}, target, http.StatusMethodNotAllowed)
	b.StopHTTPSDebug()

	status, err := b.StartHTTPSDebug(api.HTTPSDebugRequest{Targets: []string{target}, AllowHTTP: true, MaxClients: 4})
	if err != nil {
		t.Fatal(err)
	}
	proxyURL := &url.URL{Scheme: "http", Host: status.Address}
	check(proxyURL, target, http.StatusProxyAuthRequired)
	proxyURL.User = url.UserPassword(status.Username, status.Password)
	check(proxyURL, "outside.test:"+port, http.StatusForbidden)
	check(proxyURL, target, http.StatusNoContent)
	page, err := records.List(history.Requests, "", history.ListOptions{})
	if err != nil || len(page.Rows) != 1 {
		t.Fatalf("want one recorded request: %v (%v)", len(page.Rows), err)
	}
	var trace requestRecord
	if err := json.Unmarshal(page.Rows[0].Data, &trace); err != nil || trace.Scheme != "http" || trace.ConnectionID == 0 {
		t.Fatalf("unexpected HTTP trace: %+v (%v)", trace, err)
	}
}
