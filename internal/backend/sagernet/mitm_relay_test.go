package sagernet

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MimoProxy/reka/internal/history"
	"github.com/MimoProxy/reka/internal/httprewrite"
	"github.com/MimoProxy/reka/internal/mitm/ca"
	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
)

// The upstream and client are both in-memory streams. The router still sniffs
// and replays the ClientHello, and the relay performs both TLS handshakes.
func TestMITMRelayHTTPRewrites(t *testing.T) {
	const (
		host        = "origin.test"
		target      = "192.0.2.1:443"
		limit       = 64
		matchPrefix = "^https://origin[.]test/"
	)
	large := strings.Repeat("original payload ", 9)
	ref := func(s string) *string { return &s }
	spec := httprewrite.Spec{
		HTTPRewrites: []httprewrite.HTTPRewrite{
			{ID: "reject", Match: matchPrefix + "reject$", Action: "reject"},
			{ID: "close", Match: matchPrefix + "close$", Action: "reject", Response: ref("close")},
			{ID: "redirect", Match: matchPrefix + "redirect$", Action: "302", Target: ref("https://redirect.test/new")},
		},
		MapLocal: []httprewrite.MapLocal{
			{ID: "local", Match: matchPrefix + "local$", DataType: ref("text"), Data: ref("local content")},
			{ID: "missing-resource", Match: matchPrefix + "missing$", Hash: ref("missing")},
		},
		HeaderRewrites: []httprewrite.HeaderRewrite{
			{ID: "header", Match: matchPrefix + "rewrite", Op: "replace", Name: "X-Edited", Value: ref("updated")},
			{ID: "response-header", Match: matchPrefix + "large", Phase: ref("response"), Op: "add", Name: "X-Large", Value: ref("unchanged body")},
		},
		BodyRewrites: []httprewrite.BodyRewrite{
			{ID: "jq", Match: matchPrefix + "rewrite", Phase: "response", JQ: ref(`.status = "rewritten"`)},
			{ID: "request-body", Match: matchPrefix + "large", Phase: "request", Replace: []httprewrite.Replacement{
				{Pattern: ref("original"), Value: ref("modified")},
			}},
			{ID: "response-body", Match: matchPrefix + "large", Phase: "response", Replace: []httprewrite.Replacement{
				{Pattern: ref("original"), Value: ref("modified")},
			}},
		},
	}
	set, err := httprewrite.New(spec, httprewrite.Options{
		MaxBodySize: limit,
		ReadResource: func(string) ([]byte, error) {
			return nil, errors.New("test resource unavailable")
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	issuer, roots := mitmRelayTestIssuer(t, "Relay test CA")
	originIssuer, _ := mitmRelayTestIssuer(t, "Origin test CA")
	originCert, err := originIssuer.GetCertificate(&tls.ClientHelloInfo{ServerName: host})
	if err != nil {
		t.Fatal(err)
	}
	var compressed bytes.Buffer
	zip := gzip.NewWriter(&compressed)
	if _, err := io.WriteString(zip, `{"status":"original"}`); err != nil {
		t.Fatal(err)
	}
	if err := zip.Close(); err != nil {
		t.Fatal(err)
	}

	records := history.New()
	backend := New(Options{History: records, Logger: testLogger(t)})
	t.Cleanup(func() { _ = backend.Close() })
	client, inbound := connectionEventPipe(t)
	clientWire := &mitmTestWire{Conn: client}
	remote, upstream := connectionEventPipe(t)
	trackedRemote := &mitmTestCloseConn{Conn: remote}
	for _, conn := range []net.Conn{client, remote, upstream} {
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	}

	var dialCount, originRequests, releases atomic.Int32
	out := &Outbound{tag: "origin", typ: "direct", out: mitmRelayTestOutbound{
		dial: func(_ context.Context, network string, dst M.Socksaddr) (net.Conn, error) {
			if network != "tcp" || dst.String() != target {
				return nil, errors.New("unexpected upstream destination")
			}
			if dialCount.Add(1) != 1 {
				return nil, errors.New("did not reuse upstream TLS connection")
			}
			return trackedRemote, nil
		},
	}}
	originDone := make(chan error, 1)
	go func() {
		server := tls.Server(upstream, &tls.Config{Certificates: []tls.Certificate{*originCert}, NextProtos: []string{"h2", "http/1.1"}})
		defer upstream.Close()
		if err := server.Handshake(); err != nil {
			originDone <- err
			return
		}
		state := server.ConnectionState()
		if state.ServerName != host || state.NegotiatedProtocol != "http/1.1" {
			t.Errorf("upstream TLS state = server %q, ALPN %q", state.ServerName, state.NegotiatedProtocol)
		}
		reader := bufio.NewReader(server)
		for {
			req, err := http.ReadRequest(reader)
			if err != nil {
				originDone <- err
				return
			}
			originRequests.Add(1)
			body, err := io.ReadAll(req.Body)
			req.Body.Close()
			if err != nil {
				originDone <- err
				return
			}
			reply := &http.Response{StatusCode: http.StatusOK, ProtoMajor: 1, ProtoMinor: 1, Header: make(http.Header)}
			switch req.URL.Path {
			case "/rewrite":
				if req.Host != host || req.URL.RawQuery != "kind=test" || req.Header.Get("X-Edited") != "updated" ||
					req.Header.Get("X-Client-Hop") != "" || req.Header.Get("HTTP2-Settings") != "" ||
					req.Header.Get("Accept-Encoding") != "br, gzip, deflate" {
					t.Errorf("unexpected upstream request: %s %s, headers %v", req.Host, req.URL, req.Header)
				}
				reply.Header.Set("Content-Encoding", "gzip")
				reply.Header.Set("Connection", "X-Origin-Hop")
				reply.Header.Set("X-Origin-Hop", "ignored")
				reply.Header.Set("HTTP2-Settings", "ignored")
				reply.ContentLength = int64(compressed.Len())
				reply.Body = io.NopCloser(bytes.NewReader(compressed.Bytes()))
			case "/large-known", "/large-chunked":
				if string(body) != large {
					t.Errorf("upstream body = %q, want %q", body, large)
				}
				reply.ContentLength = int64(len(body))
				if req.URL.Path == "/large-chunked" {
					reply.ContentLength = -1
					reply.TransferEncoding = []string{"chunked"}
				}
				reply.Body = io.NopCloser(bytes.NewReader(body))
			default:
				originDone <- errors.New("local rewrite reached the upstream")
				return
			}
			if err := reply.Write(server); err != nil {
				originDone <- err
				return
			}
		}
	}()
	backend.SetPrepareFlow(func(context.Context, Metadata) PreparedFlow {
		return PreparedFlow{
			Sniff: SniffOptions{Enabled: true, Protocols: []string{"tls"}},
			Route: func(_ context.Context, md Metadata) Route {
				if md.SniffedDomain != host || md.Protocol != "tls" {
					t.Errorf("TLS sniff = %q/%q", md.SniffedDomain, md.Protocol)
				}
				return Route{
					Owner: ProcessInfo{Path: "/test/relay"}, Outbound: out,
					Release: func() {
						if dialCount.Load() != 0 && !trackedRemote.closed.Load() {
							t.Error("released the route before closing its upstream socket")
						}
						releases.Add(1)
					},
					MITM: &MITMRoute{Host: host, Issuer: issuer, Rewrite: set, MaxBodySize: limit, SkipServerCertVerify: true},
				}
			},
		}
	})
	done := make(chan struct{})
	go backend.router.RouteConnectionEx(t.Context(), inbound, adapter.InboundContext{
		Inbound: "test", InboundType: "mixed", Source: M.ParseSocksaddr("192.0.2.3:4567"), Destination: M.ParseSocksaddr(target),
	}, func(error) { close(done) })

	conn := tls.Client(clientWire, &tls.Config{ServerName: host, RootCAs: roots, NextProtos: []string{"h2", "http/1.1"}})
	if err := conn.Handshake(); err != nil {
		t.Fatal(err)
	}
	state := conn.ConnectionState()
	if state.NegotiatedProtocol != "http/1.1" || len(state.VerifiedChains) == 0 ||
		bytes.Equal(state.PeerCertificates[0].Raw, originCert.Certificate[0]) {
		t.Fatalf("unexpected client TLS state: ALPN %q, verified chains %d", state.NegotiatedProtocol, len(state.VerifiedChains))
	}

	reader := bufio.NewReader(conn)
	request := func(method, path string, body io.Reader, chunked bool) *http.Request {
		t.Helper()
		req, err := http.NewRequest(method, "https://"+host+path, body)
		if err != nil {
			t.Fatal(err)
		}
		if chunked {
			req.ContentLength = -1
			req.TransferEncoding = []string{"chunked"}
		}
		req.Header.Set("Accept-Encoding", "br, gzip, deflate")
		req.Header.Set("X-Edited", "original")
		req.Header.Set("Connection", "X-Client-Hop")
		req.Header.Set("X-Client-Hop", "ignored")
		req.Header.Set("HTTP2-Settings", "ignored")
		if err := req.Write(conn); err != nil {
			t.Fatal(err)
		}
		return req
	}
	checkResponse := func(req *http.Request, status int, want string) http.Header {
		t.Helper()
		reply, err := http.ReadResponse(reader, req)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(reply.Body)
		reply.Body.Close()
		if err != nil || reply.StatusCode != status || string(body) != want {
			t.Fatalf("%s: response status %d, body %q, error %v", req.URL.Path, reply.StatusCode, body, err)
		}
		return reply.Header
	}
	checkResponse(request("GET", "/reject", nil, false), http.StatusNotFound, "")
	redirect := checkResponse(request("GET", "/redirect", nil, false), http.StatusFound, "")
	if got := redirect.Get("Location"); got != "https://redirect.test/new" {
		t.Fatalf("Location = %q", got)
	}
	checkResponse(request("GET", "/local", nil, false), http.StatusOK, "local content")
	checkResponse(request("GET", "/missing", nil, false), http.StatusBadGateway, "Could not read local response resource\n")
	if dialCount.Load() != 0 {
		t.Fatal("local responses opened an upstream connection")
	}
	for range 2 {
		header := checkResponse(request("GET", "/rewrite?kind=test", nil, false), http.StatusOK, `{"status":"rewritten"}`)
		if header.Get("Content-Encoding") != "" || header.Get("X-Origin-Hop") != "" || header.Get("HTTP2-Settings") != "" {
			t.Fatalf("rewritten response headers = %v", header)
		}
	}
	for _, chunked := range []bool{false, true} {
		path := "/large-known"
		if chunked {
			path = "/large-chunked"
		}
		header := checkResponse(request("POST", path, strings.NewReader(large), chunked), http.StatusOK, large)
		if header.Get("X-Large") != "unchanged body" {
			t.Fatalf("response header rewrite skipped on %s", path)
		}
	}

	const served = 8
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		up, down := backend.Traffic()
		if records.Count(history.Requests) == served && int64(up) == clientWire.written && int64(down) == clientWire.read {
			break
		}
		time.Sleep(time.Millisecond)
	}
	list := backend.Connections()
	if len(list) != 1 {
		t.Fatalf("active connections = %v", list)
	}
	live := list[0]
	rules := slices.Clone(live.MITMMatchedIDs)
	slices.Sort(rules)
	want := []string{"header", "jq", "local", "missing-resource", "redirect", "reject", "response-header"}
	if !live.MITM || live.MITMRequests != served || live.MITMBodyPassthroughs != 4 || !slices.Equal(rules, want) {
		t.Fatalf("MITM connection diagnostics = %+v", live)
	}
	if live.Upload != clientWire.written || live.Download != clientWire.read {
		t.Fatalf("wire counts = %d/%d, connection counts = %d/%d", clientWire.written, clientWire.read, live.Upload, live.Download)
	}
	up, down := backend.Traffic()
	procs, _ := backend.ProcessTraffic(0, 10)
	if up != uint64(live.Upload) || down != uint64(live.Download) || len(procs) != 1 ||
		procs[0].Path != "/test/relay" || procs[0].Upload != up || procs[0].Download != down {
		t.Fatalf("global traffic %d/%d, process traffic %+v", up, down, procs)
	}
	page, err := records.List(history.Requests, "", history.ListOptions{})
	if err != nil || len(page.Rows) != served {
		t.Fatalf("request history: %d rows, %v", len(page.Rows), err)
	}
	reused, passthrough := 0, 0
	for _, row := range page.Rows {
		var record requestRecord
		if err := json.Unmarshal(row.Data, &record); err != nil || record.ConnectionID != live.ID || !record.MITM {
			t.Fatalf("request history row = %s, error %v", row.Data, err)
		}
		if (record.Path == "/missing") != record.ResourceError {
			t.Fatalf("resource error diagnostic = %s", row.Data)
		}
		if record.Reused != nil && *record.Reused {
			reused++
		}
		if record.Path == "/large-known" || record.Path == "/large-chunked" {
			if len(record.MatchedIDs) != 1 || record.MatchedIDs[0] != "response-header" {
				t.Fatalf("over-limit request history = %s", row.Data)
			}
			passthrough += int(record.BodyPassthroughs)
		}
	}
	if reused != 3 || passthrough != 4 || originRequests.Load() != 4 || dialCount.Load() != 1 {
		t.Fatalf("got %d reused requests, %d body passthroughs, %d origin requests, %d upstream dials", reused, passthrough, originRequests.Load(), dialCount.Load())
	}

	if _, err := http.ReadResponse(reader, request("GET", "/close", nil, false)); !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("reject close returned %v, want EOF", err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("client connection did not finish")
	}
	select {
	case err := <-originDone:
		if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("upstream close = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("idle upstream connection did not close")
	}
	trace := readClosedConnectionEventTrace(t, records, live.ID)
	if !trace.MITM || trace.MITMRequests != served+1 || !slices.Contains(trace.MITMMatchedIDs, "close") ||
		trace.MITMBodyPassthroughs != 4 || releases.Load() != 1 {
		t.Fatalf("closed MITM trace = %+v, release calls = %d", trace, releases.Load())
	}
}

type mitmTestCloseConn struct {
	net.Conn
	closed atomic.Bool
}

func (c *mitmTestCloseConn) Close() error {
	err := c.Conn.Close()
	c.closed.Store(true)
	return err
}

type mitmRelayTestOutbound struct {
	adapter.Outbound
	dial func(context.Context, string, M.Socksaddr) (net.Conn, error)
}

func (o mitmRelayTestOutbound) DialContext(ctx context.Context, network string, dst M.Socksaddr) (net.Conn, error) {
	return o.dial(ctx, network, dst)
}

func mitmRelayTestIssuer(t *testing.T, name string) (*ca.Issuer, *x509.CertPool) {
	t.Helper()
	authority, err := ca.Generate(ca.GenerateOptions{CommonName: name})
	if err != nil {
		t.Fatal(err)
	}
	issuer := ca.NewIssuer(authority, ca.IssuerOptions{})
	t.Cleanup(issuer.Close)
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(authority.CertificatePEM()) {
		t.Fatal("could not load test root")
	}
	return issuer, roots
}

type mitmTestWire struct {
	net.Conn
	read, written int64
}

func (c *mitmTestWire) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.read += int64(n)
	return n, err
}

func (c *mitmTestWire) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.written += int64(n)
	return n, err
}

func TestMITMRelayReportsCertificateRejection(t *testing.T) {
	const host = "pinning.test"
	issuer, _ := mitmRelayTestIssuer(t, "Pinning test CA")
	type failure struct{ host, reason string }
	failures := make(chan failure, 1)
	client := mitmLocalTestConnection(t, &MITMRoute{
		Host: host, Issuer: issuer,
		OnPinFailure: func(host, reason string) { failures <- failure{host, reason} },
	}, 0)
	conn := tls.Client(client, &tls.Config{ServerName: host, RootCAs: x509.NewCertPool()})
	var unknownCA x509.UnknownAuthorityError
	if err := conn.Handshake(); !errors.As(err, &unknownCA) {
		t.Fatalf("untrusted handshake = %v", err)
	}
	select {
	case got := <-failures:
		if got.host != host || (got.reason != "bad_certificate" && got.reason != "unknown_ca") {
			t.Fatalf("unexpected certificate rejection callback: %+v", got)
		}
	case <-time.After(time.Second):
		t.Fatal("certificate rejection callback did not run")
	}
}

func TestMITMRelayDropUsesFallbackName(t *testing.T) {
	const (
		host = "fallback.test"
		idle = 50 * time.Millisecond
	)
	issuer, roots := mitmRelayTestIssuer(t, "Fallback test CA")
	drop := "drop"
	set, err := httprewrite.New(httprewrite.Spec{HTTPRewrites: []httprewrite.HTTPRewrite{
		{ID: "drop", Match: "^https://fallback[.]test/drop$", Action: "reject", Response: &drop},
	}}, httprewrite.Options{})
	if err != nil {
		t.Fatal(err)
	}
	client := mitmLocalTestConnection(t, &MITMRoute{Host: host, Issuer: issuer, Rewrite: set}, idle)
	conn := tls.Client(client, &tls.Config{
		// Omit SNI while still verifying against the expected certificate name.
		InsecureSkipVerify: true,
		VerifyConnection: func(state tls.ConnectionState) error {
			_, err := state.PeerCertificates[0].Verify(x509.VerifyOptions{Roots: roots, DNSName: host})
			return err
		},
	})
	if err := conn.Handshake(); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if _, err := io.WriteString(conn, "GET /drop HTTP/1.1\r\nHost: "+host+"\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	var one [1]byte
	n, err := conn.Read(one[:])
	if n != 0 || !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) || time.Since(start) < idle {
		t.Fatalf("drop read %d bytes, error %v, elapsed %v", n, err, time.Since(start))
	}
}

func mitmLocalTestConnection(t *testing.T, route *MITMRoute, idle time.Duration) net.Conn {
	t.Helper()
	backend := New(Options{Logger: testLogger(t), HalfCloseTimeout: idle})
	t.Cleanup(func() { _ = backend.Close() })
	client, inbound := connectionEventPipe(t)
	_ = client.SetDeadline(time.Now().Add(3 * time.Second))
	out := &Outbound{tag: "origin", typ: "direct", out: mitmRelayTestOutbound{
		dial: func(context.Context, string, M.Socksaddr) (net.Conn, error) {
			t.Error("local handling triggered an upstream dial")
			return nil, errors.New("unexpected upstream dial")
		},
	}}
	backend.SetRoute(func(context.Context, Metadata) Route { return Route{Outbound: out, MITM: route} })
	done := make(chan struct{})
	go backend.router.RouteConnectionEx(t.Context(), inbound, adapter.InboundContext{
		Inbound: "test", InboundType: "mixed", Destination: M.ParseSocksaddr(route.Host + ":443"),
	}, func(error) { close(done) })
	t.Cleanup(func() {
		_ = client.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("local client connection did not finish")
		}
	})
	return client
}
