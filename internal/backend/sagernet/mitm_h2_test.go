package sagernet

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MimoProxy/reka/internal/history"
	"github.com/MimoProxy/reka/internal/httprewrite"
	"github.com/MimoProxy/reka/internal/script"
	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
)

const mitmH2TestHost = "mitm-h2.test"
const mitmH2TestTimeout = 5 * time.Second

type mitmH2Fixture struct {
	client  *http.ClientConn
	backend *Backend
	records *history.Store
	dials   atomic.Int32
	closed  atomic.Int32
	done    chan struct{}
}

type mitmH2OriginConn struct {
	net.Conn
	closed *atomic.Int32
}

func (c *mitmH2OriginConn) Close() error {
	err := c.Conn.Close()
	c.closed.Add(1)
	return err
}

func newMITMH2Origin(t *testing.T, h2 bool, handler http.HandlerFunc) mitmRelayTestOutbound {
	t.Helper()
	origin := httptest.NewTestServer(t, handler)
	origin.EnableHTTP2 = h2
	if h2 {
		origin.TLS = &tls.Config{NextProtos: []string{"h2", "http/1.1"}}
	}
	originProtocols := new(http.Protocols)
	originProtocols.SetHTTP1(true)
	originProtocols.SetHTTP2(h2)
	origin.Config.Protocols = originProtocols
	originTLS := origin.Client().Transport.(*http.Transport).DialTLSContext
	return mitmRelayTestOutbound{
		dial: func(ctx context.Context, network string, dst M.Socksaddr) (net.Conn, error) {
			conn, err := originTLS(ctx, network, dst.String())
			if err != nil {
				return nil, err
			}
			// Return the in-memory origin socket before TLS so the relay
			// still constructs the origin TLS client and negotiates ALPN.
			return conn.(interface{ NetConn() net.Conn }).NetConn(), nil
		},
	}
}

// Use a single in-memory client connection to the real MITM router.
func newMITMH2Fixture(t *testing.T, route *MITMRoute, clientH2, originH2 bool, handler http.HandlerFunc) *mitmH2Fixture {
	t.Helper()
	origin := newMITMH2Origin(t, originH2, handler)
	issuer, roots := mitmRelayTestIssuer(t, "HTTP/2 relay test CA")
	route.Host, route.Issuer, route.SkipServerCertVerify = mitmH2TestHost, issuer, true
	f := &mitmH2Fixture{records: history.New(), done: make(chan struct{})}
	f.backend = New(Options{History: f.records, Logger: testLogger(t)})
	t.Cleanup(func() { _ = f.backend.Close() })
	client, inbound := connectionEventPipe(t)
	t.Cleanup(func() {
		_ = client.Close()
		f.waitClosed(t)
	})
	out := &Outbound{tag: "origin", typ: "direct", out: mitmRelayTestOutbound{
		dial: func(ctx context.Context, network string, dst M.Socksaddr) (net.Conn, error) {
			conn, err := origin.DialContext(ctx, network, dst)
			if err != nil {
				return nil, err
			}
			f.dials.Add(1)
			return &mitmH2OriginConn{Conn: conn, closed: &f.closed}, nil
		},
	}}
	if route.Reroute == nil {
		route.Reroute = func(_ context.Context, dest Destination) Route {
			if dest.Domain != "alternate-origin.test" {
				t.Errorf("unexpected reroute destination %v", dest)
			}
			return Route{Outbound: out}
		}
	}
	f.backend.SetRoute(func(context.Context, Metadata) Route { return Route{Outbound: out, MITM: route} })
	go f.backend.router.RouteConnectionEx(t.Context(), inbound, adapter.InboundContext{
		Inbound: "test", InboundType: "mixed", Destination: M.ParseSocksaddr(mitmH2TestHost + ":443"),
	}, func(error) { close(f.done) })

	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	protocols.SetHTTP2(clientH2)
	transport := &http.Transport{
		Protocols: protocols,
		TLSClientConfig: &tls.Config{
			RootCAs: roots, NextProtos: []string{"http/1.1"},
		},
		DialContext: func(context.Context, string, string) (net.Conn, error) { return client, nil },
	}
	ctx, cancel := context.WithTimeout(t.Context(), mitmH2TestTimeout)
	defer cancel()
	var err error
	f.client, err = transport.NewClientConn(ctx, "https", mitmH2TestHost+":443")
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *mitmH2Fixture) waitClosed(t *testing.T) {
	t.Helper()
	select {
	case <-f.done:
	case <-time.After(mitmH2TestTimeout):
		t.Error("MITM client connection did not finish")
	}
	if f.dials.Load() != f.closed.Load() {
		t.Errorf("MITM closed %d of %d origin connections", f.closed.Load(), f.dials.Load())
	}
}

func (f *mitmH2Fixture) request(t *testing.T, method, path string, body io.Reader) *http.Request {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), mitmH2TestTimeout)
	t.Cleanup(cancel)
	req, err := http.NewRequestWithContext(ctx, method, "https://"+mitmH2TestHost+path, body)
	if err != nil {
		t.Fatal(err)
	}
	return req
}

// h2Request is a request the relay sends over HTTP/2 to an HTTP/2 origin:
// other requests use HTTP/1.1 upstream.
func (f *mitmH2Fixture) h2Request(t *testing.T, method, path string, body io.Reader) *http.Request {
	t.Helper()
	req := f.request(t, method, path, body)
	req.Header.Set("Content-Type", "application/grpc")
	return req
}

func (f *mitmH2Fixture) response(t *testing.T, req *http.Request) (*http.Response, string) {
	t.Helper()
	res, err := f.client.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	data, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	return res, string(data)
}

func (f *mitmH2Fixture) live(t *testing.T) ConnInfo {
	t.Helper()
	connections := f.backend.Connections()
	if len(connections) != 1 {
		t.Fatalf("active connections = %v", connections)
	}
	return connections[0]
}

func (f *mitmH2Fixture) requestHistory(t *testing.T, count int) []requestRecord {
	t.Helper()
	deadline := time.Now().Add(mitmH2TestTimeout)
	for f.records.Count(history.Requests) < count && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	page, err := f.records.List(history.Requests, "", history.ListOptions{Limit: count})
	if err != nil || len(page.Rows) != count {
		t.Fatalf("history returned %d request rows: %v", len(page.Rows), err)
	}
	rows := make([]requestRecord, len(page.Rows))
	for i, row := range page.Rows {
		if err := json.Unmarshal(row.Data, &rows[i]); err != nil {
			t.Fatal(err)
		}
	}
	return rows
}

func TestMITMHTTP2Protocols(t *testing.T) {
	for _, test := range []struct {
		name                         string
		enabled, clientH2, originH2  bool
		clientALPN, originALPN       string
		clientVersion, originVersion string
	}{
		{"both HTTP/2", true, true, true, "h2", "h2", "HTTP/2.0", "HTTP/2.0"},
		{"HTTP/1 origin", true, true, false, "h2", "http/1.1", "HTTP/2.0", "HTTP/1.1"},
		{"HTTP/1 client", true, false, true, "http/1.1", "h2", "HTTP/1.1", "HTTP/2.0"},
		{"HTTP/2 disabled", false, true, true, "http/1.1", "http/1.1", "HTTP/1.1", "HTTP/1.1"},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newMITMH2Fixture(t, &MITMRoute{H2: test.enabled}, test.clientH2, test.originH2, func(w http.ResponseWriter, r *http.Request) {
				if r.Proto != test.originVersion || r.TLS.NegotiatedProtocol != test.originALPN {
					t.Errorf("origin protocol = %s, ALPN = %q", r.Proto, r.TLS.NegotiatedProtocol)
				}
				body, err := io.ReadAll(r.Body)
				if err != nil || string(body) != "upload" {
					t.Errorf("upstream body = %q, error %v", body, err)
				}
				wantTE, wantTrailer := "", ""
				if test.enabled {
					wantTE = "trailers"
					wantTrailer = "client"
				}
				if got := r.Header.Get("TE"); got != wantTE {
					t.Errorf("upstream TE = %q, want %q", got, wantTE)
				}
				if got := r.Trailer.Get("X-Request-Trailer"); got != wantTrailer {
					t.Errorf("upstream trailer = %q, want %q", got, wantTrailer)
				}
				if got := r.Trailer.Get("Upgrade"); got != "" {
					t.Errorf("upstream Upgrade trailer = %q", got)
				}
				w.Header().Set("Content-Type", "text/plain")
				w.Header().Set("Trailer", "X-Upstream-Trailer")
				_, _ = io.WriteString(w, "origin")
				w.Header().Set("X-Upstream-Trailer", "forwarded")
				w.Header().Set(http.TrailerPrefix+"X-Late-Trailer", "late")
				w.Header().Set(http.TrailerPrefix+"Upgrade", "websocket")
			})
			for range 2 {
				req := f.request(t, http.MethodPost, "/", strings.NewReader("upload"))
				req.ContentLength = -1
				req.Trailer = http.Header{"X-Request-Trailer": {"client"}}
				req.Trailer.Set("Upgrade", "websocket")
				req.Header.Set("TE", "trailers")
				if !test.clientH2 {
					req.Header.Set("TE", "gzip, tRaIlErS")
				}
				res, body := f.response(t, req)
				if res.Proto != test.clientVersion || res.TLS.NegotiatedProtocol != test.clientALPN || res.StatusCode != http.StatusOK || body != "origin" {
					t.Fatalf("response protocol = %s, ALPN = %q, status = %d, body = %q", res.Proto, res.TLS.NegotiatedProtocol, res.StatusCode, body)
				}
				if test.enabled {
					if res.Trailer.Get("X-Upstream-Trailer") != "forwarded" || res.Trailer.Get("X-Late-Trailer") != "late" ||
						res.Trailer.Get("Upgrade") != "" {
						t.Fatalf("forwarded trailers = %v", res.Trailer)
					}
					if !test.clientH2 && !slices.Equal(res.TransferEncoding, []string{"chunked"}) {
						t.Fatalf("HTTP/1 response framing = %v", res.TransferEncoding)
					}
				}
			}
			rows := f.requestHistory(t, 2)
			live := f.live(t)
			if !live.MITM || live.MITMRequests != 2 || live.MITMClientProtocol != test.clientALPN ||
				!slices.Equal(live.MITMUpstreamProtocols, []string{test.originALPN}) {
				t.Fatalf("live MITM diagnostics = %+v", live.MITMConnectionInfo)
			}
			for _, row := range rows {
				if !row.MITM || row.ConnectionID != live.ID || row.HTTPVersion != test.clientVersion || row.UpstreamHTTP != test.originVersion {
					t.Fatalf("request history = %+v", row)
				}
			}
			if f.dials.Load() != 1 {
				t.Fatalf("origin dials = %d, want one reused connection", f.dials.Load())
			}
			_ = f.client.Close()
			f.waitClosed(t)
			trace := readClosedConnectionEventTrace(t, f.records, live.ID)
			if trace.MITMClientProtocol != test.clientALPN || !slices.Equal(trace.MITMUpstreamProtocols, []string{test.originALPN}) {
				t.Fatalf("closed MITM diagnostics = %+v", trace.MITMConnectionInfo)
			}
		})
	}
}

func TestMITMHTTP2UpstreamProtocolOrder(t *testing.T) {
	target := "https://alternate-origin.test/"
	rewrite, err := httprewrite.New(httprewrite.Spec{HTTPRewrites: []httprewrite.HTTPRewrite{
		{ID: "alternate", Match: "^https://mitm-h2[.]test/alternate$", Action: "header", Target: &target},
	}}, httprewrite.Options{})
	if err != nil {
		t.Fatal(err)
	}
	alternate := newMITMH2Origin(t, false, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, r.Proto)
	})
	f := newMITMH2Fixture(t, &MITMRoute{
		H2: true, Rewrite: rewrite,
		Reroute: func(_ context.Context, dest Destination) Route {
			if dest.Domain != "alternate-origin.test" {
				t.Errorf("unexpected reroute destination %v", dest)
			}
			return Route{Outbound: &Outbound{tag: "alternate", typ: "direct", out: alternate}}
		},
	}, true, true, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, r.Proto)
	})
	// Only gRPC uses HTTP/2 upstream, and only where the origin offers it.
	for _, test := range []struct {
		path           string
		grpc           bool
		originProtocol string
	}{
		{"/", false, "HTTP/1.1"},
		{"/", true, "HTTP/2.0"},
		{"/alternate", true, "HTTP/1.1"},
		{"/", false, "HTTP/1.1"},
		{"/alternate", false, "HTTP/1.1"},
	} {
		req := f.request(t, http.MethodGet, test.path, nil)
		if test.grpc {
			req = f.h2Request(t, http.MethodGet, test.path, nil)
		}
		res, body := f.response(t, req)
		if res.StatusCode != http.StatusOK || res.ProtoMajor != 2 || body != test.originProtocol {
			t.Fatalf("%s (gRPC %v): status %d, protocol %s, origin protocol %q", test.path, test.grpc, res.StatusCode, res.Proto, body)
		}
	}
	live := f.live(t)
	want := []string{"http/1.1", "h2"}
	if !slices.Equal(live.MITMUpstreamProtocols, want) {
		t.Fatalf("live upstream protocols = %v, want %v", live.MITMUpstreamProtocols, want)
	}
	_ = f.client.Close()
	f.waitClosed(t)
	if trace := readClosedConnectionEventTrace(t, f.records, live.ID); !slices.Equal(trace.MITMUpstreamProtocols, want) {
		t.Fatalf("closed upstream protocols = %v, want %v", trace.MITMUpstreamProtocols, want)
	}
}

func TestMITMHTTP2RejectsTunnels(t *testing.T) {
	f := newMITMH2Fixture(t, &MITMRoute{H2: true}, true, false, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/upgrade":
			w.Header().Set("Connection", "Upgrade")
			w.Header().Set("Upgrade", "websocket")
			w.WriteHeader(http.StatusSwitchingProtocols)
		case "/health":
			_, _ = io.WriteString(w, "healthy")
		default:
			t.Errorf("unexpected upstream request %s %s", r.Method, r.URL)
		}
	})
	res, _ := f.response(t, f.request(t, http.MethodConnect, "", nil))
	if res.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("CONNECT status = %d", res.StatusCode)
	}

	req := f.request(t, http.MethodConnect, "/websocket", nil)
	req.Header[":protocol"] = []string{"websocket"}
	res, err := f.client.RoundTrip(req)
	if err == nil {
		res.Body.Close()
		if res.StatusCode != http.StatusMethodNotAllowed {
			t.Fatalf("extended CONNECT status = %d", res.StatusCode)
		}
	} else if errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("extended CONNECT hung: %v", err)
	}
	if f.dials.Load() != 0 {
		t.Fatalf("CONNECT made %d origin dials", f.dials.Load())
	}
	res, _ = f.response(t, f.request(t, http.MethodGet, "/upgrade", nil))
	if res.StatusCode != http.StatusBadGateway {
		t.Fatalf("origin 101 returned status %d", res.StatusCode)
	}
	res, body := f.response(t, f.request(t, http.MethodGet, "/health", nil))
	if res.StatusCode != http.StatusOK || body != "healthy" {
		t.Fatalf("response after rejected upgrade = %d, body %q", res.StatusCode, body)
	}
}

func TestMITMHTTP2RewritesAndScripts(t *testing.T) {
	ref := func(s string) *string { return &s }
	const (
		clientAuthority = "client-authority.test"
		newURL          = "https://alternate-origin.test/rewritten"
		canonicalMatch  = "^https://alternate-origin[.]test/rewritten$"
	)
	spec := httprewrite.Spec{
		HTTPRewrites: []httprewrite.HTTPRewrite{
			{ID: "url", Match: "^https://client-authority[.]test/original$", Action: "header", Target: ref(newURL)},
		},
		HeaderRewrites: []httprewrite.HeaderRewrite{
			{ID: "authority", Match: canonicalMatch, Op: "replace", Name: "Host", Value: ref("virtual-origin.test")},
			{ID: "request-header", Match: canonicalMatch, Op: "add", Name: "X-Rewrite", Value: ref("request")},
			{ID: "response-header", Match: canonicalMatch, Phase: ref("response"), Op: "add", Name: "X-Rewrite", Value: ref("response")},
		},
		MapLocal: []httprewrite.MapLocal{
			{ID: "local", Match: "^https://client-authority[.]test/local$", DataType: ref("text"), Data: ref("local body")},
		},
		BodyRewrites: []httprewrite.BodyRewrite{
			{ID: "request-body", Match: canonicalMatch, Phase: "request", Replace: []httprewrite.Replacement{
				{Pattern: ref("request original"), Value: ref("request rewritten")},
			}},
			{ID: "response-body", Match: canonicalMatch, Phase: "response", Replace: []httprewrite.Replacement{
				{Pattern: ref("response original"), Value: ref("response rewritten")},
			}},
		},
	}
	rules, err := httprewrite.New(spec, httprewrite.Options{})
	if err != nil {
		t.Fatal(err)
	}
	route := &MITMRoute{
		H2: true, Rewrite: rules, MaxBodySize: 256,
		MatchScript: func(kind script.Kind, url string) *MITMScript {
			if url != newURL {
				t.Errorf("unexpected script match %s %s", kind, url)
				return nil
			}
			return &MITMScript{ID: string(kind), RequiresBody: true, MaxSize: 256, Run: func(_ context.Context, in *script.Input) (script.Result, error) {
				if kind == script.KindHTTPRequest {
					if string(in.Request.Body) != "request rewritten" ||
						!slices.Contains(in.Request.Headers, script.HeaderField{Name: "x-rewrite", Value: "request"}) ||
						!slices.Contains(in.Request.Headers, script.HeaderField{Name: "host", Value: "virtual-origin.test"}) {
						return script.Result{}, fmt.Errorf("unexpected request script input %+v", in.Request)
					}
					return script.Result{Action: script.ActionModify, BodySet: true, Body: []byte("request scripted")}, nil
				}
				if string(in.Response.Body) != "response rewritten" ||
					!slices.Contains(in.Response.Headers, script.HeaderField{Name: "x-rewrite", Value: "response"}) {
					return script.Result{}, fmt.Errorf("unexpected response script input %+v", in.Response)
				}
				return script.Result{
					Action: script.ActionModify, BodySet: true, Body: []byte("response scripted"),
					HeadersSet: true, Headers: []script.HeaderField{{Name: "X-Script", Value: "modified"}},
				}, nil
			}}
		},
	}
	f := newMITMH2Fixture(t, route, true, true, func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil || string(body) != "request scripted" || r.ProtoMajor != 2 ||
			r.URL.Path != "/rewritten" || r.Host != "virtual-origin.test" ||
			r.TLS.ServerName != "alternate-origin.test" || r.Header.Get("X-Rewrite") != "request" ||
			r.Trailer.Get("X-Request-Trailer") != "forwarded" {
			t.Errorf("origin request = %+v, TLS SNI = %q, body = %q, read error = %v", r, r.TLS.ServerName, body, err)
		}
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Trailer", "X-Response-Trailer")
		_, _ = io.WriteString(w, "response original")
		w.Header().Set("X-Response-Trailer", "forwarded")
	})

	req := f.request(t, http.MethodGet, "/local", nil)
	req.Host = clientAuthority
	res, body := f.response(t, req)
	if res.StatusCode != http.StatusOK || body != "local body" || f.dials.Load() != 0 {
		t.Fatalf("Map Local status = %d, body = %q, origin dials = %d", res.StatusCode, body, f.dials.Load())
	}

	req = f.request(t, http.MethodPost, "/original", strings.NewReader("request original"))
	req.Host = clientAuthority
	req.Header.Set("Content-Type", "text/plain")
	req.Trailer = http.Header{"X-Request-Trailer": {"forwarded"}}
	res, body = f.response(t, req)
	if res.StatusCode != http.StatusOK || body != "response scripted" ||
		res.Header.Get("X-Script") != "modified" || res.Trailer.Get("X-Response-Trailer") != "forwarded" {
		t.Fatalf("rewritten response status = %d, body = %q, headers = %v, trailers = %v", res.StatusCode, body, res.Header, res.Trailer)
	}
	wantMatches := []string{"url", "authority", "request-header", "request-body", "response-header", "response-body"}
	for _, row := range f.requestHistory(t, 2) {
		switch row.Path {
		case "/local":
			if !slices.Equal(row.MatchedIDs, []string{"local"}) || len(row.Scripts) != 0 {
				t.Fatalf("local request diagnostics = %+v", row)
			}
		case "/original":
			if !slices.Equal(row.MatchedIDs, wantMatches) || len(row.Scripts) != 2 ||
				row.Scripts[0].Result != "modified" || row.Scripts[1].Result != "modified" {
				t.Fatalf("rewritten request diagnostics = %+v", row)
			}
		default:
			t.Fatalf("unexpected request diagnostics = %+v", row)
		}
	}
	if live := f.live(t); !slices.Equal(live.MITMUpstreamProtocols, []string{"h2"}) {
		t.Fatalf("rerouted upstream protocols = %v", live.MITMUpstreamProtocols)
	}
}

func TestMITMHTTP2ReplacementKeepsRequestTrailers(t *testing.T) {
	f := newMITMH2Fixture(t, &MITMRoute{
		H2: true,
		MatchScript: func(kind script.Kind, _ string) *MITMScript {
			if kind != script.KindHTTPRequest {
				return nil
			}
			return &MITMScript{ID: "replace-upload", Run: func(_ context.Context, in *script.Input) (script.Result, error) {
				if in.Request.Body != nil {
					t.Errorf("bodyless script got %q", in.Request.Body)
				}
				return script.Result{Action: script.ActionModify, BodySet: true, Body: []byte("replacement")}, nil
			}}
		},
	}, true, true, func(w http.ResponseWriter, r *http.Request) {
		data, err := io.ReadAll(r.Body)
		if err != nil || string(data) != "replacement" || r.Trailer.Get("X-Upload-Trailer") != "forwarded" {
			t.Errorf("upstream body = %q, trailers = %v, error %v", data, r.Trailer, err)
		}
		w.WriteHeader(http.StatusNoContent)
	})
	req := f.request(t, http.MethodPost, "/replacement", strings.NewReader("original upload"))
	req.Trailer = http.Header{"X-Upload-Trailer": {"forwarded"}}
	if res, _ := f.response(t, req); res.StatusCode != http.StatusNoContent {
		t.Fatalf("replacement status = %d", res.StatusCode)
	}
}

func TestMITMHTTP2ConcurrentStreams(t *testing.T) {
	const count = 20
	from, to := "before:", "after:"
	rules, err := httprewrite.New(httprewrite.Spec{BodyRewrites: []httprewrite.BodyRewrite{
		{ID: "response-body", Match: "^https://mitm-h2[.]test/stream", Phase: "response", Replace: []httprewrite.Replacement{
			{Pattern: &from, Value: &to},
		}},
	}}, httprewrite.Options{})
	if err != nil {
		t.Fatal(err)
	}
	arrived := make(chan string, count)
	release := make(chan struct{})
	f := newMITMH2Fixture(t, &MITMRoute{H2: true, Rewrite: rules, MaxBodySize: 128}, true, true, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/warmup":
			return
		case "/stream":
		default:
			t.Errorf("unexpected upstream request %s", r.URL)
			return
		}
		index := r.URL.Query().Get("index")
		arrived <- index
		select {
		case <-release:
		case <-r.Context().Done():
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "before:"+index)
	})
	if res, _ := f.response(t, f.h2Request(t, http.MethodGet, "/warmup", nil)); res.StatusCode != http.StatusOK {
		t.Fatalf("warmup status = %d", res.StatusCode)
	}
	ctx, cancel := context.WithTimeout(t.Context(), mitmH2TestTimeout)
	defer cancel()
	results := make(chan error, count)
	for i := range count {
		go func() {
			index := strconv.Itoa(i)
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+mitmH2TestHost+"/stream?index="+index, nil)
			if err != nil {
				results <- err
				return
			}
			// Only gRPC shares one HTTP/2 upstream connection.
			req.Header.Set("Content-Type", "application/grpc")
			res, err := f.client.RoundTrip(req)
			if err != nil {
				results <- err
				return
			}
			defer res.Body.Close()
			body, err := io.ReadAll(res.Body)
			if err == nil && (res.StatusCode != http.StatusOK || res.ProtoMajor != 2 || string(body) != "after:"+index) {
				err = fmt.Errorf("stream %s: status %d, protocol %s, body %q", index, res.StatusCode, res.Proto, body)
			}
			results <- err
		}()
	}
	seen := make(map[string]bool, count)
	waiting := true
	for range count {
		select {
		case index := <-arrived:
			seen[index] = true
		case <-ctx.Done():
			waiting = false
		}
		if !waiting {
			break
		}
	}
	close(release)
	for range count {
		if err := <-results; err != nil {
			t.Error(err)
		}
	}
	if len(seen) != count || f.dials.Load() != 1 {
		t.Fatalf("concurrent streams = %d, origin dials = %d", len(seen), f.dials.Load())
	}
	f.requestHistory(t, count+1)
	if live := f.live(t); live.MITMRequests != count+1 || !slices.Equal(live.MITMMatchedIDs, []string{"response-body"}) {
		t.Fatalf("multiplexed connection diagnostics = %+v", live.MITMConnectionInfo)
	}
	_ = f.client.Close()
	f.waitClosed(t)
}
