package sagernet

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MimoProxy/reka/internal/httprewrite"
	"github.com/MimoProxy/reka/internal/script"
	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
	"golang.org/x/net/http2"
)

func httpRelayWire(t *testing.T, route Route, dst string) (net.Conn, *Backend) {
	t.Helper()
	b := New(Options{Logger: testLogger(t)})
	t.Cleanup(func() { _ = b.Close() })
	client, inbound := connectionEventPipe(t)
	client.SetDeadline(time.Now().Add(mitmH2TestTimeout))
	var released atomic.Int32
	route.Release = func() { released.Add(1) }
	b.SetPrepareFlow(func(context.Context, Metadata) PreparedFlow {
		return PreparedFlow{
			Sniff: SniffOptions{Enabled: route.MITM.PlainHTTP, Protocols: []string{"http"}},
			Route: func(_ context.Context, md Metadata) Route {
				if route.MITM.PlainHTTP && md.Protocol != "http" {
					t.Errorf("plain HTTP connection sniffed as %q", md.Protocol)
				}
				return route
			},
		}
	})
	done := make(chan struct{})
	go b.router.RouteConnectionEx(t.Context(), inbound, adapter.InboundContext{
		Inbound: "test", Destination: M.ParseSocksaddr(dst),
	}, func(error) { close(done) })
	t.Cleanup(func() {
		client.Close()
		select {
		case <-done:
			if count := released.Load(); count != 1 {
				t.Errorf("route released %d times", count)
			}
		case <-time.After(mitmH2TestTimeout):
			t.Error("HTTP relay did not finish")
		}
	})
	return client, b
}

func httpRelayOrigin(t *testing.T, want string) (*Outbound, net.Conn) {
	t.Helper()
	remote, origin := connectionEventPipe(t)
	origin.SetDeadline(time.Now().Add(mitmH2TestTimeout))
	var called atomic.Bool
	out := &Outbound{tag: "origin", typ: "direct", out: mitmRelayTestOutbound{
		dial: func(_ context.Context, _ string, dst M.Socksaddr) (net.Conn, error) {
			if called.Swap(true) || dst.String() != want {
				return nil, errors.New("unexpected HTTP origin dial to " + dst.String())
			}
			return remote, nil
		},
	}}
	return out, origin
}

func readHTTPRelayBytes(t *testing.T, wire io.Reader, want string) {
	t.Helper()
	data := make([]byte, len(want))
	if _, err := io.ReadFull(wire, data); err != nil || string(data) != want {
		t.Fatalf("received %q, want %q, error %v", data, want, err)
	}
}

func writeHTTPRelayBytes(t *testing.T, wire io.Writer, payload string) {
	t.Helper()
	if _, err := io.WriteString(wire, payload); err != nil {
		t.Fatal(err)
	}
}

func TestPlainHTTPProxyPassthrough(t *testing.T) {
	set, err := httprewrite.New(httprewrite.Spec{HTTPRewrites: []httprewrite.HTTPRewrite{
		{ID: "reject", Match: "^http://", Action: "reject"},
	}}, httprewrite.Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		reason, head, body string
	}{
		{"connect", "CONNECT example.net:443 HTTP/1.1\r\nHost: example.net:443\r\nProxy-Authorization: Basic dGVzdA==\r\n\r\n", ""},
		{"absolute-form", "POST http://example.net/p?q=a%2Fb HTTP/1.1\r\nHost: example.net\r\nTransfer-Encoding: chunked\r\nTrailer: X-End\r\n\r\n", "3\r\none\r\n0\r\nX-End: ok\r\n\r\n"},
		{"h2c", http2.ClientPreface, ""},
	} {
		t.Run(tc.reason, func(t *testing.T) {
			out, origin := httpRelayOrigin(t, "192.0.2.1:80")
			client, backend := httpRelayWire(t, Route{
				Outbound: out, MITM: &MITMRoute{PlainHTTP: true, Host: "example.com", Rewrite: set},
			}, "192.0.2.1:80")
			payload := tc.head + tc.body + "\x00early\xff"
			writeHTTPRelayBytes(t, client, payload)
			readHTTPRelayBytes(t, origin, payload)
			writeHTTPRelayBytes(t, origin, "server data")
			readHTTPRelayBytes(t, client, "server data")
			writeHTTPRelayBytes(t, client, "client data")
			readHTTPRelayBytes(t, origin, "client data")
			live := backend.Connections()
			if len(live) != 1 || !live[0].MITMPlainHTTP || live[0].MITMSkipped != tc.reason || len(live[0].MITMMatchedIDs) != 0 {
				t.Fatalf("connection diagnostics = %+v", live)
			}
			if tc.reason == "h2c" && live[0].MITMRequests != 0 {
				t.Errorf("HTTP/2 preface counted as a request: %+v", live[0])
			}
			origin.Close()
			if n, err := client.Read(make([]byte, 1)); n != 0 || !errors.Is(err, io.EOF) {
				t.Fatalf("client after origin close: %d, %v", n, err)
			}
		})
	}
}

func TestHTTPRelayProtocolUpgrade(t *testing.T) {
	match, edit := "^https?://example[.]com/socket$", "edited"
	changed, body := "changed", "body"
	set, err := httprewrite.New(httprewrite.Spec{
		HeaderRewrites: []httprewrite.HeaderRewrite{{ID: "header", Match: match, Name: "X-Rewrite", Op: "add", Value: &edit}},
		BodyRewrites: []httprewrite.BodyRewrite{{ID: "body", Match: match, Phase: "request", Replace: []httprewrite.Replacement{
			{Pattern: &body, Value: &changed},
		}}},
	}, httprewrite.Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"plain", "tls"} {
		t.Run(mode, func(t *testing.T) {
			dst := "example.com:80"
			var inboundTLS *tls.Config
			var originTLS *tls.Config
			route := &MITMRoute{Host: "example.com", PlainHTTP: mode == "plain", Rewrite: set}
			if !route.PlainHTTP {
				dst = "example.com:443"
				issuer, roots := mitmRelayTestIssuer(t, "Upgrade test CA")
				cert, err := issuer.Certificate(route.Host)
				if err != nil {
					t.Fatal(err)
				}
				route.Issuer, route.H2, route.SkipServerCertVerify = issuer, true, true
				inboundTLS = &tls.Config{RootCAs: roots, ServerName: route.Host, NextProtos: []string{"http/1.1"}}
				originTLS = &tls.Config{Certificates: []tls.Certificate{*cert}, NextProtos: []string{"h2", "http/1.1"}}
			}
			route.MatchScript = func(kind script.Kind, _ string) *MITMScript {
				if kind != script.KindHTTPRequest {
					return nil
				}
				return &MITMScript{ID: "request-script", RequiresBody: true, MaxSize: 64, Run: func(_ context.Context, in *script.Input) (script.Result, error) {
					if len(in.Request.Body) != 0 {
						t.Error("upgrade body was buffered for a script")
					}
					return script.Result{Action: script.ActionModify, HeadersSet: true, BodySet: true, Body: []byte("changed"),
						Headers: append(in.Request.Headers, script.HeaderField{Name: "X-Script", Value: "applied"}),
					}, nil
				}}
			}
			out, origin := httpRelayOrigin(t, dst)
			wire, backend := httpRelayWire(t, Route{Outbound: out, MITM: route}, dst)
			if inboundTLS != nil {
				wire = tls.Client(wire, inboundTLS)
				origin = tls.Server(origin, originTLS)
			}

			writeHTTPRelayBytes(t, wire, "POST /socket HTTP/1.1\r\nHost: example.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nContent-Length: 4\r\n\r\nbodyearly")
			fromRelay := bufio.NewReader(origin)
			req, err := http.ReadRequest(fromRelay)
			if err != nil {
				t.Fatal(err)
			}
			if req.Header.Get("X-Rewrite") != edit || req.Header.Get("X-Script") != "applied" || httpUpgradeProtocol(req.Header) != "websocket" {
				t.Fatalf("origin headers = %v", req.Header)
			}
			readHTTPRelayBytes(t, req.Body, "body")
			req.Body.Close()
			writeHTTPRelayBytes(t, origin, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nX-Origin: switched\r\n\r\nhello")
			fromRelayToClient := bufio.NewReader(wire)
			res, err := http.ReadResponse(fromRelayToClient, nil)
			if err != nil {
				t.Fatal(err)
			}
			if res.StatusCode != http.StatusSwitchingProtocols || res.Header.Get("X-Origin") != "switched" || httpUpgradeProtocol(res.Header) != "websocket" {
				t.Fatalf("client upgrade response = %+v", res)
			}
			readHTTPRelayBytes(t, fromRelayToClient, "hello")
			readHTTPRelayBytes(t, fromRelay, "early")
			writeHTTPRelayBytes(t, wire, "later")
			readHTTPRelayBytes(t, fromRelay, "later")
			live := backend.Connections()
			if len(live) != 1 || live[0].MITMSkipped != "upgrade" || slices.Contains(live[0].MITMMatchedIDs, "body") {
				t.Fatalf("upgraded connection = %+v", live)
			}
		})
	}
}

func TestPlainHTTPRewriteReroutes(t *testing.T) {
	for _, tc := range []struct{ target, destination string }{
		{"http://example.com:8080/new", "example.com:8080"},
		{"https://example.com:80/new", "example.com:80"},
		{"http://example.net/new", "example.net:80"},
	} {
		t.Run(tc.target, func(t *testing.T) {
			set, err := httprewrite.New(httprewrite.Spec{
				HTTPRewrites: []httprewrite.HTTPRewrite{{ID: "move", Match: "^http://example[.]com/old$", Action: "header", Target: &tc.target}},
			}, httprewrite.Options{})
			if err != nil {
				t.Fatal(err)
			}
			original := &Outbound{tag: "original", typ: "direct", out: mitmRelayTestOutbound{
				dial: func(context.Context, string, M.Socksaddr) (net.Conn, error) {
					return nil, errors.New("unexpected original dial")
				},
			}}
			out, origin := httpRelayOrigin(t, tc.destination)
			if strings.HasPrefix(tc.target, "https:") {
				issuer, _ := mitmRelayTestIssuer(t, "Origin test CA")
				cert, err := issuer.Certificate("example.com")
				if err != nil {
					t.Fatal(err)
				}
				origin = tls.Server(origin, &tls.Config{Certificates: []tls.Certificate{*cert}})
			}
			released := make(chan struct{})
			route := &MITMRoute{PlainHTTP: true, Host: "example.com", Rewrite: set, SkipServerCertVerify: true,
				Reroute: func(_ context.Context, dst Destination) Route {
					if dst.String() != tc.destination {
						t.Errorf("reroute destination = %s, want %s", dst.String(), tc.destination)
					}
					return Route{Outbound: out, Release: func() { close(released) }}
				}}
			wire, _ := httpRelayWire(t, Route{Outbound: original, MITM: route}, "192.0.2.1:80")
			writeHTTPRelayBytes(t, wire, "GET /old HTTP/1.1\r\nHost: example.com\r\n\r\n")
			req, err := http.ReadRequest(bufio.NewReader(origin))
			if err != nil || req.URL.Path != "/new" {
				t.Fatalf("origin request = %v, error %v", req, err)
			}
			writeHTTPRelayBytes(t, origin, "HTTP/1.1 204 No Content\r\n\r\n")
			res, err := http.ReadResponse(bufio.NewReader(wire), nil)
			if err != nil || res.StatusCode != http.StatusNoContent {
				t.Fatalf("response = %v, error %v", res, err)
			}
			select {
			case <-released:
			case <-time.After(mitmH2TestTimeout):
				t.Fatal("rewritten route was not released")
			}
		})
	}
}

func TestPlainHTTPDeclinedUpgradeProcessesResponse(t *testing.T) {
	match, phase, edited := "^http://example[.]com/socket$", "response", "edited"
	set, err := httprewrite.New(httprewrite.Spec{HeaderRewrites: []httprewrite.HeaderRewrite{{
		ID: "declined", Match: match, Phase: &phase, Op: "add", Name: "X-Response", Value: &edited,
	}}}, httprewrite.Options{})
	if err != nil {
		t.Fatal(err)
	}
	out, origin := httpRelayOrigin(t, "example.com:80")
	wire, backend := httpRelayWire(t, Route{
		Outbound: out, MITM: &MITMRoute{PlainHTTP: true, Host: "example.com", Rewrite: set},
	}, "example.com:80")
	writeHTTPRelayBytes(t, wire, "GET /socket HTTP/1.1\r\nHost: example.com\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
	req, err := http.ReadRequest(bufio.NewReader(origin))
	if err != nil || httpUpgradeProtocol(req.Header) != "websocket" {
		t.Fatalf("upgrade request = %v, error %v", req, err)
	}
	writeHTTPRelayBytes(t, origin, "HTTP/1.1 403 Forbidden\r\nContent-Length: 2\r\n\r\nno")
	res, err := http.ReadResponse(bufio.NewReader(wire), nil)
	if err != nil || res.StatusCode != http.StatusForbidden || res.Header.Get("X-Response") != "edited" {
		t.Fatalf("declined upgrade response = %v, error %v", res, err)
	}
	defer res.Body.Close()
	readHTTPRelayBytes(t, res.Body, "no")
	live := backend.Connections()
	if len(live) != 1 || live[0].MITMSkipped != "" {
		t.Fatalf("declined upgrade diagnostics = %+v", live)
	}
}

func TestPlainHTTPUpgradeWithPendingUpload(t *testing.T) {
	out, origin := httpRelayOrigin(t, "example.com:80")
	wire, _ := httpRelayWire(t, Route{
		Outbound: out, MITM: &MITMRoute{PlainHTTP: true, Host: "example.com"},
	}, "example.com:80")
	writeHTTPRelayBytes(t, wire, "POST / HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: upgrade\r\nContent-Length: 4\r\n\r\n")
	fromClient := bufio.NewReader(origin)
	req, err := http.ReadRequest(fromClient)
	if err != nil {
		t.Fatal(err)
	}
	writeHTTPRelayBytes(t, origin, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
	writeHTTPRelayBytes(t, wire, "bodyfirst frame")
	readHTTPRelayBytes(t, req.Body, "body")
	req.Body.Close()
	res, err := http.ReadResponse(bufio.NewReader(wire), nil)
	if err != nil || res.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade response = %v, error %v", res, err)
	}
	readHTTPRelayBytes(t, fromClient, "first frame")
}
