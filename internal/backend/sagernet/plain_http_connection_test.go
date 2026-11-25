package sagernet

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/MimoProxy/reka/internal/config/compile"
	"github.com/MimoProxy/reka/internal/config/model"
	"github.com/MimoProxy/reka/internal/config/module"
	"github.com/MimoProxy/reka/internal/history"
	"github.com/MimoProxy/reka/internal/httprewrite"
	"github.com/MimoProxy/reka/internal/resource"
	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
)

func startPlainHTTPFlow(t *testing.T, out *Outbound, rewrite *httprewrite.Set) (*Backend, net.Conn, <-chan struct{}) {
	t.Helper()
	backend := New(Options{History: history.New(), Logger: testLogger(t)})
	t.Cleanup(func() { _ = backend.Close() })
	client, inbound := connectionEventPipe(t)
	_ = client.SetDeadline(time.Now().Add(mitmH2WireTimeout))
	backend.SetPrepareFlow(func(context.Context, Metadata) PreparedFlow {
		return PreparedFlow{
			Sniff: SniffOptions{Enabled: true, Protocols: []string{"http"}},
			Route: func(_ context.Context, md Metadata) Route {
				rt := Route{Outbound: out}
				if md.Protocol != "http" || md.SniffedDomain == "" {
					t.Errorf("unexpected HTTP sniff result: %+v", md)
				}
				if rewrite.MayMatchHTTP(md.SniffedDomain, md.Destination.Port) {
					rt.MITM = &MITMRoute{PlainHTTP: true, Host: md.SniffedDomain, Rewrite: rewrite, MaxBodySize: 1024}
				}
				return rt
			},
		}
	})
	done := make(chan struct{})
	go backend.router.RouteConnectionEx(t.Context(), inbound, adapter.InboundContext{
		Inbound: "test", InboundType: "tun", Destination: M.ParseSocksaddr("192.0.2.1:80"),
	}, func(error) { close(done) })
	return backend, client, done
}

func TestPlainHTTPUnmatchedRelayPreservesWireBytes(t *testing.T) {
	set, err := httprewrite.New(httprewrite.Spec{HTTPRewrites: []httprewrite.HTTPRewrite{
		{ID: "reject", Match: `^http://example\.com/`, Action: "reject"},
	}}, httprewrite.Options{})
	if err != nil {
		t.Fatal(err)
	}
	remote, origin := connectionEventPipe(t)
	out := &Outbound{tag: "origin", typ: "direct", out: eventTestOutbound{conn: remote}}
	backend, client, done := startPlainHTTPFlow(t, out, set)
	// A parsed and serialized request would lose case, whitespace and header order.
	wire := "POST /raw HTTP/1.1\r\nhOst: example.net\r\nx-test:  two  \r\nContent-Length: 3\r\n\r\n\x00\xff!"
	passConnectionEventPayload(t, client, origin, wire)
	passConnectionEventPayload(t, origin, client, "\xff\x00unparsed response")
	live := backend.Connections()
	if len(live) != 1 || live[0].MITM || live[0].MITMRequests != 0 {
		t.Fatalf("unmatched connection = %+v", live)
	}
	closeConnectionEventFlow(t, backend, live[0].ID, done)
	got, err := backend.history.List(history.Requests, "", history.ListOptions{})
	if err != nil || len(got.Rows) != 0 {
		t.Fatalf("unmatched relay recorded %d requests, error %v", len(got.Rows), err)
	}
}

func TestPlainHTTPKeepAliveMatchesEachAuthority(t *testing.T) {
	body := []byte(`[Body Rewrite]
http-response-jq ^http:\/\/[^?]+\/resolve\?host= '.changed = true'
`)
	source := model.Module{URL: "https://example.com/filter.sgmodule"}
	profile := fmt.Appendf(nil, `schema-version: 1
modules: [{id: filter, url: %s}]
http-rewrites:
  - {id: redirect, match: '/redirect$', action: '302', target: '/next'}
  - {id: reject, match: '/reject$', action: reject}
map-local:
  - {id: local, match: '^http://example\.com/local$', data-type: text, data: local}
header-rewrites:
  - {id: header, match: '^http://example\.net/resolve\?', phase: response, op: add, name: X-Rewrite, value: applied}
`, source.URL)
	hash := resource.Hash(body)
	eff, diagnostics := compile.Compile(profile, nil, compile.Options{
		Sources: fmt.Appendf(nil, "sources: [{id: filter, module: {format: surge, request: %s}, lock: {root: %s}}]", source.RequestHash(), hash),
		ReadResource: func(key string) ([]byte, error) {
			if key == hash {
				return body, nil
			}
			return nil, resource.ErrCorrupt
		},
	})
	if diagnostics.HasErrors() {
		t.Fatal(diagnostics)
	}
	if lines := eff.Modules["filter"].Lines; len(lines) != 2 || lines[1].Line != 2 || lines[1].Status != module.Supported {
		t.Fatalf("module import = %+v", lines)
	}
	out := &Outbound{tag: "origin", typ: "direct", out: mitmRelayTestOutbound{
		dial: func(_ context.Context, network string, dst M.Socksaddr) (net.Conn, error) {
			if network != "tcp" || dst.String() != "192.0.2.1:80" {
				return nil, fmt.Errorf("unexpected upstream destination %s %s", network, dst)
			}
			conn, origin := net.Pipe()
			go func() {
				defer origin.Close()
				_ = origin.SetDeadline(time.Now().Add(mitmH2WireTimeout))
				reader := bufio.NewReader(origin)
				for {
					req, err := http.ReadRequest(reader)
					if err != nil {
						return
					}
					_ = req.Body.Close()
					body := fmt.Sprintf(`{"host":%q}`, req.Host)
					if _, err := fmt.Fprintf(origin, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s", len(body), body); err != nil {
						return
					}
				}
			}()
			return conn, nil
		},
	}}
	backend, client, done := startPlainHTTPFlow(t, out, eff.HTTPRewrite)
	reader := bufio.NewReader(client)
	cases := []struct {
		host, path, header, body string
		status                   int
	}{
		{"example.com", "/local", "", "local", http.StatusOK},
		{"example.com", "/redirect", "", "", http.StatusFound},
		{"example.com", "/reject", "", "", http.StatusNotFound},
		{"example.net", "/resolve?host=example.com", "applied", `{"changed":true,"host":"example.net"}`, http.StatusOK},
		{"example.com", "/query", "", `{"host":"example.com"}`, http.StatusOK},
		{"example.net", "/local", "", `{"host":"example.net"}`, http.StatusOK},
	}
	for _, tc := range cases {
		req, err := http.NewRequest(http.MethodGet, "http://"+tc.host+tc.path, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := req.Write(client); err != nil {
			t.Fatal(err)
		}
		res, err := http.ReadResponse(reader, req)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(res.Body)
		_ = res.Body.Close()
		if err != nil || res.StatusCode != tc.status || res.Header.Get("X-Rewrite") != tc.header || strings.TrimSpace(string(body)) != tc.body {
			t.Fatalf("%s: %s, headers %v, body %q, error %v", req.URL, res.Status, res.Header, body, err)
		}
		if tc.status == http.StatusFound && res.Header.Get("Location") != "http://example.com/next" {
			t.Fatalf("redirect location = %q", res.Header.Get("Location"))
		}
	}
	live := backend.Connections()
	if len(live) != 1 {
		t.Fatalf("active connections = %d", len(live))
	}
	closeConnectionEventFlow(t, backend, live[0].ID, done)
	trace := readClosedConnectionEventTrace(t, backend.history, live[0].ID)
	if !trace.MITM || !trace.MITMPlainHTTP || trace.Protocol != "http" || trace.MITMRequests != uint64(len(cases)) ||
		!slices.Equal(trace.MITMUpstreamProtocols, []string{"http/1.1"}) {
		t.Fatalf("closed HTTP connection = %+v", trace)
	}
	requests, err := backend.history.List(history.Requests, "", history.ListOptions{})
	if err != nil || len(requests.Rows) != len(cases) {
		t.Fatalf("got %d request history rows, error %v", len(requests.Rows), err)
	}
	for _, row := range requests.Rows {
		var record requestRecord
		if err := json.Unmarshal(row.Data, &record); err != nil || record.Scheme != "http" || record.ConnectionID != trace.ID {
			t.Fatalf("request history = %s, error %v", row.Data, err)
		}
	}
}
