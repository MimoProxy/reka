//go:build !ios

package generation

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"github.com/MimoProxy/reka/internal/backend/sagernet"
	"github.com/MimoProxy/reka/internal/config/compile"
	"github.com/MimoProxy/reka/internal/config/model"
	"github.com/MimoProxy/reka/internal/config/module"
	"github.com/MimoProxy/reka/internal/httprewrite"
	"github.com/MimoProxy/reka/internal/resource"
	"github.com/MimoProxy/reka/internal/script"
	"github.com/MimoProxy/reka/internal/testnet"
	"golang.org/x/net/proxy"
)

func TestPlainHTTPSurgeModuleAndScripts(t *testing.T) {
	engine := NewEngine(EngineOptions{})
	t.Cleanup(engine.Close)
	origin := scriptWireUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/resolve":
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"answer":"original","extra":true}`)
		case "/script":
			fmt.Fprint(w, r.Header.Get("X-Rule"), " ", r.Header.Get("X-Script"))
		default:
			io.WriteString(w, r.Host)
		}
	}, false)
	target := origin.Listener.Addr().(*net.TCPAddr).AddrPort()
	second := scriptWireUpstream(t, func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "rerouted") }, false)
	newPort := second.Listener.Addr().(*net.TCPAddr).AddrPort().Port()
	profile, opts := plainHTTPWireProfile(newPort)
	listener := testnet.RetryAddr(t, func(addr netip.AddrPort) error {
		local := fmt.Appendf(nil, "listeners: [{id: proxy, type: mixed, listen: %q}]", addr)
		eff, diagnostics := compile.Compile([]byte(profile), local, opts)
		if diagnostics.HasErrors() {
			t.Fatal(diagnostics)
		}
		if lines := eff.Modules["filter"].Lines; len(lines) == 0 || lines[len(lines)-1].Line != 2 || lines[len(lines)-1].Status != module.Supported {
			t.Fatalf("module import = %+v", lines)
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
		host, path string
		status     int
		body       string
	}{
		{"example.com", "/resolve?host=example.net", http.StatusOK, `{"answer":"changed"}`},
		{"example.com", "/redirect", http.StatusFound, ""},
		{"example.com", "/reject", http.StatusNotFound, ""},
		{"example.net", "/local", http.StatusOK, "mapped"},
		{"example.com", "/local", http.StatusOK, fmt.Sprintf("example.com:%d", target.Port())},
		{"example.com", "/reroute", http.StatusOK, "rerouted"},
		{"example.com", "/script", http.StatusOK, "header request response"},
	}
	for _, tt := range cases {
		rawURL := fmt.Sprintf("http://%s:%d%s", tt.host, target.Port(), tt.path)
		req, err := http.NewRequest(http.MethodGet, rawURL, nil)
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
		data, err := io.ReadAll(res.Body)
		res.Body.Close()
		if err != nil || res.StatusCode != tt.status {
			t.Fatalf("%s response = %d %q, %v", rawURL, res.StatusCode, data, err)
		}
		if string(data) != tt.body {
			t.Fatalf("%s body = %q, want %q", rawURL, data, tt.body)
		}
		if tt.path == "/redirect" && res.Header.Get("Location") != fmt.Sprintf("http://example.com:%d/next", target.Port()) {
			t.Fatalf("Location = %q", res.Header.Get("Location"))
		}
	}
	if status := engine.MITMStatus(); status.Enabled || status.CALoaded || status.Connections != 0 || status.Requests != 0 ||
		status.PlainHTTPConnections != 1 || status.PlainHTTPRequests != uint64(len(cases)) || status.Scripts.Modified != 2 {
		t.Fatalf("HTTP engine status = %+v", status)
	}
}

func plainHTTPWireProfile(newPort uint16) (string, compile.Options) {
	request := []byte(`$done({headers: Object.assign({}, $request.headers, {"X-Script": "request"})});`)
	response := []byte(`$done({body: $response.body + " response"});`)
	profile, opts := plainHTTPModule(map[string][]byte{resource.Hash(request): request, resource.Hash(response): response})
	profile += fmt.Sprintf(`mitm: {hostnames: [ignored.example.net], client-source-address: [192.0.2.99]}
dns:
  use-hosts: true
  nameserver: ['127.0.0.1:9']
  hosts: [{id: example.com, addresses: [127.0.0.1]}]
http-rewrites:
  - {id: redirect, match: '/redirect$', action: '302', target: '/next'}
  - {id: reject, match: '/reject$', action: reject, response: error}
  - {id: change-port, match: '^http://example[.]com:[0-9]+/reroute$', action: header, target: 'http://example.com:%d/new'}
map-local:
  - {id: local, match: '^http://example[.]net:[0-9]+/local$', data-type: text, data: 'mapped'}
header-rewrites:
  - {id: rule-header, match: '/script$', op: add, name: X-Rule, value: header}
scripts:
  - {id: request, type: http-request, pattern: '/script$', hash: %s}
  - {id: response, type: http-response, pattern: '/script$', requires-body: true, hash: %s}
`, newPort, resource.Hash(request), resource.Hash(response))
	return profile, opts
}

func plainHTTPModule(resources map[string][]byte) (string, compile.Options) {
	def := model.Module{URL: "https://example.com/filter.sgmodule"}
	body := []byte(`[Body Rewrite]
http-response-jq ^http:\/\/[^?]+\/resolve\?host= 'del(.extra) | .answer = "changed"'
`)
	resources[resource.Hash(body)] = body
	opts := compile.Options{
		Sources: fmt.Appendf(nil, "sources: [{id: filter, module: {format: surge, request: %s}, lock: {root: %s}}]", def.RequestHash(), resource.Hash(body)),
		ReadResource: func(key string) ([]byte, error) {
			if data, ok := resources[key]; ok {
				return data, nil
			}
			return nil, resource.ErrCorrupt
		},
	}
	return fmt.Sprintf("schema-version: 1\nmodules: [{id: filter, url: %s}]\n", def.URL), opts
}

func TestPlainHTTPSurgeModuleRoute(t *testing.T) {
	engine := NewEngine(EngineOptions{})
	t.Cleanup(engine.Close)
	profile, opts := plainHTTPModule(map[string][]byte{})
	eff := activatePlainHTTPConfig(t, engine, profile, "", opts, 1)
	if report := eff.Modules["filter"]; report.Rewrites.Imported != 1 || report.Partial || !report.CanApply {
		t.Fatalf("module import = %+v", report)
	}
	md := sagernet.Metadata{Network: "tcp", Destination: sagernet.Destination{Addr: netip.MustParseAddr("192.0.2.1"), Port: 80}}
	prep := engine.prepareFlow(t.Context(), md)
	if !prep.Sniff.Enabled {
		t.Fatal("the imported module did not request HTTP sniffing")
	}
	defer prep.Release()
	md.Protocol, md.SniffedDomain = "http", "example.com"
	rt := prep.Route(t.Context(), md)
	if rt.Release != nil {
		defer rt.Release()
	}
	if rt.MITM == nil || !rt.MITM.PlainHTTP || rt.MITM.Issuer != nil {
		t.Fatalf("imported module route = %+v", rt.MITM)
	}
	response := rt.MITM.Rewrite.Response("http://example.com/resolve?host=example.net", httprewrite.Response{
		Header: http.Header{"Content-Type": {"application/json"}}, Body: []byte(`{"answer":"original","extra":true}`),
	})
	if string(response.Body) != `{"answer":"changed"}` {
		t.Fatalf("module jq response = %s", response.Body)
	}
}

func TestPlainHTTPScriptExecution(t *testing.T) {
	engine := NewEngine(EngineOptions{})
	t.Cleanup(engine.Close)
	profile, opts := plainHTTPWireProfile(8080)
	activatePlainHTTPConfig(t, engine, profile, "", opts, 1)
	md := sagernet.Metadata{Network: "tcp", Protocol: "http", Destination: sagernet.Destination{Domain: "example.com", Port: 80}}
	route := engine.route(t.Context(), md)
	if route.Release != nil {
		defer route.Release()
	}
	if route.MITM == nil || !route.MITM.PlainHTTP || route.MITM.MatchScript == nil {
		t.Fatalf("missing HTTP script route: %+v", route.MITM)
	}
	input := &script.Input{Request: script.Request{ID: "sample", URL: "http://example.com/script", Method: http.MethodGet}}
	headers := route.MITM.Rewrite.Request(httprewrite.Request{URL: input.Request.URL, Header: http.Header{}}).Header
	input.Request.Headers = []script.HeaderField{{Name: "X-Rule", Value: headers.Get("X-Rule")}}
	run := func(kind script.Kind) script.Result {
		t.Helper()
		matched := route.MITM.MatchScript(kind, input.Request.URL)
		if matched == nil || matched.Run == nil {
			t.Fatalf("missing %s script", kind)
		}
		result, err := matched.Run(t.Context(), input)
		if err != nil || result.Action != script.ActionModify {
			t.Fatalf("%s script result = %+v, error = %v", kind, result, err)
		}
		return result
	}
	request := run(script.KindHTTPRequest)
	edited := make(http.Header)
	for _, h := range request.Headers {
		edited.Add(h.Name, h.Value)
	}
	if !request.HeadersSet || edited.Get("X-Rule") != "header" || edited.Get("X-Script") != "request" {
		t.Fatalf("script request headers = %+v", request.Headers)
	}
	input.Request.Headers = request.Headers
	input.Response = &script.Response{Status: http.StatusOK, Body: []byte("header request")}
	response := run(script.KindHTTPResponse)
	if !response.BodySet || string(response.Body) != "header request response" {
		t.Fatalf("script response body = %q", response.Body)
	}
}
