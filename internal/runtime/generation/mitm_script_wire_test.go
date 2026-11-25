//go:build !ios

package generation

import (
	"bytes"
	"compress/gzip"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MimoProxy/reka/internal/api"
	"github.com/MimoProxy/reka/internal/config/compile"
	"github.com/MimoProxy/reka/internal/history"
	"github.com/MimoProxy/reka/internal/mitm/ca"
	"github.com/MimoProxy/reka/internal/resource"
	"github.com/MimoProxy/reka/internal/secret"
	"github.com/MimoProxy/reka/internal/testnet"
)

type wireScript struct {
	id, kind, pattern, options, source string
}

type scriptWireFixture struct {
	t        *testing.T
	origin   netip.AddrPort
	secrets  secret.Store
	roots    *x509.CertPool
	listener netip.AddrPort
}

func newScriptWireFixture(t *testing.T, handler http.HandlerFunc) *scriptWireFixture {
	t.Helper()
	upstream := scriptWireUpstream(t, handler, true)
	authority := mitmWireAuthority(t, "Script test CA")
	secrets := mitmWireStore(t)
	if err := ca.Save(secrets, authority); err != nil {
		t.Fatal(err)
	}
	return &scriptWireFixture{
		t: t, origin: upstream.Listener.Addr().(*net.TCPAddr).AddrPort(),
		secrets: secrets, roots: mitmWireRoots(t, authority),
	}
}

func scriptWireUpstream(t *testing.T, handler http.HandlerFunc, secure bool) *httptest.Server {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &httptest.Server{Listener: listener, Config: &http.Server{Handler: handler}}
	if secure {
		server.StartTLS()
	} else {
		server.Start()
	}
	t.Cleanup(server.Close)
	return server
}

func (f *scriptWireFixture) apply(engine *Engine, revision uint64, extra string, scripts []wireScript) {
	f.t.Helper()
	var profile strings.Builder
	profile.WriteString(`schema-version: 1
sniff: {enabled: true, protocols: [tls]}
mitm: {hostnames: ['origin.test:0'], h2: false, skip-server-cert-verify: true}
`)
	profile.WriteString(extra)
	profile.WriteString("scripts:\n")
	sources := make(map[string][]byte, len(scripts))
	for _, s := range scripts {
		data := []byte(s.source)
		hash := resource.Hash(data)
		sources[hash] = data
		fmt.Fprintf(&profile, "  - {id: %s, type: http-%s, pattern: %q, hash: %s%s}\n",
			s.id, s.kind, s.pattern, hash, s.options)
	}
	start := func(addr netip.AddrPort) error {
		local := fmt.Appendf(nil, "listeners: [{id: mixed, type: mixed, listen: %q}]\nmitm: {enabled: true, ca: secret://mitm/ca}\n", addr)
		eff, diags := compile.Compile([]byte(profile.String()), local, compile.Options{
			Secrets: f.secrets, ReadResource: func(hash string) ([]byte, error) {
				data := sources[hash]
				if data == nil {
					return nil, resource.ErrCorrupt
				}
				return data, nil
			},
		})
		if diags.HasErrors() {
			f.t.Fatal(diags)
		}
		prepared, err := engine.Prepare(eff)
		if err != nil {
			return err
		}
		_, err = engine.Activate(prepared, revision)
		return err
	}
	if f.listener.IsValid() {
		if err := start(f.listener); err == nil {
			return
		} else if !testnet.InUse(err) {
			f.t.Fatal(err)
		}
	}
	f.listener = testnet.RetryAddr(f.t, start)
}

func (f *scriptWireFixture) connect(t *testing.T) *mitmWireClient {
	t.Helper()
	client, err := mitmWireConnect(t, f.listener, f.origin, f.roots)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.conn.Close() })
	return client
}

func writeScriptWireRequest(t *testing.T, client *mitmWireClient, method, path string, body io.Reader) *http.Request {
	t.Helper()
	req, err := http.NewRequest(method, "https://"+client.host+path, body)
	if err != nil {
		t.Fatal(err)
	}
	if err := req.Write(client.conn); err != nil {
		t.Fatal(err)
	}
	return req
}

func readScriptWireResponse(t *testing.T, client *mitmWireClient, req *http.Request) *http.Response {
	t.Helper()
	reply, err := http.ReadResponse(client.reader, req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reply.Body.Close() })
	return reply
}

func checkScriptWireBody(t *testing.T, res *http.Response, status int, expected string) {
	t.Helper()
	data, err := io.ReadAll(res.Body)
	_ = res.Body.Close()
	if err != nil || res.StatusCode != status || string(data) != expected {
		t.Fatalf("response = %d %q, err = %v, want %d %q", res.StatusCode, data, err, status, expected)
	}
}

func TestMITMScriptWirePipeline(t *testing.T) {
	f := newScriptWireFixture(t, func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(r.Body)
		if err != nil || r.URL.Path != "/processed" || r.TLS.ServerName != "rewritten.test" ||
			r.Header.Get("X-Stage") != "" || r.Header.Get("X-Script") != "request" ||
			r.Header.Get("Content-Encoding") != "" || r.ContentLength != int64(len("rewritten-js")) {
			http.Error(w, "unexpected upstream request", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("X-Request-Id", r.Header.Get("X-Request-Id"))
		gz := gzip.NewWriter(w)
		_, _ = gz.Write(raw)
		_ = gz.Close()
	})
	routes := make(chan RouteObservation, 2)
	engine := NewEngine(EngineOptions{ObserveRoute: func(r RouteObservation) {
		if r.Domain == "rewritten.test" {
			routes <- r
		}
	}})
	t.Cleanup(engine.Close)
	extra := fmt.Sprintf(`dns:
  nameserver: ['127.0.0.1:9']
  use-hosts: true
  hosts: [{id: rewritten.test, addresses: [127.0.0.1]}]
outbounds: [{id: rewritten, type: direct}]
rules:
  - {match: {domain: rewritten.test}, outbound: rewritten}
  - {match: {all: true}, outbound: direct}
http-rewrites:
  - {id: change-path, match: '^https://origin[.]test:[0-9]+/initial$', action: header, target: 'https://origin.test:%d/request'}
header-rewrites:
  - {id: stage-header, match: '/request$', op: add, name: X-Stage, value: header}
body-rewrites:
  - {id: request-body, match: '/request$', phase: request, replace: [{pattern: client, value: rewritten}]}
  - {id: response-body, match: '/processed$', phase: response, replace: [{pattern: rewritten-js, value: upstream}]}
`, f.origin.Port())
	f.apply(engine, 1, extra, []wireScript{
		{"first-request", "request", "/request$", ", requires-body: true", `
if ($request.headers["X-Stage"] !== "header" || $request.body !== "rewritten" || !$request.id) throw Error("unexpected request input");
$done({url: $request.url.replace("origin.test", "rewritten.test").replace("/request", "/processed"),
       headers: {"X-Script": "request", "X-Request-Id": $request.id, "Content-Length": "1"},
       body: $request.body + "-js"});`},
		{"later-request", "request", "/request$", "", `$done({abort: true});`},
		{"first-response", "response", "rewritten[.]test:[0-9]+/processed$", ", requires-body: true", `
if ($request.id !== $response.headers["X-Request-Id"] || $response.body !== "upstream") throw Error("unexpected response input");
$done({status: 201, headers: {"X-Script": "response", "Content-Length": "1"}, body: $response.body + "-js"});`},
		{"later-response", "response", "/processed$", "", `$done({abort: true});`},
	})
	client := f.connect(t)
	req := writeScriptWireRequest(t, client, http.MethodPost, "/initial", strings.NewReader("client"))
	reply := readScriptWireResponse(t, client, req)
	checkScriptWireBody(t, reply, http.StatusCreated, "upstream-js")
	if reply.Header.Get("X-Script") != "response" || reply.Header.Get("Content-Encoding") != "" ||
		reply.ContentLength != int64(len("upstream-js")) {
		t.Fatalf("response headers = %v, length = %d", reply.Header, reply.ContentLength)
	}
	select {
	case route := <-routes:
		if route.Decision.Outbound != "rewritten" {
			t.Fatalf("rewritten URL selected %q", route.Decision.Outbound)
		}
	default:
		t.Fatal("the new host did not go through routing")
	}
	checkScriptWireHistory(t, engine, "/initial", []string{"first-request", "first-response"}, []string{"modified", "modified"})
	if conns := engine.Connections(); len(conns) != 1 || !slices.Equal(conns[0].MITMScripts, []api.MITMScriptStats{
		{ID: "first-request", Count: 1, LastResult: "modified"}, {ID: "first-response", Count: 1, LastResult: "modified"},
	}) {
		t.Fatalf("connection scripts = %+v", conns)
	}
	if status := engine.MITMStatus().Scripts; status.Status != "enabled" || status.Count != 4 || status.Runs != 2 || status.Modified != 2 {
		t.Fatalf("script status = %+v", status)
	}
}

func checkScriptWireHistory(t *testing.T, engine *Engine, path string, ids, results []string) uint64 {
	t.Helper()
	store, scope := engine.History()
	deadline := time.Now().Add(time.Second)
	for {
		page, err := store.List(history.Requests, scope.ProfileID, history.ListOptions{})
		if err != nil {
			t.Fatal(err)
		}
		for _, row := range page.Rows {
			var got struct {
				Path             string              `json:"path"`
				Scripts          []api.MITMScriptRun `json:"scripts"`
				BodyPassthroughs uint64              `json:"body_passthroughs"`
			}
			if err := json.Unmarshal(row.Data, &got); err != nil {
				t.Fatal(err)
			}
			if got.Path != path {
				continue
			}
			if len(got.Scripts) != len(ids) {
				t.Fatalf("%s: scripts = %+v, want %v", path, got.Scripts, ids)
			}
			for i, run := range got.Scripts {
				if run.ID != ids[i] || run.Result != results[i] ||
					run.Phase != "request" && run.Phase != "response" ||
					run.Result == "failed" && run.Error == "" {
					t.Fatalf("%s: unexpected script record %+v", path, run)
				}
			}
			return got.BodyPassthroughs
		}
		if time.Now().After(deadline) {
			t.Fatalf("no request history for %s", path)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestMITMScriptWirePassThroughAndLocalResponses(t *testing.T) {
	var upstreamRequests atomic.Uint64
	streamBody := make(chan struct{})
	var gzipBody bytes.Buffer
	encoder := gzip.NewWriter(&gzipBody)
	_, _ = io.WriteString(encoder, strings.Repeat("upstream", 64))
	if err := encoder.Close(); err != nil {
		t.Fatal(err)
	}
	f := newScriptWireFixture(t, func(w http.ResponseWriter, r *http.Request) {
		upstreamRequests.Add(1)
		switch r.URL.Path {
		case "/stream":
			w.(http.Flusher).Flush()
			select {
			case <-streamBody:
				_, _ = io.WriteString(w, "stream")
			case <-r.Context().Done():
			}
		case "/chunked":
			w.(http.Flusher).Flush()
			_, _ = io.WriteString(w, "chunked")
		case "/gzip-oversize", "/gzip-unchanged":
			w.Header().Set("Content-Encoding", "gzip")
			_, _ = w.Write(gzipBody.Bytes())
		case "/request-oversize", "/replace-without-read":
			_, _ = io.Copy(w, r.Body)
		default:
			_, _ = io.WriteString(w, "origin")
		}
	})
	engine := NewEngine(EngineOptions{})
	t.Cleanup(engine.Close)
	f.apply(engine, 1, `map-local:
  - {id: local-map, match: '/map$', data-type: text, data: map}
body-rewrites:
  - {id: local-response-body, match: '/local$', phase: response, replace: [{pattern: local, value: rewritten}]}
`, []wireScript{
		{"local", "request", "/local$", "", `$done({response: {headers: {"X-Local": "yes", "Content-Length": "999"}, body: "local"}});`},
		{"local-bypass", "response", "/local$|/map$", "", `$done({abort: true});`},
		{"map-bypass", "request", "/map$", "", `$done({abort: true});`},
		{"timeout", "request", "/timeout$", ", timeout: 1", `setTimeout(() => {}, 5000);`},
		{"no-done", "request", "/no-done$", "", `0;`},
		{"invalid-url", "request", "/invalid-url$", "", `$done({url: "http://other.test/", body: "discard", headers: {"Host":"other.test"}});`},
		{"request-oversize", "request", "/request-oversize$", ", requires-body: true, max-size: 4", `$done({body: "modified"});`},
		{"request-extra", "request", "/request-oversize$", "", `$done({abort: true});`},
		{"gzip-oversize", "response", "/gzip-oversize$", ", requires-body: true, max-size: 128", `$done({body: "modified"});`},
		{"gzip-unchanged", "response", "/gzip-unchanged$", ", requires-body: true", `
if ($response.body !== "upstream".repeat(64)) throw Error("body was not decoded");
$done({headers: {"X-Body": "read", "Content-Length": "1"}});`},
		{"chunked", "response", "/chunked$", ", requires-body: true", `
if ($response.body !== "chunked") throw Error("expected a buffered body");
$done();`},
		{"stream", "response", "/stream$", "", `
if (typeof $response.body !== "undefined" || typeof $request.body !== "undefined") throw Error("unexpected body");
$done({headers: {"Content-Length": "1", "X-Stream": "yes"}});`},
		{"body-without-read", "request", "/body-without-read$", "", `
if (typeof $request.body !== "undefined") throw Error("unexpected body");
$done({response: {body: "new"}});`},
		{"replace-without-read", "request", "/replace-without-read$", "", `
if (typeof $request.body !== "undefined") throw Error("unexpected body");
$done({body: "new"});`},
	})
	client := f.connect(t)
	get := func(path string) *http.Response {
		t.Helper()
		return readScriptWireResponse(t, client, writeScriptWireRequest(t, client, http.MethodGet, path, nil))
	}
	reply := get("/local")
	checkScriptWireBody(t, reply, http.StatusOK, "local")
	if reply.Header.Get("X-Local") != "yes" || reply.ContentLength != int64(len("local")) {
		t.Fatalf("local response headers = %v", reply.Header)
	}
	reply = readScriptWireResponse(t, client, writeScriptWireRequest(t, client, http.MethodHead, "/local", nil))
	checkScriptWireBody(t, reply, http.StatusOK, "")
	if reply.ContentLength != int64(len("local")) {
		t.Fatalf("HEAD local response content length = %d", reply.ContentLength)
	}
	checkScriptWireBody(t, get("/map"), http.StatusOK, "map")
	checkScriptWireBody(t, readScriptWireResponse(t, client, writeScriptWireRequest(t, client,
		http.MethodPost, "/body-without-read", strings.NewReader("old"))), http.StatusOK, "new")
	if upstreamRequests.Load() != 0 {
		t.Fatalf("local responses made %d upstream requests", upstreamRequests.Load())
	}
	checkScriptWireBody(t, readScriptWireResponse(t, client, writeScriptWireRequest(t, client,
		http.MethodPost, "/replace-without-read", strings.NewReader("old"))), http.StatusOK, "new")
	checkScriptWireHistory(t, engine, "/local", []string{"local"}, []string{"responded"})
	checkScriptWireHistory(t, engine, "/map", nil, nil)
	for _, tc := range []struct{ path, result string }{
		{"timeout", "timeout"}, {"no-done", "failed"}, {"invalid-url", "failed"},
	} {
		checkScriptWireBody(t, get("/"+tc.path), http.StatusOK, "origin")
		checkScriptWireHistory(t, engine, "/"+tc.path, []string{tc.path}, []string{tc.result})
	}
	req := writeScriptWireRequest(t, client, http.MethodPost, "/request-oversize", strings.NewReader("original"))
	checkScriptWireBody(t, readScriptWireResponse(t, client, req), http.StatusOK, "original")
	if got := checkScriptWireHistory(t, engine, "/request-oversize", []string{"request-oversize"}, []string{"oversize"}); got != 1 {
		t.Fatalf("oversized request body passthroughs = %d", got)
	}
	reply = get("/gzip-oversize")
	checkScriptWireBody(t, reply, http.StatusOK, gzipBody.String())
	if reply.Header.Get("Content-Encoding") != "gzip" {
		t.Fatalf("oversized response headers = %v", reply.Header)
	}
	if got := checkScriptWireHistory(t, engine, "/gzip-oversize", []string{"gzip-oversize"}, []string{"oversize"}); got != 1 {
		t.Fatalf("oversized response body passthroughs = %d", got)
	}
	reply = get("/gzip-unchanged")
	checkScriptWireBody(t, reply, http.StatusOK, gzipBody.String())
	if reply.Header.Get("X-Body") != "read" || reply.Header.Get("Content-Encoding") != "gzip" || reply.ContentLength != int64(gzipBody.Len()) {
		t.Fatalf("unmodified gzip response headers = %v", reply.Header)
	}
	reply = get("/chunked")
	checkScriptWireBody(t, reply, http.StatusOK, "chunked")
	if reply.ContentLength != 7 || len(reply.TransferEncoding) != 0 {
		t.Fatalf("buffered response framing = %d, %v", reply.ContentLength, reply.TransferEncoding)
	}
	reply = get("/stream")
	close(streamBody)
	if reply.Header.Get("X-Stream") != "yes" || reply.ContentLength != -1 || !slices.Equal(reply.TransferEncoding, []string{"chunked"}) {
		t.Fatalf("streaming response framing = %d, %v, %v", reply.ContentLength, reply.TransferEncoding, reply.Header)
	}
	checkScriptWireBody(t, reply, http.StatusOK, "stream")
	if status := engine.MITMStatus().Scripts; status.Timeouts != 1 || status.Oversize != 2 || status.Failed != 2 {
		t.Fatalf("script status = %+v", status)
	}
}

func TestMITMScriptWireAbortAndDialects(t *testing.T) {
	var upstreamRequests atomic.Uint64
	f := newScriptWireFixture(t, func(w http.ResponseWriter, r *http.Request) {
		upstreamRequests.Add(1)
		_, _ = io.WriteString(w, "origin")
	})
	engine := NewEngine(EngineOptions{})
	t.Cleanup(engine.Close)
	f.apply(engine, 1, "", []wireScript{
		{"request-abort", "request", "/request-abort$", "", `$done({abort: true});`},
		{"response-abort", "response", "/response-abort$", "", `$done({abort: true});`},
		{"surge-request", "request", "/surge$", ", format: surge", `$done();`},
		{"surge-response", "response", "/surge$", ", format: surge", `$done();`},
		{"loon-request", "request", "/loon-request$", ", format: loon", `$done();`},
		{"loon-response", "response", "/loon-response$", ", format: loon", `$done();`},
		{"stash-request", "request", "/stash-request$", ", format: stash", `$done();`},
		{"stash-response", "response", "/stash-response$", ", format: stash", `$done();`},
	})
	for _, id := range []string{"request-abort", "loon-request", "stash-request", "response-abort"} {
		client := f.connect(t)
		req := writeScriptWireRequest(t, client, http.MethodGet, "/"+id, nil)
		if res, err := http.ReadResponse(client.reader, req); !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("%s: expected the connection to close without a response, got %v, %v", id, res, err)
		}
		checkScriptWireHistory(t, engine, "/"+id, []string{id}, []string{"aborted"})
	}
	if upstreamRequests.Load() != 1 {
		t.Fatalf("aborted exchanges made %d upstream requests", upstreamRequests.Load())
	}
	client := f.connect(t)
	for _, path := range []string{"/surge", "/loon-response", "/stash-response"} {
		checkScriptWireBody(t, readScriptWireResponse(t, client, writeScriptWireRequest(t, client, http.MethodGet, path, nil)),
			http.StatusOK, "origin")
	}
	checkScriptWireHistory(t, engine, "/surge", []string{"surge-request", "surge-response"}, []string{"passed", "passed"})
}

func TestMITMScriptWireHTTPClient(t *testing.T) {
	remote := scriptWireUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, r.URL.Path)
	}, false)
	f := newScriptWireFixture(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unexpected origin request", http.StatusBadRequest)
	})
	engine := NewEngine(EngineOptions{})
	t.Cleanup(engine.Close)
	f.apply(engine, 1, `outbounds: [{id: callback-direct, name: 'Callback Direct', type: direct}]
rules: [{match: {all: true}, outbound: callback-direct}]
`, []wireScript{
		{"callbacks", "request", "/callback$", "", fmt.Sprintf(`
$httpClient.get(%[1]q, (err, res, data) => {
  if (err || res.status !== 200) throw Error("default routing failed: " + err);
  $httpClient.get({url: %[2]q, policy: "Callback Direct"}, (policyError, policyResponse, policyBody) => {
    if (policyError || policyResponse.status !== 200) throw Error("display name failed: " + policyError);
    $httpClient.get({url: %[2]q, policy: "missing-policy"}, (missingError) => {
      if (!missingError) throw Error("missing policy succeeded");
      $done({response: {body: data + policyBody}});
    });
  });
});`, remote.URL+"/rule", remote.URL+"/named")},
	})
	client := f.connect(t)
	req := writeScriptWireRequest(t, client, http.MethodGet, "/callback", nil)
	checkScriptWireBody(t, readScriptWireResponse(t, client, req), http.StatusOK, "/rule/named")
}

func TestGenericScriptWireHTTPClientWithoutMITM(t *testing.T) {
	remote := scriptWireUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, r.URL.Path)
	}, false)
	engine := NewEngine(EngineOptions{})
	t.Cleanup(engine.Close)
	source := fmt.Sprintf(`
$httpClient.get(%[1]q, (error, response, body) => {
  if (error || response.status !== 200) throw Error("default routing failed: " + error);
  $httpClient.get({url: %[2]q, policy: "DIRECT"}, (policyError, policyResponse, policyBody) => {
    if (policyError || policyResponse.status !== 200) throw Error("policy routing failed: " + policyError);
    $done({content: body + policyBody});
  });
});`, remote.URL+"/rule", remote.URL+"/policy")
	activateScriptTestProfile(t, engine, 1, source, false, compile.Script{ID: "widget", Type: "generic", Supported: true})
	run, err := engine.RunScript(t.Context(), "widget", nil, true)
	if err != nil || run.Result != "done" || string(run.Value) != `{"content":"/rule/policy"}` {
		t.Fatalf("generic HTTP client run = %+v, %v", run, err)
	}
}

func TestMITMScriptWirePersistentStore(t *testing.T) {
	f := newScriptWireFixture(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unexpected origin request", http.StatusBadRequest)
	})
	root := t.TempDir()
	engine := NewEngine(EngineOptions{StateRoot: root})
	t.Cleanup(engine.Close)
	source := fmt.Sprintf(`
const old = $persistentStore.read();
const next = String(Number(old) + 1);
if (!$persistentStore.write(next)) throw Error("could not save");
if ($persistentStore.write("x".repeat(%d), "oversize")) throw Error("oversize write succeeded");
$done({response: {body: next}});`, scriptStoreValueMax+1)
	apply := func(engine *Engine, revision uint64, id string) {
		t.Helper()
		f.apply(engine, revision, "", []wireScript{
			{id, "request", "/store$", ", download: {url: 'https://scripts.test/store.js'}", source},
		})
	}
	query := func(client *mitmWireClient, want string) {
		t.Helper()
		req := writeScriptWireRequest(t, client, http.MethodGet, "/store", nil)
		checkScriptWireBody(t, readScriptWireResponse(t, client, req), http.StatusOK, want)
	}
	apply(engine, 1, "first-store")
	initial := f.connect(t)
	query(initial, "1")
	query(initial, "2")
	apply(engine, 2, "current-store")
	query(f.connect(t), "3")
	query(initial, "4")
	engine.Close()
	restored := NewEngine(EngineOptions{StateRoot: root})
	t.Cleanup(restored.Close)
	apply(restored, 1, "restored-store")
	query(f.connect(t), "5")
}

func TestGenericScriptHTTPClientNegotiatesHTTP2(t *testing.T) {
	remote := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Bili-Status-Code", "0")
		_, _ = io.WriteString(w, r.Proto)
	}))
	remote.EnableHTTP2 = true
	remote.StartTLS()
	t.Cleanup(remote.Close)
	engine := NewEngine(EngineOptions{})
	t.Cleanup(engine.Close)
	source := fmt.Sprintf(`
$httpClient.get({url: %q, insecure: true, policy: "DIRECT"}, (error, response, body) => {
  if (error) throw Error(error);
  $done({content: body + " " + response.headers["bili-status-code"]});
});`, remote.URL+"/h2")
	activateScriptTestProfile(t, engine, 1, source, false, compile.Script{ID: "widget", Type: "generic", Supported: true})
	run, err := engine.RunScript(t.Context(), "widget", nil, true)
	if err != nil || run.Result != "done" || string(run.Value) != `{"content":"HTTP/2.0 0"}` {
		t.Fatalf("HTTP/2 client run = %+v, %v", run, err)
	}
}
