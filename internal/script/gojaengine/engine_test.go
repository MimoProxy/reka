package gojaengine_test

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/MimoProxy/reka/internal/script"
	"github.com/MimoProxy/reka/internal/script/gojaengine"
)

func newTestHost(t *testing.T, limits script.Limits, env script.Environment) *script.Host {
	t.Helper()
	host := script.NewHost(gojaengine.New(), limits, env)
	t.Cleanup(host.Close)
	return host
}

func testInput(kind script.Kind) *script.Input {
	in := &script.Input{
		Request: script.Request{ID: "request-id", Method: "POST", URL: "https://example.test/input"},
	}
	if kind == script.KindHTTPResponse {
		in.Response = &script.Response{Status: 200}
	}
	return in
}

func runScript(t *testing.T, host *script.Host, spec script.Script, in *script.Input, services script.Services) script.Result {
	t.Helper()
	if spec.Kind == "" {
		spec.Kind = script.KindHTTPRequest
	}
	if spec.Name == "" {
		spec.Name = t.Name()
	}
	if in == nil {
		in = testInput(spec.Kind)
	}
	result, err := host.Run(context.Background(), &spec, in, services)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestLanguageFeatures(t *testing.T) {
	host := newTestHost(t, script.Limits{}, script.Environment{})
	tests := []struct {
		name, expr string
	}{
		{"BigInt", `(1n << 63n).toString() === "9223372036854775808" && BigInt.asUintN(64, -1n) === 18446744073709551615n`},
		{"DataView.getBigInt64", `(() => { const d = new DataView(new ArrayBuffer(8)); d.setBigUint64(0, 5n, true); return d.getBigInt64(0, true) === 5n })()`},
		{"BigInt64Array", `new BigInt64Array([1n, -9n]).at(1) === -9n`},
		{"optional chaining", `({a:{b:1}})?.a?.b === 1 && (null)?.x === undefined`},
		{"nullish coalescing", `(null ?? 3) === 3 && (0 ?? 3) === 0`},
		{"nullish assignment", `(() => { let a = null; a ??= 4; a ??= 6; return a === 4 })()`},
		{"class fields", `(() => { class A { #x = 1; static y = 2; get x() { return this.#x } }; return new A().x + A.y === 3 })()`},
		{"generators", `(function*(){ yield 1 })().next().value === 1`},
		{"spread and destructuring", `(() => { const {a, ...rest} = {a:1, b:2}; const [first, ...tail] = [...[1,2]]; return a === 1 && rest.b === 2 && first === 1 && tail[0] === 2 })()`},
		{"numeric separators", `1_000 === 1000`},
		{"globalThis", `globalThis.$done === $done`},
		{"replaceAll", `"a.a.a".replaceAll(".", "-") === "a-a-a"`},
		{"at", `[1,2,3].at(-1) === 3 && "abc".at(-2) === "b"`},
		{"Object.fromEntries", `Object.fromEntries([["a",1]]).a === 1`},
		{"regexp named group", `/(?<y>\d+)/.exec("x12").groups.y === "12"`},
		{"regexp lookbehind", `/(?<=a)b/.test("ab")`},
		{"URL", `(() => {
			const url = new URL("../item?q=one", "https://example.test/path/base");
			const initial = url.href;
			url.searchParams.append("q", "two words");
			return url.origin === "https://example.test" && url.pathname === "/item" &&
				initial === "https://example.test/item?q=one" &&
				url.toString() === "https://example.test/item?q=one&q=two+words";
		})()`},
		{"URLSearchParams", `(() => {
			const params = new URLSearchParams("x=1&x=two+words");
			return params.getAll("x").join(",") === "1,two words";
		})()`},
		{"TextEncoder", `(() => {
			const b = new TextEncoder().encode("é🌊");
			return b instanceof Uint8Array && b.join(",") === "195,169,240,159,140,138";
		})()`},
		{"TextDecoder", `(() => {
			const b = new Uint8Array([0, 195, 169, 0]);
			const d = new TextDecoder("utf-8");
			return d.decode(new DataView(b.buffer, 1, 2)) === "é" &&
				d.decode(b.subarray(1, 3)) === "é" && d.decode(b.slice(1, 3).buffer) === "é";
		})()`},
		{"base64", `(() => {
			const decoded = atob(" /wA= \n");
			return decoded.length === 2 && decoded.charCodeAt(0) === 255 && decoded.charCodeAt(1) === 0 &&
				btoa(decoded) === "/wA=";
		})()`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := runScript(t, host, script.Script{Source: `$done({body: String(` + tt.expr + `)})`}, nil, script.Services{})
			if result.Action != script.ActionModify || string(result.Body) != "true" {
				t.Fatalf("feature result = %+v", result)
			}
		})
	}
	t.Run("async await", func(t *testing.T) {
		spec := script.Script{Source: `
			(async () => {
				const value = await new Promise(resolve => setTimeout(resolve, 1, "resolved"));
				$done({body: value});
			})();
		`}
		result := runScript(t, host, spec, nil, script.Services{})
		if result.Action != script.ActionModify || string(result.Body) != "resolved" {
			t.Fatalf("async result = %+v", result)
		}
	})
}

func TestDone(t *testing.T) {
	host := newTestHost(t, script.Limits{}, script.Environment{})
	tests := []struct {
		name, source, body string
		kind               script.Kind
		dialect            script.Dialect
		action             script.Action
	}{
		{name: "empty arguments", source: `$done()`, action: script.ActionPass},
		{name: "undefined", source: `$done(undefined)`, dialect: script.DialectLoon, action: script.ActionAbort},
		{name: "null", source: `$done(null)`, dialect: script.DialectStash, action: script.ActionAbort},
		{name: "empty object", source: `$done({})`, dialect: script.DialectStash, action: script.ActionPass},
		{name: "explicit abort", source: `$done({body: "other", abort: true})`, action: script.ActionAbort},
		{name: "only first call", source: `$done({body: "first"}); $done({abort: true})`, action: script.ActionModify, body: "first"},
		{name: "immediate completion", source: `
			setTimeout(() => { throw new Error("unused timer") }, 1000);
			$done({body: "finished"});
			while (true) {}
		`, action: script.ActionModify, body: "finished"},
		{name: "response without arguments", source: `$done()`, kind: script.KindHTTPResponse, dialect: script.DialectLoon, action: script.ActionPass},
		{name: "response ignores nested response", source: `$done({response: {body: "ignored"}})`, kind: script.KindHTTPResponse, action: script.ActionPass},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec := script.Script{Kind: tt.kind, Dialect: tt.dialect, Source: tt.source, Timeout: time.Second}
			result := runScript(t, host, spec, nil, script.Services{})
			if result.Action != tt.action || result.BodySet != (tt.body != "") || string(result.Body) != tt.body {
				t.Fatalf("result = %+v", result)
			}
		})
	}

	t.Run("modify request", func(t *testing.T) {
		in := testInput(script.KindHTTPRequest)
		in.Request.Body = []byte("request 🌊")
		in.Request.Headers = []script.HeaderField{{Name: "x-Input", Value: "one"}, {Name: "x-Input", Value: "two"}}
		result := runScript(t, host, script.Script{Source: `
			if ($request.method !== "POST" || $request.id !== "request-id" ||
				$request.headers["x-Input"] !== "one, two" || typeof $response !== "undefined") {
				throw new Error("unexpected request fields");
			}
			$done({url: $request.url + "/edited", headers: {"X-Replacement": ["a", "b"]}, body: $request.body + "!"});
		`}, in, script.Services{})
		headers := []script.HeaderField{{Name: "X-Replacement", Value: "a"}, {Name: "X-Replacement", Value: "b"}}
		if result.Action != script.ActionModify || result.URL == nil || *result.URL != "https://example.test/input/edited" ||
			!result.HeadersSet || !slices.Equal(result.Headers, headers) || !result.BodySet || string(result.Body) != "request 🌊!" {
			t.Fatalf("result = %+v", result)
		}
	})

	t.Run("direct response", func(t *testing.T) {
		result := runScript(t, host, script.Script{Source: `
			$done({url: "https://example.test/unused", body: "unused",
				response: {headers: {"X-Local": "yes"}, body: new TextEncoder().encode("local")}});
		`}, nil, script.Services{})
		headers := []script.HeaderField{{Name: "X-Local", Value: "yes"}}
		if result.Action != script.ActionRespond || result.Response == nil || result.Response.Status != 200 ||
			string(result.Response.Body) != "local" || !slices.Equal(result.Response.Headers, headers) {
			t.Fatalf("result = %+v", result)
		}
	})

	t.Run("modify response", func(t *testing.T) {
		in := testInput(script.KindHTTPResponse)
		in.Request.Body = []byte("hidden")
		in.Response.Body = []byte("original")
		in.Response.Headers = []script.HeaderField{{Name: "X-Response", Value: "old"}}
		spec := script.Script{Kind: script.KindHTTPResponse, Dialect: script.DialectLoon, Source: `
			if ("body" in $request || $request.id !== "request-id" || $response.status !== 200 ||
				$response.headers["X-Response"] !== "old" || $response.body !== "original") {
				throw new Error("unexpected response fields");
			}
			$done({statusCode: 202, headers: {}, body: ""});
		`}
		result := runScript(t, host, spec, in, script.Services{})
		if result.Action != script.ActionModify || result.Status != 202 || !result.HeadersSet || len(result.Headers) != 0 ||
			!result.BodySet || len(result.Body) != 0 {
			t.Fatalf("result = %+v", result)
		}
	})
}

func TestBinaryBody(t *testing.T) {
	host := newTestHost(t, script.Limits{}, script.Environment{})
	tests := []struct {
		name, body string
		want       []byte
	}{
		{"subarray", `$request.body.subarray(1, 3)`, []byte{20, 30}},
		{"DataView", `new DataView($request.body.buffer, 1, 2)`, []byte{20, 30}},
		{"other typed array", `new Uint16Array($request.body.buffer, 2, 1)`, []byte{30, 40}},
		{"ArrayBuffer", `$request.body.buffer.slice(1, 3)`, []byte{20, 30}},
		{"detached view", `(() => {
			const view = $request.body.subarray(1, 3);
			view.buffer.transfer();
			return view;
		})()`, nil},
		{"string conversion", `123n`, []byte("123")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := testInput(script.KindHTTPRequest)
			in.Request.Body = []byte{10, 20, 30, 40}
			spec := script.Script{BinaryBody: true, Source: `
				if (!($request.body instanceof Uint8Array) || !$script.binaryBodyMode || $request.body[0] !== 10) {
					throw new Error("unexpected binary body");
				}
				$request.body[0] = 99;
				$done({body: ` + tt.body + `});
			`}
			result := runScript(t, host, spec, in, script.Services{})
			if result.Action != script.ActionModify || !result.BodySet || !slices.Equal(result.Body, tt.want) {
				t.Fatalf("result = %+v, want body %v", result, tt.want)
			}
			if in.Request.Body[0] != 10 {
				t.Fatalf("script changed the input body: %v", in.Request.Body)
			}
		})
	}
	t.Run("empty input omits body", func(t *testing.T) {
		result := runScript(t, host, script.Script{Kind: script.KindHTTPResponse, BinaryBody: true, Source: `
			if ("body" in $request || "body" in $response) throw new Error("unexpected body");
			$done({});
		`}, nil, script.Services{})
		if result.Action != script.ActionPass {
			t.Fatalf("result = %+v", result)
		}
	})
}

func TestFullHeaders(t *testing.T) {
	host := newTestHost(t, script.Limits{}, script.Environment{})
	in := testInput(script.KindHTTPResponse)
	in.Response.Headers = []script.HeaderField{{Name: "Set-Cookie", Value: "a=1"}, {Name: "x-Mixed", Value: "one"}, {Name: "Set-Cookie", Value: "b=2"}}
	result := runScript(t, host, script.Script{Kind: script.KindHTTPResponse, FullHeader: true, Source: `
		if (!Array.isArray($request.headers) || !Array.isArray($response.headers) ||
			$response.headers.map(h => h.field + "=" + h.value).join(";") !== "Set-Cookie=a=1;x-Mixed=one;Set-Cookie=b=2") {
			throw new Error("unexpected header shape");
		}
		$done({headers: $response.headers.slice().reverse()});
	`}, in, script.Services{})
	want := slices.Clone(in.Response.Headers)
	slices.Reverse(want)
	if result.Action != script.ActionModify || !result.HeadersSet || !slices.Equal(result.Headers, want) {
		t.Fatalf("result = %+v, want headers %v", result, want)
	}
}

func TestTimers(t *testing.T) {
	host := newTestHost(t, script.Limits{MaxTimers: 1}, script.Environment{})
	t.Run("timer arguments", func(t *testing.T) {
		result := runScript(t, host, script.Script{Source: `
			setTimeout((a, b) => $done({body: a + b}), 1, "tim", "er");
		`}, nil, script.Services{})
		if result.Action != script.ActionModify || string(result.Body) != "timer" {
			t.Fatalf("result = %+v", result)
		}
	})
	t.Run("clear frees the limit", func(t *testing.T) {
		result := runScript(t, host, script.Script{Source: `
			const id = setTimeout(() => $done({abort: true}), 0);
			clearTimeout(id);
			clearTimeout(id);
			setTimeout(() => $done({}), 1);
		`}, nil, script.Services{})
		if result.Action != script.ActionPass {
			t.Fatalf("result = %+v", result)
		}
	})
	t.Run("limit throws", func(t *testing.T) {
		result := runScript(t, host, script.Script{Source: `
			setTimeout(() => $done({abort:true}), 1000);
			try { setTimeout(() => {}, 1000); } catch (err) { $done({body: err instanceof Error}); }
		`}, nil, script.Services{})
		if result.Action != script.ActionModify || string(result.Body) != "true" {
			t.Fatalf("result = %+v", result)
		}
	})
	t.Run("callback can schedule another timer", func(t *testing.T) {
		result := runScript(t, host, script.Script{Source: `
			setTimeout(() => setTimeout(() => $done({}), 0), 0);
		`}, nil, script.Services{})
		if result.Action != script.ActionPass {
			t.Fatalf("result = %+v", result)
		}
	})
}

func TestNoDone(t *testing.T) {
	host := newTestHost(t, script.Limits{}, script.Environment{})
	for _, source := range []string{
		`const ignored = 42;`,
		`const id = setTimeout(() => $done({}), 1000); clearTimeout(id);`,
		`Promise.resolve().then(() => {});`,
		`setTimeout(() => {}, 0);`,
	} {
		spec := script.Script{Kind: script.KindHTTPRequest, Source: source}
		if _, err := host.Run(context.Background(), &spec, testInput(spec.Kind), script.Services{}); !errors.Is(err, script.ErrNoDone) {
			t.Errorf("%q returned %v, want ErrNoDone", source, err)
		}
	}
}

func TestScriptErrors(t *testing.T) {
	host := newTestHost(t, script.Limits{}, script.Environment{})
	for _, source := range []string{
		`throw new Error("failure: " + "x".repeat(16384) + "\nprivate continuation")`,
		`setTimeout(() => { throw new Error("failure in timer\nprivate continuation") }, 0)`,
	} {
		spec := script.Script{Kind: script.KindHTTPRequest, Name: "exception.js", Source: source}
		_, err := host.Run(context.Background(), &spec, testInput(spec.Kind), script.Services{})
		var exception *script.ScriptError
		if !errors.As(err, &exception) || exception.Name != spec.Name ||
			!strings.Contains(exception.Message, "failure") || strings.Contains(exception.Message, "\n") ||
			len(exception.Message) >= 16384 || !strings.Contains(err.Error(), spec.Name) {
			t.Fatalf("error = %v, extracted exception = %+v", err, exception)
		}
	}
	if err := gojaengine.Check("syntax.js", "function {"); err == nil {
		t.Fatal("Check accepted invalid syntax")
	}
	if err := gojaengine.Check("only-compile.js", `throw new Error("execution")`); err != nil {
		t.Fatalf("Check executed valid source: %v", err)
	}
}

func TestSynchronousTimeout(t *testing.T) {
	host := newTestHost(t, script.Limits{}, script.Environment{})
	spec := script.Script{Kind: script.KindHTTPRequest, Name: "loop.js", Source: `while (true) {}`, Timeout: 70 * time.Millisecond}
	start := time.Now()
	_, err := host.Run(context.Background(), &spec, testInput(spec.Kind), script.Services{})
	elapsed := time.Since(start)
	if !errors.Is(err, script.ErrTimeout) || elapsed < spec.Timeout/2 || elapsed > 2*time.Second {
		t.Fatalf("run took %v and returned %v, want ErrTimeout near %v", elapsed, err, spec.Timeout)
	}
}

func TestConcurrentRuns(t *testing.T) {
	const sessions = 16
	host := newTestHost(t, script.Limits{Concurrency: 4}, script.Environment{})
	var wg sync.WaitGroup
	for i := range sessions {
		wg.Go(func() {
			spec := script.Script{Kind: script.KindHTTPRequest, Source: fmt.Sprintf(`
				if (globalThis.sessionMarker !== undefined) throw new Error("shared global");
				globalThis.sessionMarker = %d;
				setTimeout(() => $done({body: globalThis.sessionMarker}), 1);
			`, i)}
			result, err := host.Run(context.Background(), &spec, testInput(spec.Kind), script.Services{})
			if err != nil || result.Action != script.ActionModify || string(result.Body) != fmt.Sprint(i) {
				t.Errorf("run %d: result = %+v, error = %v", i, result, err)
			}
		})
	}
	wg.Wait()
}

func TestDoneEscapesScriptHandlers(t *testing.T) {
	host := newTestHost(t, script.Limits{}, script.Environment{})
	result := runScript(t, host, script.Script{Source: `
		try { $done({url: "https://example.test/first"}) } catch (err) { $done({url: "https://example.test/caught"}) }
		finally { $done({url: "https://example.test/finally"}) }
	`}, nil, script.Services{})
	if result.URL == nil || *result.URL != "https://example.test/first" {
		t.Fatalf("URL = %v, want the first $done", result.URL)
	}
}

func TestUnhandledRejectionKeepsSessionAlive(t *testing.T) {
	host := newTestHost(t, script.Limits{}, script.Environment{})
	result := runScript(t, host, script.Script{Source: `
		Promise.reject(new Error("ignored"));
		setTimeout(() => $done({url: "https://example.test/later"}), 10);
	`}, nil, script.Services{})
	if result.URL == nil || *result.URL != "https://example.test/later" {
		t.Fatalf("URL = %v, want the timer's $done", result.URL)
	}

	spec := script.Script{Kind: script.KindHTTPRequest, Name: "rejected", Source: `Promise.reject(new Error("boom"))`}
	_, err := host.Run(context.Background(), &spec, testInput(script.KindHTTPRequest), script.Services{})
	var scriptErr *script.ScriptError
	if !errors.As(err, &scriptErr) || !strings.Contains(scriptErr.Message, "boom") {
		t.Fatalf("error = %v, want the unhandled rejection", err)
	}
}

func TestDoneNullBodyIsOmitted(t *testing.T) {
	host := newTestHost(t, script.Limits{}, script.Environment{})
	result := runScript(t, host, script.Script{Source: `$done({body: null})`}, nil, script.Services{})
	if result.Action != script.ActionPass || result.BodySet {
		t.Fatalf("result = %+v, want pass-through", result)
	}
}
