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
)

type httpFunc func(context.Context, *script.HTTPRequest) (*script.HTTPResponse, error)

func (f httpFunc) Do(ctx context.Context, req *script.HTTPRequest) (*script.HTTPResponse, error) {
	return f(ctx, req)
}

func TestHTTPClient(t *testing.T) {
	host := newTestHost(t, script.Limits{}, script.Environment{})
	t.Run("methods and default options", func(t *testing.T) {
		for _, method := range []string{"get", "post", "put", "delete", "head", "options", "patch"} {
			t.Run(method, func(t *testing.T) {
				requests := make(chan *script.HTTPRequest, 1)
				client := httpFunc(func(_ context.Context, req *script.HTTPRequest) (*script.HTTPResponse, error) {
					requests <- req
					return &script.HTTPResponse{Status: 201, Headers: []script.HeaderField{
						{Name: "x-Reply", Value: "one"}, {Name: "x-Reply", Value: "two"},
					}, Body: []byte("reply")}, nil
				})
				spec := script.Script{Source: fmt.Sprintf(`
					$httpClient.%s("https://example.test/call", (err, response, data) => {
						if (err !== null || response.status !== 201 || response.statusCode !== 201 ||
							response.headers["x-Reply"] !== "one, two") {
							throw new Error("unexpected HTTP callback");
						}
						$done({body: data});
					});
				`, method)}
				result := runScript(t, host, spec, nil, script.Services{HTTP: client})
				if result.Action != script.ActionModify || string(result.Body) != "reply" {
					t.Fatalf("result = %+v", result)
				}
				req := <-requests
				if req.Method != strings.ToUpper(method) || req.URL != "https://example.test/call" ||
					req.Timeout != 5*time.Second || !req.AutoRedirect || !req.AutoCookie || req.Binary || req.Insecure {
					t.Fatalf("request options = %+v", req)
				}
			})
		}
	})

	t.Run("await and JSON body", func(t *testing.T) {
		requests := make(chan *script.HTTPRequest, 1)
		client := httpFunc(func(_ context.Context, req *script.HTTPRequest) (*script.HTTPResponse, error) {
			requests <- req
			return &script.HTTPResponse{Status: 200, Body: []byte("awaited")}, nil
		})
		spec := script.Script{Source: `
			(async () => {
				const text = await new Promise((resolve, reject) => {
					$httpClient.post({
						url: "https://example.test/json", body: {a: 1}, timeout: 1.25,
						headers: {"x-extra": ["yes", "also"], "x-mode": "test"},
						policy: "route", "policy-descriptor": "route-info", insecure: true,
						"auto-redirect": false, "auto-cookie": false
					}, (err, reply, data) => err === null ? resolve(data) : reject(err));
				});
				$done({body: text});
			})();
		`}
		result := runScript(t, host, spec, nil, script.Services{HTTP: client})
		if result.Action != script.ActionModify || string(result.Body) != "awaited" {
			t.Fatalf("result = %+v", result)
		}
		req := <-requests
		if req.Method != "POST" || req.URL != "https://example.test/json" || string(req.Body) != `{"a":1}` ||
			req.Timeout != 1250*time.Millisecond || req.AutoRedirect || req.AutoCookie || !req.Insecure ||
			req.Policy != "route" || req.PolicyDescriptor != "route-info" {
			t.Fatalf("request options = %+v", req)
		}
		var extra []string
		var contentType string
		for _, header := range req.Headers {
			switch {
			case strings.EqualFold(header.Name, "Content-Type"):
				contentType = header.Value
			case header.Name == "x-extra":
				extra = append(extra, header.Value)
			}
		}
		if contentType != "application/json" || !slices.Equal(extra, []string{"yes", "also"}) {
			t.Fatalf("request headers = %v", req.Headers)
		}
	})

	t.Run("binary", func(t *testing.T) {
		requests := make(chan *script.HTTPRequest, 1)
		client := httpFunc(func(_ context.Context, req *script.HTTPRequest) (*script.HTTPResponse, error) {
			requests <- req
			return &script.HTTPResponse{Status: 200, Body: []byte{30, 40, 50}}, nil
		})
		spec := script.Script{Source: `
			const backing = new Uint8Array([0, 10, 20, 0]);
			$httpClient.put({url: "https://example.test/binary", body: backing.subarray(1, 3), "binary-mode": true},
				(err, reply, data) => {
					if (err !== null || !(data instanceof Uint8Array)) throw new Error("expected byte array");
					$done({body: data.subarray(1)});
				});
			backing.fill(99);
		`}
		result := runScript(t, host, spec, nil, script.Services{HTTP: client})
		if result.Action != script.ActionModify || !slices.Equal(result.Body, []byte{40, 50}) {
			t.Fatalf("result = %+v", result)
		}
		req := <-requests
		if !req.Binary || !slices.Equal(req.Body, []byte{10, 20}) {
			t.Fatalf("request = %+v", req)
		}
	})

	for _, tt := range []struct {
		name string
		http script.HTTPClient
		want string
	}{
		{"unavailable", nil, "unavailable"},
		{"service error", httpFunc(func(context.Context, *script.HTTPRequest) (*script.HTTPResponse, error) {
			return nil, errors.New("test failure")
		}), "test failure"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			spec := script.Script{Source: `
				$httpClient.get("https://example.test/error", (err, reply, data) => {
					if (typeof err !== "string" || reply !== null || data !== null) throw new Error("expected error callback");
					$done({body: err});
				});
			`}
			result := runScript(t, host, spec, nil, script.Services{HTTP: tt.http})
			if result.Action != script.ActionModify || string(result.Body) != tt.want {
				t.Fatalf("result = %+v, want body %q", result, tt.want)
			}
		})
	}
}

func TestHTTPClientInFlightLimit(t *testing.T) {
	host := newTestHost(t, script.Limits{MaxHTTPInFlight: 1}, script.Environment{})
	canceled := make(chan struct{}, 1)
	client := httpFunc(func(ctx context.Context, _ *script.HTTPRequest) (*script.HTTPResponse, error) {
		<-ctx.Done()
		canceled <- struct{}{}
		return nil, ctx.Err()
	})
	spec := script.Script{Source: `
		$httpClient.get("https://example.test/first", () => { throw new Error("first request finished early") });
		$httpClient.get("https://example.test/second", (err, reply, data) => {
			if (typeof err !== "string" || err === "" || reply !== null || data !== null) {
				throw new Error("expected in-flight limit");
			}
			$done({});
		});
	`}
	result := runScript(t, host, spec, nil, script.Services{HTTP: client})
	if result.Action != script.ActionPass {
		t.Fatalf("result = %+v", result)
	}
	select {
	case <-canceled:
	case <-time.After(2 * time.Second):
		t.Fatal("pending HTTP request was not canceled")
	}
}

func TestHTTPClientTimeoutAndLateReply(t *testing.T) {
	host := newTestHost(t, script.Limits{}, script.Environment{})
	started := make(chan struct{})
	release := make(chan struct{})
	returned := make(chan struct{})
	ready := sync.OnceFunc(func() { close(release) })
	defer ready()
	client := httpFunc(func(ctx context.Context, _ *script.HTTPRequest) (*script.HTTPResponse, error) {
		close(started)
		<-ctx.Done()
		<-release
		close(returned)
		return &script.HTTPResponse{Status: 200, Body: []byte("late")}, nil
	})
	spec := script.Script{Kind: script.KindHTTPRequest, Timeout: 100 * time.Millisecond, Source: `
		$httpClient.get("https://example.test/late", () => { throw new Error("late callback ran"); });
	`}
	start := time.Now()
	_, err := host.Run(context.Background(), &spec, testInput(spec.Kind), script.Services{HTTP: client})
	elapsed := time.Since(start)
	if !errors.Is(err, script.ErrTimeout) || elapsed < spec.Timeout/2 || elapsed > 2*time.Second {
		t.Fatalf("run took %v and returned %v, want ErrTimeout near %v", elapsed, err, spec.Timeout)
	}
	select {
	case <-started:
	default:
		t.Fatal("HTTP call never started")
	}
	ready()
	select {
	case <-returned:
	case <-time.After(2 * time.Second):
		t.Fatal("late request did not receive cancellation")
	}
	result := runScript(t, host, script.Script{Source: `setTimeout(() => $done({}), 1)`}, nil, script.Services{})
	if result.Action != script.ActionPass {
		t.Fatalf("follow-up result = %+v", result)
	}
}

func TestSessionCancellation(t *testing.T) {
	host := newTestHost(t, script.Limits{}, script.Environment{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client := httpFunc(func(ctx context.Context, _ *script.HTTPRequest) (*script.HTTPResponse, error) {
		cancel()
		<-ctx.Done()
		return nil, ctx.Err()
	})
	spec := script.Script{Kind: script.KindHTTPRequest, Source: `
		$httpClient.get("https://example.test/canceled", () => $done({}));
	`}
	_, err := host.Run(ctx, &spec, testInput(spec.Kind), script.Services{HTTP: client})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
}

type testStore struct {
	values map[string]string
}

func (s *testStore) Read(key string) (string, bool, error) {
	value, ok := s.values[key]
	return value, ok, nil
}

func (s *testStore) Write(key, value string) error {
	s.values[key] = value
	return nil
}

func (s *testStore) Delete(key string) error {
	delete(s.values, key)
	return nil
}

func TestPersistentStore(t *testing.T) {
	host := newTestHost(t, script.Limits{StoreValueMax: 16}, script.Environment{})
	store := &testStore{values: make(map[string]string)}
	services := script.Services{Store: store}
	result := runScript(t, host, script.Script{Path: "module.js", Source: `
		if ($persistentStore.read() !== null || !$persistentStore.write({v:1}) ||
			!$persistentStore.write("explicit", "script-path:module.js") ||
			$persistentStore.read("script-path:module.js") !== "explicit" ||
			$persistentStore.write("x".repeat(17), "too-large") || $persistentStore.read("too-large") !== null) {
			throw new Error("unexpected store write");
		}
		$done({});
	`}, nil, services)
	if result.Action != script.ActionPass {
		t.Fatalf("write result = %+v", result)
	}
	result = runScript(t, host, script.Script{Name: "another", Path: "module.js", Source: `
		const v = $persistentStore.read();
		if (!$persistentStore.write(null) || $persistentStore.read() !== null) {
			throw new Error("unexpected store delete");
		}
		$done({body: v});
	`}, nil, services)
	if result.Action != script.ActionModify || string(result.Body) != `{"v":1}` {
		t.Fatalf("shared read result = %+v", result)
	}
	result = runScript(t, host, script.Script{Source: `
		if ($persistentStore.read("missing") !== null || $persistentStore.write("text", "key") !== false) {
			throw new Error("expected unavailable store");
		}
		$done({});
	`}, nil, script.Services{})
	if result.Action != script.ActionPass {
		t.Fatalf("unavailable store result = %+v", result)
	}
}

type notifyFunc func(script.Notification)

func (f notifyFunc) Post(notification script.Notification) {
	f(notification)
}

func TestBackgroundScriptServices(t *testing.T) {
	host := newTestHost(t, script.Limits{}, script.Environment{})
	for _, kind := range []script.Kind{script.KindCron, script.KindGeneric} {
		t.Run(string(kind), func(t *testing.T) {
			store := &testStore{values: make(map[string]string)}
			var gotNotification script.Notification
			var gotLog string
			services := script.Services{
				Store:  store,
				Notify: notifyFunc(func(n script.Notification) { gotNotification = n }),
				Log:    func(level, message string) { gotLog = level + ":" + message },
				HTTP: httpFunc(func(_ context.Context, req *script.HTTPRequest) (*script.HTTPResponse, error) {
					if req.Method != "GET" || req.URL != "https://example.test/panel" {
						return nil, fmt.Errorf("unexpected HTTP request: %+v", req)
					}
					return &script.HTTPResponse{Status: 200, Body: []byte("panel data")}, nil
				}),
			}
			result := runScript(t, host, script.Script{Kind: kind, Source: `
				$httpClient.get("https://example.test/panel", (err, response, body) => {
					if (err || response.status !== 200 || !$persistentStore.write(body, "panel")) {
						throw new Error("HTTP or store operation failed");
					}
					const content = $persistentStore.read("panel");
					$notification.post("Panel", "", content);
					console.info(content);
					$done({title: "Panel", content});
				});
			`}, &script.Input{}, services)
			if string(result.Value) != `{"title":"Panel","content":"panel data"}` ||
				gotNotification.Title != "Panel" || gotNotification.Body != "panel data" ||
				gotLog != "info:panel data" {
				t.Fatalf("value = %s, notification = %+v, log = %q", result.Value, gotNotification, gotLog)
			}
		})
	}
}

func TestNotification(t *testing.T) {
	host := newTestHost(t, script.Limits{}, script.Environment{})
	var got script.Notification
	notifier := notifyFunc(func(notification script.Notification) { got = notification })
	spec := script.Script{Source: `
		$notification.post("title", "subtitle", "text", {"open-url": "https://example.test/"});
		$done({});
	`}
	result := runScript(t, host, spec, nil, script.Services{Notify: notifier})
	if result.Action != script.ActionPass || got.Title != "title" || got.Subtitle != "subtitle" ||
		got.Body != "text" || got.Options["open-url"] != "https://example.test/" {
		t.Fatalf("result = %+v, notification = %+v", result, got)
	}
	if result := runScript(t, host, spec, nil, script.Services{}); result.Action != script.ActionPass {
		t.Fatalf("unavailable notifier result = %+v", result)
	}
}

type testGeoIP struct{}

func (testGeoIP) Country(ip string) string {
	if ip == "192.0.2.1" {
		return "ZZ"
	}
	return ""
}

func (testGeoIP) ASN(ip string) (uint32, bool) {
	return 64496, ip == "192.0.2.1"
}

func (testGeoIP) ASOrg(ip string) string {
	if ip == "192.0.2.1" {
		return "Example Network"
	}
	return ""
}

func TestUtils(t *testing.T) {
	host := newTestHost(t, script.Limits{UngzipMax: 16}, script.Environment{})
	t.Run("geoip", func(t *testing.T) {
		spec := script.Script{Source: `
			const ip = "192.0.2.1";
			if ($utils.geoip(ip) !== "ZZ" || $utils.ipasn(ip) !== 64496 || $utils.ipaso(ip) !== "Example Network" ||
				$utils.ipasn("192.0.2.2") !== null) {
				throw new Error("unexpected GeoIP result");
			}
			$done({});
		`}
		if result := runScript(t, host, spec, nil, script.Services{GeoIP: testGeoIP{}}); result.Action != script.ActionPass {
			t.Fatalf("result = %+v", result)
		}
	})
	t.Run("unavailable geoip", func(t *testing.T) {
		spec := script.Script{Source: `
			const ip = "192.0.2.1";
			if (($utils.geoip(ip) ?? "") !== "" || $utils.ipasn(ip) !== null || ($utils.ipaso(ip) ?? "") !== "") {
				throw new Error("unexpected GeoIP result");
			}
			$done({});
		`}
		if result := runScript(t, host, spec, nil, script.Services{}); result.Action != script.ActionPass {
			t.Fatalf("result = %+v", result)
		}
	})
	t.Run("gzip and ungzip", func(t *testing.T) {
		spec := script.Script{Source: `
			const compressed = $utils.gzip("é🌊");
			const text = $utils.ungzip(compressed);
			const data = new Uint8Array([0, 1, 2, 3, 0]);
			const roundTrip = $utils.ungzip($utils.gzip(data.subarray(1, 4)));
			if (!(compressed instanceof Uint8Array) || !(text instanceof Uint8Array) ||
				new TextDecoder().decode(text) !== "é🌊" || roundTrip.join(",") !== "1,2,3" ||
				$utils.ungzip(new Uint8Array([0, 1])) !== null || $utils.ungzip($utils.gzip("x".repeat(17))) !== null) {
				throw new Error("unexpected gzip result");
			}
			$done({});
		`}
		if result := runScript(t, host, spec, nil, script.Services{}); result.Action != script.ActionPass {
			t.Fatalf("result = %+v", result)
		}
	})
}

func TestConsole(t *testing.T) {
	host := newTestHost(t, script.Limits{LogLineMax: 30}, script.Environment{})
	t.Run("disabled ignores parameters", func(t *testing.T) {
		spec := script.Script{Source: `
			let calls = 0;
			const object = {
				get toJSON() { calls++; throw new Error("unexpected getter"); },
				toString() { calls++; throw new Error("unexpected conversion"); }
			};
			for (const method of ["log", "info", "warn", "error", "debug"]) console[method](object);
			$done({body: calls});
		`}
		result := runScript(t, host, spec, nil, script.Services{})
		if result.Action != script.ActionModify || string(result.Body) != "0" {
			t.Fatalf("result = %+v", result)
		}
	})
	t.Run("formats and truncates", func(t *testing.T) {
		var lines []string
		record := func(level, message string) { lines = append(lines, level+":"+message) }
		spec := script.Script{Source: `
			console.info("alpha", {a: 1}, null);
			const cyclic = {toString() { return "fallback"; }};
			cyclic.self = cyclic;
			console.warn(cyclic);
			console.error("x".repeat(100));
			$done({});
		`}
		result := runScript(t, host, spec, nil, script.Services{Log: record})
		want := []string{`info:alpha {"a":1} null`, "warn:fallback", "error:" + strings.Repeat("x", 30)}
		if result.Action != script.ActionPass || !slices.Equal(lines, want) {
			t.Fatalf("result = %+v, logs = %q, want %q", result, lines, want)
		}
	})
}

func TestSurgeGlobals(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		host := newTestHost(t, script.Limits{}, script.Environment{})
		spec := script.Script{Source: `
			if ($environment["surge-version"] !== "5.20.0" || $environment["surge-build"] !== "3000" ||
				$environment.language !== "en" || typeof $environment.system !== "string" ||
				typeof $loon !== "undefined" || typeof $task !== "undefined" || typeof $rocket !== "undefined" ||
				typeof $prefs !== "undefined" || typeof $notify !== "undefined" || "$argument" in globalThis) {
				throw new Error("unexpected default globals");
			}
			$done({});
		`}
		if result := runScript(t, host, spec, nil, script.Services{}); result.Action != script.ActionPass {
			t.Fatalf("result = %+v", result)
		}
	})
	t.Run("custom environment and argument", func(t *testing.T) {
		env := script.Environment{System: "Windows", SurgeVersion: "6.0.0", SurgeBuild: "4000", Language: "fr", DeviceModel: "test-model"}
		host := newTestHost(t, script.Limits{}, env)
		argument := ""
		spec := script.Script{Name: "script.js", Kind: script.KindHTTPResponse, Argument: &argument, Source: `
			if ($argument !== "" || $environment.system !== "Windows" || $environment["surge-version"] !== "6.0.0" ||
				$environment["surge-build"] !== "4000" || $environment.language !== "fr" ||
				$environment["device-model"] !== "test-model" || $script.name !== "script.js" ||
				$script.type !== "http-response" || $script.binaryBodyMode !== false ||
				typeof $script.startTime !== "number" || Math.abs(Date.now() / 1000 - $script.startTime) > 10 ||
				typeof $script.sessionID !== "string" || $script.sessionID === "") {
				throw new Error("unexpected session globals");
			}
			$done({body: $script.sessionID});
		`}
		first := runScript(t, host, spec, nil, script.Services{})
		second := runScript(t, host, spec, nil, script.Services{})
		if first.Action != script.ActionModify || second.Action != script.ActionModify || slices.Equal(first.Body, second.Body) {
			t.Fatalf("session IDs = %q, %q", first.Body, second.Body)
		}
	})
}
