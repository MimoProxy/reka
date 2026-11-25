package scriptbridge

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"testing/synctest"
	"time"

	"github.com/MimoProxy/reka/internal/script"
)

type fakeHost struct {
	start  func(run uint64, job, requestBody, responseBody []byte)
	cancel func(run uint64)
	reply  func(run, call uint64, response, body []byte)
	purge  func()
}

func (h *fakeHost) Start(run uint64, job, requestBody, responseBody []byte) {
	h.start(run, job, requestBody, responseBody)
}

func (h *fakeHost) Cancel(run uint64) {
	if h.cancel != nil {
		h.cancel(run)
	}
}

func (h *fakeHost) Reply(run, call uint64, response, body []byte) {
	h.reply(run, call, response, body)
}

func (h *fakeHost) Purge() {
	if h.purge != nil {
		h.purge()
	}
}

func newJob() *script.Job {
	return &script.Job{
		Script: &script.Script{Kind: script.KindHTTPRequest, Source: "$done()"},
		Input:  &script.Input{},
	}
}

func assertJSON(t *testing.T, got []byte, want string) {
	t.Helper()
	var actual, expected any
	if err := json.Unmarshal(got, &actual); err != nil {
		t.Fatalf("invalid actual JSON %q: %v", got, err)
	}
	if err := json.Unmarshal([]byte(want), &expected); err != nil {
		t.Fatalf("invalid expected JSON %q: %v", want, err)
	}
	if !reflect.DeepEqual(actual, expected) {
		t.Errorf("JSON = %s, want %s", got, want)
	}
}

func TestRunJobAndBinaryDone(t *testing.T) {
	argument := ""
	job := &script.Job{
		Script: &script.Script{
			Kind: script.KindHTTPResponse, Dialect: script.DialectStash, Engine: "webview",
			Key: "cache-key", Path: "https://example.org/script.js", Name: "test",
			Source: "$done()", FullHeader: true, BinaryBody: true, Argument: &argument,
			Timeout: 2 * time.Second,
		},
		Input: &script.Input{
			Request: script.Request{
				ID: "request-id", Method: "POST", URL: "https://example.org/",
				Headers: []script.HeaderField{{Name: "X-Test", Value: "one"}, {Name: "X-Test", Value: "two"}},
				Body:    []byte{0, 1},
			},
			Response: &script.Response{Status: 201, Body: []byte{}},
		},
		Env: script.Environment{System: "iOS", SurgeVersion: "version", SurgeBuild: "build", Language: "en"},
		Limits: script.Limits{
			MaxTimers: 3, MaxHTTPInFlight: 5, LogLineMax: 10, StoreValueMax: 20, UngzipMax: 30,
		},
	}
	host := &fakeHost{}
	b := New(host, Options{})
	host.start = func(run uint64, data, request, response []byte) {
		if run != 1 || !bytes.Equal(request, []byte{0, 1}) || response == nil || len(response) != 0 {
			t.Errorf("Start(%d, ..., %#v, %#v)", run, request, response)
		}
		assertJSON(t, data, `{
			"key":"cache-key","name":"test","path":"https://example.org/script.js",
			"kind":"http-response","dialect":"stash","engine":"webview","binaryBody":true,
			"fullHeader":true,"argument":"","timeoutMs":2000,"sourceSize":7,
			"request":{"id":"request-id","method":"POST","url":"https://example.org/",
				"headers":[["X-Test","one"],["X-Test","two"]],"hasBody":true},
			"response":{"status":201,"headers":[],"hasBody":true},
			"env":{"system":"iOS","surgeVersion":"version","surgeBuild":"build","language":"en","deviceModel":""},
			"limits":{"maxTimers":3,"maxHTTPInFlight":5,"logLineMax":10,"storeValueMax":20,"ungzipMax":30}
		}`)
		if source, ok := b.Source(run); !ok || string(source) != job.Script.Source {
			t.Errorf("Source = %q, %v", source, ok)
		}
		source := make([]byte, len(job.Script.Source))
		if n := b.WriteSource(run, nil); int(n) != -len(source) {
			t.Errorf("WriteSource with short buffer = %d", n)
		}
		if n := b.WriteSource(run, source); int(n) != len(source) || string(source) != job.Script.Source {
			t.Errorf("WriteSource = %d, output = %q", n, source)
		}
		completion := []byte(`{"called":true,"hasValue":true,"status":202,"headers":[["Set-Cookie","a"],["Set-Cookie","b"]],"headersSet":true,"bodySet":true}`)
		body := []byte{1, 0, 255}
		if !b.Done(run, completion, body, nil) || b.Done(run, completion, body, nil) {
			t.Error("expected Done to accept exactly one completion")
		}
		clear(completion)
		clear(body)
		if _, ok := b.Source(run); ok {
			t.Error("retired run still exposes its source")
		}
		if n := b.WriteSource(run, source); n != 0 {
			t.Errorf("WriteSource for retired run = %d", n)
		}
	}
	done, err := b.Run(context.Background(), job)
	wantHeaders := []script.HeaderField{{Name: "Set-Cookie", Value: "a"}, {Name: "Set-Cookie", Value: "b"}}
	if err != nil || !done.Called || !done.HasValue || done.Status == nil || *done.Status != 202 ||
		!done.HeadersSet || !reflect.DeepEqual(done.Headers, wantHeaders) || !done.BodySet ||
		!bytes.Equal(done.Body, []byte{1, 0, 255}) {
		t.Fatalf("Run = %+v, %v", done, err)
	}
}

func TestJobEncodesArgumentObject(t *testing.T) {
	const object = `{"player":"Example","enabled":true}`
	argument := object
	job := newJob()
	job.Script.Argument = &argument
	job.Script.ArgumentObject = true
	metadata, _, err := marshalJob(job)
	if err != nil {
		t.Fatal(err)
	}
	var wire struct {
		Argument json.RawMessage `json:"argument"`
	}
	if err := json.Unmarshal(metadata, &wire); err != nil {
		t.Fatal(err)
	}
	assertJSON(t, wire.Argument, object)
	argument = `[]`
	if _, _, err := marshalJob(job); err == nil {
		t.Fatal("non-object argument was accepted")
	}
}

func TestRunRequestResponse(t *testing.T) {
	host := &fakeHost{}
	b := New(host, Options{})
	job := newJob()
	host.start = func(run uint64, data, request, response []byte) {
		assertJSON(t, data, `{
			"key":"`+job.Script.CacheKey()+`","name":"","path":"","kind":"http-request","dialect":"",
			"engine":"","binaryBody":false,"fullHeader":false,"argument":null,"timeoutMs":5000,"sourceSize":7,
			"request":{"id":"","method":"","url":"","headers":[],"hasBody":false},
			"env":{"system":"","surgeVersion":"","surgeBuild":"","language":"","deviceModel":""},
			"limits":{"maxTimers":64,"maxHTTPInFlight":64,"logLineMax":524288,"storeValueMax":4194304,"ungzipMax":33554432}
		}`)
		if request != nil || response != nil {
			t.Errorf("unexpected input bodies: %#v, %#v", request, response)
		}
		responseBody := []byte{1, 0, 2}
		if !b.Done(run, []byte(`{"called":true,"hasValue":true,"bodySet":true,"response":{"status":404,"bodySet":true}}`), nil, responseBody) {
			t.Error("completion was rejected")
		}
		clear(responseBody)
	}
	done, err := b.Run(context.Background(), job)
	if err != nil || done.Body == nil || len(done.Body) != 0 || done.Response == nil ||
		done.Response.Status != 404 || !bytes.Equal(done.Response.Body, []byte{1, 0, 2}) {
		t.Fatalf("Run = %+v, %v", done, err)
	}
}

func TestRunCancelAndLateDone(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		host := &fakeHost{}
		b := New(host, Options{})
		var started, canceled uint64
		host.start = func(run uint64, _, _, _ []byte) { started = run }
		host.cancel = func(run uint64) {
			canceled = run
			if b.Done(run, []byte(`{"called":true}`), nil, nil) {
				t.Error("completion during Cancel was accepted")
			}
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if _, err := b.Run(ctx, newJob()); !errors.Is(err, script.ErrTimeout) {
			t.Errorf("Run = %v, want timeout", err)
		}
		if started != 1 || canceled != started || b.Done(started, []byte(`{"called":true}`), nil, nil) {
			t.Fatalf("started = %d, canceled = %d, late completion must be rejected", started, canceled)
		}
		host.start = func(run uint64, _, _, _ []byte) {
			if run <= started {
				t.Errorf("run ID %d was reused", run)
			}
			b.Done(run, []byte(`{"called":true}`), nil, nil)
		}
		if _, err := b.Run(context.Background(), newJob()); err != nil {
			t.Fatal(err)
		}
	})
}

func TestRunCompletionErrors(t *testing.T) {
	for _, tc := range []struct {
		name, input string
		want        error
	}{
		{name: "invalid JSON", input: `{`},
		{name: "null", input: `null`},
		{name: "exception", input: `{"error":{"kind":"exception","name":"TypeError","message":"bad argument\nstack"}}`},
		{name: "timeout", input: `{"error":{"kind":"timeout"}}`, want: script.ErrTimeout},
		{name: "no done", input: `{"error":{"kind":"nodone"}}`, want: script.ErrNoDone},
		{name: "memory", input: `{"error":{"kind":"memory"}}`, want: script.ErrMemoryExceeded},
		{name: "internal", input: `{"error":{"kind":"internal","message":"unexpected host error"}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			host := &fakeHost{}
			b := New(host, Options{})
			host.start = func(run uint64, _, _, _ []byte) { b.Done(run, []byte(tc.input), nil, nil) }
			_, err := b.Run(context.Background(), newJob())
			if err == nil || tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("Run = %v, want error %v", err, tc.want)
			}
			if tc.name == "exception" {
				var ex *script.ScriptError
				if !errors.As(err, &ex) || ex.Name != "TypeError" || ex.Message != "bad argument" {
					t.Errorf("exception = %#v, error = %v", ex, err)
				}
			}
		})
	}
}

func TestHostMemoryBudgetAndCircuitBreaker(t *testing.T) {
	var footprint uint64
	var starts, purges int
	host := &fakeHost{purge: func() { purges++ }}
	b := New(host, Options{Footprint: func() uint64 { return footprint }, SkipAbove: 10, DiscardAbove: 20})
	overBudget := false
	host.start = func(run uint64, _, _, _ []byte) {
		starts++
		if overBudget {
			footprint = 21
		}
		b.Done(run, []byte(`{"called":true,"hasValue":true,"url":"https://example.org/new"}`), nil, nil)
	}
	h := script.NewHost(b, script.Limits{BreakerFailures: 1}, script.Environment{})
	defer h.Close()
	job := newJob()
	run := func() (script.Result, error) {
		return h.Run(context.Background(), job.Script, job.Input, job.Services)
	}
	footprint = 11
	for range 2 {
		if _, err := run(); !errors.Is(err, script.ErrLowMemory) {
			t.Fatalf("Run = %v, want preflight skip", err)
		}
	}
	if starts != 0 || purges != 0 {
		t.Fatalf("skipped runs started %d hosts and purged %d times", starts, purges)
	}
	footprint = 10
	if result, err := run(); err != nil || result.Action != script.ActionModify || result.URL == nil ||
		*result.URL != "https://example.org/new" {
		t.Fatalf("Run = %+v, %v", result, err)
	}
	overBudget = true
	if result, err := run(); !errors.Is(err, script.ErrMemoryExceeded) || result.Action != script.ActionPass {
		t.Fatalf("Run = %+v, %v, want memory budget failure", result, err)
	}
	footprint = 0
	if _, err := run(); !errors.Is(err, script.ErrCircuitOpen) {
		t.Fatalf("Run = %v, want open circuit", err)
	}
	if starts != 2 || purges != 1 {
		t.Fatalf("Start called %d times, Purge %d times", starts, purges)
	}
}
