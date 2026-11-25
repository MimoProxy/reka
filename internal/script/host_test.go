package script

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
	"unicode/utf8"
)

type fakeEngine struct {
	run   func(context.Context, *Job) (Done, error)
	purge func()
}

func (e fakeEngine) Run(ctx context.Context, job *Job) (Done, error) {
	return e.run(ctx, job)
}

func (e fakeEngine) Purge() {
	if e.purge != nil {
		e.purge()
	}
}

func newTestHost(t *testing.T, engine fakeEngine, limits Limits) *Host {
	t.Helper()
	h := NewHost(engine, limits, Environment{})
	t.Cleanup(h.Close)
	return h
}

func TestHostInterpretsDone(t *testing.T) {
	url, status := "https://example.com/rewritten", 203
	headers := []HeaderField{{"X-Test", "one"}, {"X-Test", "two"}}
	body := []byte("changed")
	response := &Response{Headers: headers, Body: body}
	modifiedHeaders := Result{Action: ActionModify, Headers: headers, HeadersSet: true}
	modifiedBody := Result{Action: ActionModify, Body: body, BodySet: true}
	responded := Result{Action: ActionRespond, Response: &Response{Status: 200, Headers: headers, Body: body}}
	for _, dialect := range []Dialect{"", DialectSurge, DialectLoon, DialectStash} {
		dialectName := string(dialect)
		if dialectName == "" {
			dialectName = "default"
		}
		for _, kind := range []Kind{KindHTTPRequest, KindHTTPResponse} {
			request := kind == KindHTTPRequest
			var noArgument, rewriteURL, rewriteStatus, directResponse Result
			if request {
				if dialect == DialectLoon || dialect == DialectStash {
					noArgument.Action = ActionAbort
				}
				rewriteURL = Result{Action: ActionModify, URL: &url}
				directResponse = responded
			} else {
				rewriteStatus = Result{Action: ActionModify, Status: status}
			}
			input := &Input{}
			if !request {
				input.Response = &Response{}
			}
			for _, tc := range []struct {
				name string
				done Done
				want Result
			}{
				{"no argument", Done{}, noArgument},
				{"empty object", Done{HasValue: true}, Result{}},
				{"url", Done{HasValue: true, URL: &url}, rewriteURL},
				{"status or statusCode", Done{HasValue: true, Status: &status}, rewriteStatus},
				{"headers", Done{HasValue: true, Headers: headers, HeadersSet: true}, modifiedHeaders},
				{"body", Done{HasValue: true, Body: body, BodySet: true}, modifiedBody},
				{"empty headers and body", Done{HasValue: true, HeadersSet: true, BodySet: true}, Result{
					Action: ActionModify, HeadersSet: true, BodySet: true,
				}},
				{"response", Done{HasValue: true, Response: response}, directResponse},
				{"abort", Done{HasValue: true, Abort: true, Response: response, URL: &url, BodySet: true}, Result{
					Action: ActionAbort,
				}},
			} {
				t.Run(dialectName+"/"+string(kind)+"/"+tc.name, func(t *testing.T) {
					done := tc.done
					done.Called = true
					h := newTestHost(t, fakeEngine{run: func(context.Context, *Job) (Done, error) {
						return done, nil
					}}, Limits{})
					result, err := h.Run(t.Context(), &Script{Kind: kind, Dialect: dialect}, input, Services{})
					if err != nil {
						t.Fatal(err)
					}
					result.Duration = 0
					if !reflect.DeepEqual(result, tc.want) {
						t.Fatalf("result = %#v, want %#v", result, tc.want)
					}
				})
			}
		}
	}
	if response.Status != 0 {
		t.Fatal("host mutated the engine response")
	}
}

func TestHostBackgroundDone(t *testing.T) {
	for _, kind := range []Kind{KindCron, KindGeneric, KindEvent} {
		t.Run(string(kind), func(t *testing.T) {
			value := json.RawMessage(`{"title":"Panel","content":"Example","abort":true}`)
			h := newTestHost(t, fakeEngine{run: func(_ context.Context, job *Job) (Done, error) {
				if job.Script.Kind != kind || job.Input.Response != nil {
					t.Errorf("unexpected background job: %+v", job)
				}
				return Done{Called: true, HasValue: true, Value: value, Abort: true, BodySet: true}, nil
			}}, Limits{})
			got, err := h.Run(t.Context(), &Script{Kind: kind}, &Input{}, Services{})
			if err != nil || got.Action != ActionPass || got.BodySet || got.ValueTruncated || string(got.Value) != string(value) {
				t.Fatalf("Run = %+v, %v", got, err)
			}
		})
	}
}

func TestHostTruncatesBackgroundValue(t *testing.T) {
	atLimit := `"` + strings.Repeat("a", maxDoneValue-2) + `"`
	overLimit := `{"content":"` + strings.Repeat(`<🌊\n`, maxDoneValue) + `"}`
	for _, tc := range []struct {
		name, value string
		truncated   bool
	}{
		{name: "at the limit", value: atLimit},
		{name: "oversized object", value: overLimit, truncated: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newTestHost(t, fakeEngine{run: func(context.Context, *Job) (Done, error) {
				return Done{Called: true, HasValue: true, Value: json.RawMessage(tc.value)}, nil
			}}, Limits{})
			got, err := h.Run(t.Context(), &Script{Kind: KindGeneric}, &Input{}, Services{})
			if err != nil || got.ValueTruncated != tc.truncated || len(got.Value) > maxDoneValue || !json.Valid(got.Value) {
				t.Fatalf("Run = %v with %d bytes, truncated = %t", err, len(got.Value), got.ValueTruncated)
			}
			if !tc.truncated {
				if string(got.Value) != tc.value {
					t.Fatal("value changed within limit")
				}
				return
			}
			var preview string
			if err := json.Unmarshal(got.Value, &preview); err != nil || !strings.HasPrefix(tc.value, preview) || preview == "" {
				t.Fatal("truncated value is missing a valid JSON prefix")
			}
		})
	}
}

func TestHostResponsePriority(t *testing.T) {
	url := "https://example.com/rewritten"
	response := &Response{Status: 204}
	done := Done{Called: true, HasValue: true, Response: response, URL: &url, HeadersSet: true, BodySet: true}
	h := newTestHost(t, fakeEngine{run: func(context.Context, *Job) (Done, error) {
		return done, nil
	}}, Limits{})
	got, err := h.Run(t.Context(), &Script{Kind: KindHTTPRequest}, &Input{}, Services{})
	if err != nil || got.Action != ActionRespond || got.Response == nil || got.Response.Status != 204 ||
		got.URL != nil || got.HeadersSet || got.BodySet {
		t.Fatalf("result = %#v, error = %v", got, err)
	}
}

func TestHostBodyLimit(t *testing.T) {
	for _, tc := range []struct {
		name       string
		maxSize    int64
		request    string
		response   string
		wantTooBig bool
	}{
		{"script limit", 2, "abc", "", true},
		{"response over script limit", 2, "", "abc", true},
		{"body at script limit", 2, "ab", "cd", false},
		{"script limit higher than hard limit", 5, "", "abcde", true},
		{"zero script limit", 0, "abcd", "efgh", false},
		{"zero script limit still bounded", 0, "abcde", "", true},
		{"negative script limit", -1, "abcd", "efgh", false},
		{"negative script limit still bounded", -1, "", "abcde", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls int
			h := newTestHost(t, fakeEngine{run: func(context.Context, *Job) (Done, error) {
				calls++
				return Done{Called: true}, nil
			}}, Limits{HardMaxSize: 4, BreakerFailures: 1})
			s := &Script{Kind: KindHTTPResponse, MaxSize: tc.maxSize}
			input := &Input{Request: Request{Body: []byte(tc.request)}, Response: &Response{Body: []byte(tc.response)}}
			_, err := h.Run(t.Context(), s, input, Services{})
			if tc.wantTooBig {
				if !errors.Is(err, ErrBodyTooLarge) || calls != 0 {
					t.Fatalf("oversized body returned %v after %d engine calls", err, calls)
				}
				input.Request.Body, input.Response.Body = nil, nil
				if _, err := h.Run(t.Context(), s, input, Services{}); err != nil {
					t.Fatalf("oversized body affected the circuit: %v", err)
				}
			} else if err != nil || calls != 1 {
				t.Fatalf("body within limit returned %v after %d engine calls", err, calls)
			}
		})
	}
}

func TestHostCircuitBreaker(t *testing.T) {
	var next Done
	var runErr error
	var calls int
	h := newTestHost(t, fakeEngine{run: func(context.Context, *Job) (Done, error) {
		calls++
		return next, runErr
	}}, Limits{BreakerFailures: 2, BreakerCooldown: time.Minute})
	now := time.Unix(100, 0)
	h.now = func() time.Time { return now }
	s := &Script{Kind: KindHTTPRequest, Source: "source"}
	check := func(want error) {
		t.Helper()
		if _, err := h.Run(t.Context(), s, &Input{}, Services{}); !errors.Is(err, want) {
			t.Fatalf("run error = %v, want %v", err, want)
		}
	}
	check(ErrNoDone)
	runErr = ErrTimeout
	check(ErrTimeout)
	check(ErrCircuitOpen)
	if calls != 2 {
		t.Fatalf("engine ran %d times while opening the circuit", calls)
	}
	now = now.Add(time.Minute)
	runErr = NewScriptError("sample", "Error: failed")
	check(runErr)
	check(ErrCircuitOpen)
	now = now.Add(time.Minute)
	runErr, next = nil, Done{Called: true}
	check(nil)
	runErr = ErrTimeout
	check(ErrTimeout)
	runErr = nil
	check(nil)
	runErr, next = nil, Done{}
	check(ErrNoDone)
	check(ErrNoDone)
	check(ErrCircuitOpen)
}

func TestHostMemoryErrorsAndCircuitBreaker(t *testing.T) {
	runErr := ErrLowMemory
	h := newTestHost(t, fakeEngine{run: func(context.Context, *Job) (Done, error) {
		return Done{Called: true}, runErr
	}}, Limits{BreakerFailures: 2, BreakerCooldown: time.Minute})
	now := time.Unix(100, 0)
	h.now = func() time.Time { return now }
	s := &Script{Kind: KindHTTPRequest, Source: "source"}
	check := func(want error) {
		t.Helper()
		if _, err := h.Run(t.Context(), s, &Input{}, Services{}); !errors.Is(err, want) {
			t.Fatalf("run error = %v, want %v", err, want)
		}
	}
	for range 3 {
		check(ErrLowMemory)
	}
	runErr = ErrMemoryExceeded
	check(ErrMemoryExceeded)
	runErr = ErrLowMemory
	check(ErrLowMemory)
	runErr = ErrMemoryExceeded
	check(ErrMemoryExceeded)
	check(ErrCircuitOpen)

	now = now.Add(time.Minute)
	runErr = ErrLowMemory
	check(ErrLowMemory)
	runErr = nil
	check(nil)
}

func TestHostCircuitIsScopedToCacheKey(t *testing.T) {
	h := newTestHost(t, fakeEngine{run: func(context.Context, *Job) (Done, error) {
		return Done{}, ErrNoDone
	}}, Limits{BreakerFailures: 1})
	check := func(key, source string, want error) {
		t.Helper()
		s := &Script{Kind: KindHTTPRequest, Key: key, Source: source}
		if _, err := h.Run(t.Context(), s, &Input{}, Services{}); !errors.Is(err, want) {
			t.Fatalf("key %q, source %q: error = %v, want %v", key, source, err, want)
		}
	}
	check("shared", "old", ErrNoDone)
	check("shared", "new", ErrCircuitOpen)
	check("other", "old", ErrNoDone)
	check("", "old", ErrNoDone)
	check("", "old", ErrCircuitOpen)
	check("", "new", ErrNoDone)
}

func TestHostCircuitRejectsStaleRunAndAllowsOneTrial(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	h := newTestHost(t, fakeEngine{run: func(ctx context.Context, _ *Job) (Done, error) {
		switch calls.Add(1) {
		case 1, 3:
			started <- struct{}{}
			select {
			case <-release:
			case <-ctx.Done():
				return Done{}, ctx.Err()
			}
		case 2:
			return Done{}, ErrTimeout
		}
		return Done{Called: true}, nil
	}}, Limits{Concurrency: 2, BreakerFailures: 1, BreakerCooldown: time.Minute})
	now := time.Unix(100, 0)
	h.now = func() time.Time { return now }
	run := func() error {
		_, err := h.Run(t.Context(), &Script{Kind: KindHTTPRequest}, &Input{}, Services{})
		return err
	}
	async := make(chan error, 1)
	go func() { async <- run() }()
	<-started
	if err := run(); !errors.Is(err, ErrTimeout) {
		t.Fatalf("opening failure = %v", err)
	}
	release <- struct{}{}
	if err := <-async; err != nil {
		t.Fatalf("previously admitted run = %v", err)
	}
	if err := run(); !errors.Is(err, ErrCircuitOpen) {
		t.Fatalf("run after a stale success = %v", err)
	}
	now = now.Add(time.Minute)
	go func() { async <- run() }()
	<-started
	if err := run(); !errors.Is(err, ErrCircuitOpen) {
		t.Fatalf("concurrent trial returned %v", err)
	}
	release <- struct{}{}
	if err := <-async; err != nil {
		t.Fatalf("trial returned %v", err)
	}
	if err := run(); err != nil {
		t.Fatalf("run after successful trial returned %v", err)
	}
}

func TestHostConcurrencyQueueTimeout(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	h := newTestHost(t, fakeEngine{run: func(ctx context.Context, _ *Job) (Done, error) {
		if calls.Add(1) == 1 {
			close(started)
			select {
			case <-release:
			case <-ctx.Done():
				return Done{}, ctx.Err()
			}
		}
		return Done{Called: true}, nil
	}}, Limits{Concurrency: 1, BreakerFailures: 1})
	first := make(chan error, 1)
	go func() {
		_, err := h.Run(t.Context(), &Script{Kind: KindHTTPRequest}, &Input{}, Services{})
		first <- err
	}()
	<-started
	s := &Script{Kind: KindHTTPRequest, Timeout: 25 * time.Millisecond}
	_, err := h.Run(t.Context(), s, &Input{}, Services{})
	close(release)
	if !errors.Is(err, ErrBusy) || calls.Load() != 1 {
		t.Fatalf("queued run returned %v after %d engine calls", err, calls.Load())
	}
	if err := <-first; err != nil {
		t.Fatalf("first run = %v", err)
	}
	if _, err := h.Run(t.Context(), s, &Input{}, Services{}); err != nil {
		t.Fatalf("queue timeout affected the circuit or slot: %v", err)
	}
}

func TestHostCanceledQueuedRunDoesNotReadSource(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		started, release := make(chan struct{}), make(chan struct{})
		defer close(release)
		h := newTestHost(t, fakeEngine{run: func(ctx context.Context, job *Job) (Done, error) {
			if job.Script.Key != "running" {
				t.Errorf("unexpected engine run for %q", job.Script.Key)
				return Done{Called: true}, nil
			}
			close(started)
			select {
			case <-release:
				return Done{Called: true}, nil
			case <-ctx.Done():
				return Done{}, ctx.Err()
			}
		}}, Limits{Concurrency: 1})
		go func() {
			if _, err := h.Run(t.Context(), &Script{Kind: KindGeneric, Key: "running"}, &Input{}, Services{}); err != nil {
				t.Errorf("running script: %v", err)
			}
		}()
		<-started
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		result := make(chan error, 1)
		go func() {
			_, err := h.RunWithSource(ctx, &Script{Kind: KindCron, Key: "queued"}, &Input{}, Services{}, func(key string) ([]byte, error) {
				t.Errorf("read source for queued script %q", key)
				return []byte("$done()"), nil
			})
			result <- err
		}()
		synctest.Wait()
		cancel()
		if err := <-result; !errors.Is(err, ErrBusy) {
			t.Fatalf("queued run returned %v, want %v", err, ErrBusy)
		}
	})
}

func TestHostRunsWithLockedSource(t *testing.T) {
	const key, source = "locked", "$done()"
	var calls int
	h := newTestHost(t, fakeEngine{run: func(_ context.Context, job *Job) (Done, error) {
		calls++
		if job.Script.Key != key || job.Script.Source != source {
			t.Errorf("loaded script = %+v", job.Script)
		}
		return Done{Called: true}, nil
	}}, Limits{BreakerFailures: 1})
	spec := &Script{Kind: KindGeneric, Key: key}
	readErr := errors.New("source unavailable")
	_, err := h.RunWithSource(t.Context(), spec, &Input{}, Services{}, func(string) ([]byte, error) {
		return nil, readErr
	})
	if !errors.Is(err, readErr) || calls != 0 {
		t.Fatalf("failed read returned %v after %d engine calls", err, calls)
	}
	read := func(got string) ([]byte, error) {
		if got != key {
			t.Errorf("source key = %q, want %q", got, key)
		}
		return []byte(source), nil
	}
	if _, err := h.RunWithSource(t.Context(), spec, &Input{}, Services{}, read); err != nil || calls != 1 || spec.Source != "" {
		t.Fatalf("successful read returned %v after %d engine calls, script = %+v", err, calls, spec)
	}
	spec.Key = ""
	if _, err := h.RunWithSource(t.Context(), spec, &Input{}, Services{}, read); err == nil || calls != 1 {
		t.Fatalf("missing key returned %v after %d engine calls", err, calls)
	}
}

func TestPurgeAllUnregistersClosedHosts(t *testing.T) {
	var first, second int
	h1 := newTestHost(t, fakeEngine{purge: func() { first++ }}, Limits{})
	h2 := newTestHost(t, fakeEngine{purge: func() { second++ }}, Limits{})
	PurgeAll()
	if first != 1 || second != 1 {
		t.Fatalf("purge counts = (%d, %d), want (1, 1)", first, second)
	}
	h1.Close()
	PurgeAll()
	if first != 1 || second != 2 {
		t.Fatalf("purge counts after close = (%d, %d), want (1, 2)", first, second)
	}
	h2.Purge()
	if second != 3 {
		t.Fatalf("direct purge count = %d, want 3", second)
	}
}

func TestPurgeAllAllowsHostToUnregisterDuringPurge(t *testing.T) {
	var h *Host
	var calls int
	h = newTestHost(t, fakeEngine{purge: func() {
		if !liveHosts.TryLock() {
			t.Error("purge callback ran with the host registry locked")
			return
		}
		liveHosts.Unlock()
		h.Close()
		calls++
	}}, Limits{})
	PurgeAll()
	PurgeAll()
	if calls != 1 {
		t.Fatalf("purge callback ran %d times", calls)
	}
}

func TestHostValidatesAndFillsDefaults(t *testing.T) {
	var calls int
	h := newTestHost(t, fakeEngine{run: func(ctx context.Context, job *Job) (Done, error) {
		calls++
		if job.Env.System == "" || job.Env.SurgeVersion != DefaultSurgeVersion ||
			job.Env.SurgeBuild != DefaultSurgeBuild || job.Env.Language != "en" {
			t.Errorf("environment defaults = %+v", job.Env)
		}
		limits := job.Limits
		if limits.UngzipMax != 128 || limits.HardMaxSize != 128 || limits.CacheBytes != 32<<20 || limits.Concurrency != 2 {
			t.Errorf("limits = %+v", limits)
		}
		if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) <= 0 || time.Until(deadline) > DefaultTimeout {
			t.Errorf("deadline = %v, present = %v", deadline, ok)
		}
		return Done{Called: true}, nil
	}}, Limits{HardMaxSize: 128})
	if _, err := h.Run(t.Context(), &Script{Kind: KindHTTPResponse}, &Input{}, Services{}); err == nil || calls != 0 {
		t.Fatalf("response script without response returned %v after %d engine calls", err, calls)
	}
	if _, err := h.Run(t.Context(), &Script{Kind: KindHTTPRequest}, &Input{}, Services{}); err != nil || calls != 1 {
		t.Fatalf("valid script returned %v after %d engine calls", err, calls)
	}
}

func TestScriptCacheKey(t *testing.T) {
	s := Script{Source: "abc"}
	const digest = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	if got := s.CacheKey(); got != digest {
		t.Errorf("source cache key = %q, want %q", got, digest)
	}
	s.Key = "configured-key"
	if got := s.CacheKey(); got != s.Key {
		t.Errorf("explicit cache key = %q, want %q", got, s.Key)
	}
}

func TestScriptErrorKeepsBoundedFirstLine(t *testing.T) {
	var exception *ScriptError
	err := NewScriptError("sample", "Error: first\nframe")
	if !errors.As(err, &exception) || exception.Name != "sample" || exception.Message != "Error: first" {
		t.Fatalf("exception = %#v", exception)
	}
	line := NewScriptError("sample", strings.Repeat("界", 1024)).Message
	if !utf8.ValidString(line) || len(line) > 1024 || len(line) == 0 {
		t.Fatalf("truncated exception length = %d, valid UTF-8 = %v", len(line), utf8.ValidString(line))
	}
}
