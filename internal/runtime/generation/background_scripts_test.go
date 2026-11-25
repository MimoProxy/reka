package generation

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/MimoProxy/reka/internal/backend/sagernet"
	"github.com/MimoProxy/reka/internal/config/compile"
	"github.com/MimoProxy/reka/internal/resource"
	"github.com/MimoProxy/reka/internal/script"
)

type fakeScriptTimer struct {
	callback func()
}

func (t *fakeScriptTimer) Stop() bool {
	active := t.callback != nil
	t.callback = nil
	return active
}

type fakeScriptClock struct {
	now   time.Time
	delay time.Duration
	timer *fakeScriptTimer
}

func (c *fakeScriptClock) clock() *scriptSchedulerClock {
	return &scriptSchedulerClock{now: func() time.Time { return c.now }, afterFunc: func(delay time.Duration, cb func()) scriptTimer {
		c.delay = delay
		c.timer = &fakeScriptTimer{callback: cb}
		return c.timer
	}}
}

func (c *fakeScriptClock) advance(d time.Duration) {
	c.now = c.now.Add(d)
	if c.timer != nil && c.timer.callback != nil && d >= c.delay {
		callback := c.timer.callback
		c.timer.Stop()
		callback()
	} else {
		c.delay -= d
	}
}

type backgroundTestEngine func(context.Context, *script.Job) (script.Done, error)

func (f backgroundTestEngine) Run(ctx context.Context, job *script.Job) (script.Done, error) {
	return f(ctx, job)
}

func (backgroundTestEngine) Purge() {}

func activateScriptTestProfile(t *testing.T, e *Engine, revision uint64, source string, log bool, defs ...compile.Script) {
	t.Helper()
	eff, diagnostics := compile.Compile([]byte("schema-version: 1\n"), nil, compile.Options{})
	if diagnostics.HasErrors() {
		t.Fatal(diagnostics)
	}
	hash := resource.Hash([]byte(source))
	for i := range defs {
		defs[i].Hash = hash
	}
	eff.Scripts = defs
	eff.MITM.ScriptLog = log
	p, err := e.Prepare(eff)
	if err != nil {
		t.Fatal(err)
	}
	p.SetScriptSourceReader(func(key string) ([]byte, error) {
		if key != hash {
			return nil, resource.ErrCorrupt
		}
		return []byte(source), nil
	})
	if _, err := e.Activate(p, revision); err != nil {
		t.Fatal(err)
	}
}

func backgroundTestOptions(fake backgroundTestEngine) (EngineOptions, *fakeScriptClock) {
	clock := &fakeScriptClock{now: time.Date(2026, time.January, 3, 12, 0, 0, 0, time.FixedZone("local", 9*60*60))}
	return EngineOptions{ScriptEngine: func() script.Engine { return fake }, scriptClock: clock.clock()}, clock
}

func awaitScriptTestSignal[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case value := <-ch:
		return value
	case <-time.After(5 * time.Second):
		t.Fatal("script did not enter the engine")
		var zero T
		return zero
	}
}

func TestBackgroundCronScheduleAndOverlap(t *testing.T) {
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	opts, clock := backgroundTestOptions(func(ctx context.Context, _ *script.Job) (script.Done, error) {
		entered <- struct{}{}
		select {
		case <-release:
			return script.Done{Called: true, Value: json.RawMessage(`{"ok":true}`)}, nil
		case <-ctx.Done():
			return script.Done{}, ctx.Err()
		}
	})
	e := NewEngine(opts)
	t.Cleanup(e.Close)
	def := compile.Script{ID: "tick", Type: "cron", Supported: true, CronExp: "*/2 * * * *", Timeout: 60}
	activateScriptTestProfile(t, e, 1, "old source", false, def)
	first := e.ListScripts().Scripts[0]
	if first.NextRun == nil || first.NextRun.Location() != clock.now.Location() || !first.NextRun.Equal(clock.now.Add(2*time.Minute)) || clock.delay != time.Minute {
		t.Fatalf("initial schedule = %+v, alarm delay = %v", first, clock.delay)
	}
	clock.advance(time.Minute)
	if runs := e.GetScriptRuns("", 0); len(runs) != 0 {
		t.Fatalf("early trigger = %+v", runs)
	}
	clock.advance(time.Minute)
	awaitScriptTestSignal(t, entered)
	if got := e.GetScriptRuns("tick", 0); len(got) != 1 || got[0].Result != "running" || got[0].Trigger != "cron" || !got[0].StartedAt.Equal(clock.now) {
		t.Fatalf("running cron = %+v", got)
	}
	clock.advance(2 * time.Minute)
	clock.advance(4*time.Minute + time.Second)
	info := e.ListScripts().Scripts[0]
	if got := e.GetScriptRuns("tick", 0); len(got) != 2 || got[0].Result != "overlap" || got[0].Trigger != "cron" || !info.Running {
		t.Fatalf("cron overlap and missed triggers = %+v, running = %v", got, info.Running)
	}
	if info.NextRun == nil || !info.NextRun.Equal(clock.now.Add(2*time.Minute-time.Second)) {
		t.Fatalf("next run after wake = %v", info.NextRun)
	}
	staleCallback := clock.timer.callback
	activateScriptTestProfile(t, e, 2, "replacement", false, compile.Script{ID: "manual", Type: "generic", Supported: true})
	staleCallback()
	if list := e.ListScripts(); list.Status != "enabled" || len(list.Scripts) != 1 || list.Scripts[0].ID != "manual" || list.Scripts[0].NextRun != nil {
		t.Fatalf("generation schedule = %+v", list)
	}
	close(release)
	e.backgroundScripts.workers.Wait()
	if got := e.GetScriptRuns("tick", 0); len(got) != 2 || got[0].Result != "overlap" || got[1].Result != "done" || string(got[1].Value) != `{"ok":true}` {
		t.Fatalf("retired script runs = %+v", got)
	}
}

func TestBackgroundNetworkEvents(t *testing.T) {
	opts, clock := backgroundTestOptions(func(context.Context, *script.Job) (script.Done, error) {
		return script.Done{Called: true}, nil
	})
	e := NewEngine(opts)
	t.Cleanup(e.Close)
	activateScriptTestProfile(t, e, 1, "event", false,
		compile.Script{ID: "one", Type: "event", Supported: true, EventName: "network-changed"},
		compile.Script{ID: "two", Type: "event", Supported: true, EventName: "network-changed"},
		compile.Script{ID: "other", Type: "event", EventName: "wake"})
	observe := func(obs *sceneObservation) {
		e.mu.Lock()
		defer e.mu.Unlock()
		e.observeScriptNetwork(obs)
	}
	a := netip.MustParseAddr("192.0.2.10")
	b := netip.MustParseAddr("2001:db8::1")
	observe(&sceneObservation{name: "en0", addresses: []netip.Addr{a, b}})
	observe(&sceneObservation{name: "en0", addresses: []netip.Addr{b, a, a}})
	if clock.timer != nil {
		t.Fatal("first observation or address reordering triggered an event")
	}
	observe(&sceneObservation{err: "default network unavailable"})
	clock.advance(networkEventDelay / 2)
	e.NotifyNetworkChanged()
	e.NotifyNetworkChanged()
	if runs := e.GetScriptRuns("", 0); len(runs) != 0 {
		t.Fatalf("early event = %+v", runs)
	}
	clock.advance(networkEventDelay / 2)
	e.backgroundScripts.workers.Wait()
	if runs := e.GetScriptRuns("", 0); len(runs) != 2 || runs[0].ID != "two" || runs[1].ID != "one" ||
		runs[0].Event != "network-changed" || runs[1].Trigger != "event" || runs[0].Result != "done" {
		t.Fatalf("coalesced network event = %+v", runs)
	}
	observe(&sceneObservation{err: "different error"})
	if clock.timer.callback != nil {
		t.Fatal("two unavailable observations triggered an event")
	}
	observe(&sceneObservation{name: "en0", addresses: []netip.Addr{a, b}})
	clock.advance(networkEventDelay)
	e.backgroundScripts.workers.Wait()
	if runs := e.GetScriptRuns("", 0); len(runs) != 4 || runs[0].Event != "network-changed" {
		t.Fatalf("recovered network event = %+v", runs)
	}
}

func TestBackgroundManualScriptArgumentsAndGenerationRouting(t *testing.T) {
	jobs := make(chan *script.Job, 1)
	resume := make(chan struct{})
	opts, _ := backgroundTestOptions(func(ctx context.Context, job *script.Job) (script.Done, error) {
		if job.Script.Source == "original" {
			jobs <- job
			select {
			case <-resume:
			case <-ctx.Done():
				return script.Done{}, ctx.Err()
			}
			_, err := job.Services.HTTP.Do(ctx, &script.HTTPRequest{Method: "GET", URL: "ftp://example.test/"})
			if err == nil || !strings.Contains(err.Error(), "requires an HTTP or HTTPS URL") {
				return script.Done{}, errors.New("old generation could not prepare HTTP request")
			}
		}
		value, err := json.Marshal(*job.Script.Argument)
		return script.Done{Called: true, Value: value}, err
	})
	e := NewEngine(opts)
	t.Cleanup(e.Close)
	manual := compile.Script{ID: "widget", Type: "generic", Supported: true, Argument: "default"}
	activateScriptTestProfile(t, e, 1, "original", false, manual,
		compile.Script{ID: "http", Type: "http-request", Supported: true, Pattern: ".*"}, compile.Script{ID: "dns", Type: "dns"})
	for id, message := range map[string]string{"http": "cannot run manually", "dns": "unsupported"} {
		if _, err := e.RunScript(t.Context(), id, nil, true); err == nil || !strings.Contains(err.Error(), message) {
			t.Fatalf("run %s: %v", id, err)
		}
	}
	if _, err := e.RunScript(t.Context(), "missing", nil, true); !errors.Is(err, ErrScriptNotFound) {
		t.Fatalf("unknown script error = %v", err)
	}
	argument := ""
	async, err := e.RunScript(t.Context(), "widget", &argument, false)
	if err != nil || async.Result != "running" || async.Name != "widget" || async.Trigger != "manual" {
		t.Fatalf("async run = %+v, %v", async, err)
	}
	argument = "changed after admission"
	job := awaitScriptTestSignal(t, jobs)
	client := job.Services.HTTP.(scriptHTTPClient)
	if client.snapshot.Value.(*generation).revision != 1 || job.Script.Argument == nil || *job.Script.Argument != "" {
		t.Fatalf("captured generation or argument = %+v", job.Script)
	}
	activateScriptTestProfile(t, e, 2, "replacement", false, manual)
	overlap, err := e.RunScript(t.Context(), "widget", nil, true)
	if err != nil || overlap.Result != "overlap" || !e.ListScripts().Scripts[0].Running {
		t.Fatalf("overlap across activation = %+v, %v", overlap, err)
	}
	close(resume)
	e.backgroundScripts.workers.Wait()
	if runs := e.GetScriptRuns("widget", 0); len(runs) != 2 || runs[1].Result != "done" || string(runs[1].Value) != `""` ||
		e.ListScripts().Scripts[0].LastRun.RunID != overlap.RunID {
		t.Fatalf("manual history = %+v", runs)
	}
	completed, err := e.RunScript(t.Context(), "widget", nil, true)
	if err != nil || completed.Result != "done" || string(completed.Value) != `"default"` {
		t.Fatalf("synchronous run = %+v, %v", completed, err)
	}
}

func TestBackgroundScriptHistoryAndLogLimits(t *testing.T) {
	var debug bytes.Buffer
	opts, _ := backgroundTestOptions(func(_ context.Context, job *script.Job) (script.Done, error) {
		job.Services.Log("info", "message")
		for range scriptLogLines {
			job.Services.Log("debug", "line")
		}
		return script.Done{Called: true, Value: json.RawMessage(`true`)}, nil
	})
	opts.Backend = sagernet.Options{Logger: slog.New(slog.NewTextHandler(&debug, &slog.HandlerOptions{Level: slog.LevelDebug}))}
	e := NewEngine(opts)
	t.Cleanup(e.Close)
	manual := compile.Script{ID: "widget", Type: "generic", Supported: true}
	activateScriptTestProfile(t, e, 1, "source", true, manual)
	run, err := e.RunScript(t.Context(), "widget", nil, true)
	if err != nil || len(run.Logs) != scriptLogLines || !run.LogsTruncated || run.Logs[0].Message != "message" {
		t.Fatalf("console capture = %d lines, truncated %v, %v", len(run.Logs), run.LogsTruncated, err)
	}
	summary := e.ListScripts().Scripts[0].LastRun
	if summary == nil || len(summary.Value) != 0 || len(summary.Logs) != 0 || summary.RunID != run.RunID {
		t.Fatalf("last run summary = %+v", summary)
	}
	if !strings.Contains(debug.String(), "script widget: message") || !strings.Contains(debug.String(), "result=done") {
		t.Fatalf("backend logs = %s", &debug)
	}
	run.Value[0] = 'x'
	run.Logs[0].Message = "changed"
	if recorded := e.GetScriptRuns("widget", 1)[0]; string(recorded.Value) != `true` || recorded.Logs[0].Message != "message" {
		t.Fatalf("returned run mutated retained history: %+v", recorded)
	}
	activateScriptTestProfile(t, e, 2, "source", false, manual)
	debug.Reset()
	for range scriptRunCapacity + 3 {
		if _, err := e.RunScript(t.Context(), "widget", nil, true); err != nil {
			t.Fatal(err)
		}
	}
	if runs := e.GetScriptRuns("", 999); len(runs) != scriptRunCapacity || runs[0].RunID-runs[len(runs)-1].RunID != uint64(scriptRunCapacity-1) || runs[len(runs)-1].RunID != 5 {
		t.Fatalf("history length = %d, unexpected bounds", len(runs))
	}
	if runs := e.GetScriptRuns("widget", 0); len(runs) != min(scriptRunDefault, scriptRunCapacity) {
		t.Fatalf("default history limit = %d", len(runs))
	}
	if runs := e.GetScriptRuns("missing", 0); len(runs) != 0 || strings.Contains(debug.String(), "script widget: message") {
		t.Fatalf("filtered history = %+v, debug logging enabled = %v", runs, strings.Contains(debug.String(), "script widget: message"))
	}
	var capture backgroundScriptLogs
	capture.append("info", strings.Repeat("x", scriptLogBytes-len("info")))
	capture.append("info", "overflow")
	if lines, truncated := capture.finish(); len(lines) != 1 || !truncated {
		t.Fatalf("byte limit = %d lines, truncated %v", len(lines), truncated)
	}
}

func TestBackgroundScriptsCloseAndUnsupported(t *testing.T) {
	entered := make(chan struct{})
	opts, clock := backgroundTestOptions(func(ctx context.Context, _ *script.Job) (script.Done, error) {
		close(entered)
		<-ctx.Done()
		return script.Done{}, ctx.Err()
	})
	e := NewEngine(opts)
	t.Cleanup(e.Close)
	manual := compile.Script{ID: "widget", Type: "generic", Supported: true}
	activateScriptTestProfile(t, e, 1, "source", false, manual,
		compile.Script{ID: "cron", Type: "cron", Supported: true, CronExp: "* * * * *"},
		compile.Script{ID: "event", Type: "event", Supported: true, EventName: "network-changed"})
	if _, err := e.RunScript(t.Context(), "widget", nil, false); err != nil {
		t.Fatal(err)
	}
	awaitScriptTestSignal(t, entered)
	e.NotifyNetworkChanged()
	staleCallback := clock.timer.callback
	e.Close()
	clock.advance(time.Minute)
	staleCallback()
	e.NotifyNetworkChanged()
	if runs := e.GetScriptRuns("", 0); len(runs) != 1 || runs[0].Result != "failed" || runs[0].Error != context.Canceled.Error() {
		t.Fatalf("closed engine runs = %+v", runs)
	}
	if list := e.ListScripts(); list.Status != "disabled" || list.Scripts[1].NextRun != nil || list.Scripts[0].Running {
		t.Fatalf("closed engine scripts = %+v", list)
	}
	unsupported := NewEngine(EngineOptions{ScriptEngine: func() script.Engine { return nil }})
	t.Cleanup(unsupported.Close)
	activateScriptTestProfile(t, unsupported, 1, "source", false, manual)
	run, err := unsupported.RunScript(t.Context(), "widget", nil, true)
	if list := unsupported.ListScripts(); list.Status != "unsupported" || err == nil || run.Result != "unsupported" {
		t.Fatalf("no engine: list = %+v, run = %+v, err = %v", list, run, err)
	}
}

func TestBackgroundScriptOutcome(t *testing.T) {
	for err, want := range map[error]string{
		nil: "done", script.ErrNoDone: "no-done", script.ErrTimeout: "timeout", script.ErrCircuitOpen: "circuit-open",
		script.ErrBusy: "busy", script.ErrLowMemory: "low-memory", script.ErrMemoryExceeded: "low-memory",
	} {
		if result, _ := scriptRunOutcome(err); result != want {
			t.Fatalf("outcome for %v = %s, want %s", err, result, want)
		}
	}
}
