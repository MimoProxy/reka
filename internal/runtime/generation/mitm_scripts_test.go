package generation

import (
	"bytes"
	"context"
	"log/slog"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/MimoProxy/reka/internal/api"
	"github.com/MimoProxy/reka/internal/backend/sagernet"
	"github.com/MimoProxy/reka/internal/config/compile"
	"github.com/MimoProxy/reka/internal/resource"
	"github.com/MimoProxy/reka/internal/runtime"
	"github.com/MimoProxy/reka/internal/script"
)

func TestMITMScriptTableOrder(t *testing.T) {
	const request, response = string(script.KindHTTPRequest), string(script.KindHTTPResponse)
	var logs bytes.Buffer
	table := newMITMScriptTable([]compile.Script{
		{ID: "unsupported", Type: request, Pattern: ".*"},
		{ID: "non-http", Supported: true, Type: "event", Pattern: ".*"},
		{ID: "bad-pattern", Supported: true, Type: request, Pattern: "("},
		{ID: "response", Supported: true, Type: response, Pattern: "example[.]test", ArgumentType: "object", Argument: `{"enabled":true}`},
		{ID: "first", Supported: true, Type: request, Pattern: "/path$", Argument: "sample", Name: "First",
			Path: "https://scripts.test/sample.js", Hash: "hash", Format: "loon", RequiresBody: true,
			Engine: "webview", BinaryBodyMode: true, Timeout: 4, MaxSize: 128},
		{ID: "fallback", Supported: true, Type: request, Pattern: "example[.]test"},
	}, slog.New(slog.NewTextHandler(&logs, nil)))
	if table.count() != 3 || !strings.Contains(logs.String(), "bad-pattern") {
		t.Fatalf("entries = %d, diagnostics = %s", table.count(), &logs)
	}
	const url = "https://example.test/path"
	first := table.match(script.KindHTTPRequest, url)
	if first == nil || first.id != "first" || !first.requiresBody {
		t.Fatalf("first request match = %+v", first)
	}
	s := first.spec
	if s.Name != "First" || s.Key != "hash" || s.Path != "https://scripts.test/sample.js" ||
		s.Source != "" || s.Dialect != script.DialectLoon || s.Engine != "webview" || !s.BinaryBody ||
		s.Argument == nil || *s.Argument != "sample" || s.Timeout != 4*time.Second || s.MaxSize != 128 {
		t.Fatalf("script = %+v", s)
	}
	if got := table.match(script.KindHTTPRequest, "https://example.test/other"); got == nil ||
		got.id != "fallback" || got.spec.Name != "fallback" || got.spec.Path != "fallback" || got.spec.Argument != nil {
		t.Fatalf("fallback request match = %+v", got)
	}
	if got := table.match(script.KindHTTPResponse, url); got == nil || got.id != "response" || !got.spec.ArgumentObject ||
		got.spec.Argument == nil || *got.spec.Argument != `{"enabled":true}` {
		t.Fatalf("response match = %+v", got)
	}
	if got := table.match(script.KindHTTPRequest, "https://other.test/other"); got != nil {
		t.Fatalf("unexpected script = %+v", got)
	}
}

type testScriptEngine struct {
	run func(*script.Job)
}

func (e testScriptEngine) Run(_ context.Context, job *script.Job) (script.Done, error) {
	if e.run != nil {
		e.run(job)
	}
	return script.Done{Called: true}, nil
}

func (testScriptEngine) Purge() {}

func TestScriptStateDir(t *testing.T) {
	dir := t.TempDir()
	e := NewEngine(EngineOptions{
		ScriptStateDir: dir, ScriptEngine: func() script.Engine { return testScriptEngine{} },
	})
	t.Cleanup(e.Close)
	if got, want := e.scriptStore.path, filepath.Join(dir, "scripts", "store.json"); got != want || e.takeover != nil {
		t.Fatalf("script store path = %q, want %q, network takeover = %v", got, want, e.takeover != nil)
	}
}

func TestMITMScriptSourceReaderFollowsGeneration(t *testing.T) {
	var latestSource string
	engine := NewEngine(EngineOptions{ScriptEngine: func() script.Engine {
		return testScriptEngine{run: func(job *script.Job) { latestSource = job.Script.Source }}
	}})
	t.Cleanup(engine.Close)
	activate := func(revision uint64, source string) *runtime.Snapshot[*sagernet.Outbound] {
		t.Helper()
		eff, diagnostics := compile.Compile([]byte("schema-version: 1\n"), nil, compile.Options{})
		if diagnostics.HasErrors() {
			t.Fatal(diagnostics)
		}
		hash := resource.Hash([]byte(source))
		eff.Scripts = []compile.Script{{
			ID: "sample", Type: string(script.KindHTTPRequest), Supported: true, Pattern: ".*", Hash: hash,
		}}
		p, err := engine.Prepare(eff)
		if err != nil {
			t.Fatal(err)
		}
		p.SetScriptSourceReader(func(key string) ([]byte, error) {
			if key != hash {
				return nil, resource.ErrCorrupt
			}
			return []byte(source), nil
		})
		if _, err := engine.Activate(p, revision); err != nil {
			t.Fatal(err)
		}
		snap, _ := engine.current()
		return snap
	}
	const before, after = "$done({})", "$done()"
	old := activate(1, before)
	current := activate(2, after)
	check := func(snap *runtime.Snapshot[*sagernet.Outbound], want string) {
		t.Helper()
		match := engine.mitmScriptMatcher(snap, routingState{})(script.KindHTTPRequest, "https://example.test/")
		if match == nil || match.Run == nil {
			t.Fatal("script did not match")
		}
		if _, err := match.Run(t.Context(), &script.Input{}); err != nil || latestSource != want {
			t.Fatalf("script source = %q, want %q, error = %v", latestSource, want, err)
		}
	}
	check(old, before)
	check(current, after)
}

func TestMITMScriptStatusItemsAcrossGenerations(t *testing.T) {
	const request, response = string(script.KindHTTPRequest), string(script.KindHTTPResponse)
	e := NewEngine(EngineOptions{ScriptEngine: func() script.Engine { return testScriptEngine{} }})
	t.Cleanup(e.Close)
	activate := func(defs ...compile.Script) {
		t.Helper()
		eff := &compile.Effective{MITM: compile.MITM{Enabled: true}}
		g := &generation{eff: eff, scripts: newMITMScriptTable(defs, e.scriptLogger())}
		if _, err := e.rt.CommitValue(nil, g); err != nil {
			t.Fatal(err)
		}
	}
	keep := compile.Script{ID: "keep", Name: "Keep", Module: "module", Supported: true, Type: request, Pattern: ".*"}
	remove := compile.Script{ID: "remove", Supported: true, Type: response, Pattern: ".*"}
	activate(keep, remove)
	e.scriptRuns.record(api.MITMScriptRun{ID: "keep", Result: "low-memory"}, false)
	e.scriptRuns.record(api.MITMScriptRun{ID: "keep", Result: "low-memory"}, true)
	e.scriptRuns.record(api.MITMScriptRun{ID: "keep", Result: "failed", Error: "failed to run", DurationMS: 3}, true)
	e.scriptRuns.record(api.MITMScriptRun{ID: "remove", Result: "modified"}, true)
	keep.Name = "Updated"
	add := compile.Script{ID: "new", Supported: true, Type: response, Pattern: ".*"}
	activate(add, keep)

	got := e.MITMStatus().Scripts
	if got.Status != "enabled" || got.Count != 2 || got.Runs != 3 || got.LowMemory != 2 ||
		got.Modified != 1 || got.Failed != 1 || len(got.Items) != 2 {
		t.Fatalf("script status = %+v", got)
	}
	if item := got.Items[0]; item.ID != "keep" || item.Name != "Updated" || item.Type != request ||
		item.Module != "module" || item.Matches != 3 || item.Runs != 2 || item.LastResult != "failed" ||
		item.LastError != "failed to run" || item.LastDurationMS != 3 || item.LastAt.IsZero() {
		t.Fatalf("retained script = %+v", item)
	}
	if item := got.Items[1]; item.ID != "new" || item.Type != response || item.Matches != 0 ||
		item.Runs != 0 || item.LastResult != "" || !item.LastAt.IsZero() {
		t.Fatalf("new script = %+v", item)
	}
}

func TestMITMScriptStatusBoundsRetainedItems(t *testing.T) {
	var counters mitmScriptCounters
	for i := range mitmScriptItemCapacity {
		counters.record(api.MITMScriptRun{ID: strconv.Itoa(i)}, true)
	}
	counters.record(api.MITMScriptRun{ID: "0"}, true)
	counters.record(api.MITMScriptRun{ID: "new"}, true)
	if len(counters.items) != mitmScriptItemCapacity || counters.items["1"] != nil || counters.items["0"] == nil {
		t.Fatal("diagnostic history did not evict its least recently used entry")
	}
}
