//go:build with_gvisor

package packettunnel

import (
	"context"
	"encoding/json"
	"log/slog"
	"testing"
	"testing/synctest"
	"time"

	"github.com/MimoProxy/reka/internal/api"
	"github.com/MimoProxy/reka/internal/config/compile"
	"github.com/MimoProxy/reka/internal/resource"
	"github.com/MimoProxy/reka/internal/runtime/generation"
	"github.com/MimoProxy/reka/internal/script"
)

func TestScriptOperationsRequireProfile(t *testing.T) {
	session := &Session{ctx: t.Context()}
	for _, action := range []string{"scripts", "runScript", "scriptRuns"} {
		if _, err := session.RunOperation(Operation{Action: action}); err == nil || err.Error() != "the operation requires a profile" {
			t.Errorf("%s = %v", action, err)
		}
	}
}

func TestPacketTunnelScriptOperations(t *testing.T) {
	session := scriptOperationSession(t, compile.Script{ID: "sample", Type: "generic", Argument: "configured"})
	call := func(raw string) any {
		t.Helper()
		var op Operation
		if err := json.Unmarshal([]byte(raw), &op); err != nil {
			t.Fatal(err)
		}
		result, err := session.RunOperation(op)
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	list := call(`{"action":"scripts"}`).(api.ScriptList)
	if list.Status != "enabled" || len(list.Scripts) != 1 || list.Scripts[0].ID != "sample" {
		t.Fatalf("script list = %+v", list)
	}
	run := call(`{"action":"runScript","target":"sample","argument":"override","wait":true}`).(api.ScriptRun)
	if run.Result != "done" || string(run.Value) != `"override"` {
		t.Fatalf("script run = %+v", run)
	}
	async := call(`{"action":"runScript","target":"sample"}`).(api.ScriptRun)
	if async.RunID <= run.RunID || async.Result != "running" {
		t.Fatalf("async script run = %+v", async)
	}
	runs := call(`{"action":"scriptRuns","target":"sample","limit":1}`).([]api.ScriptRun)
	if len(runs) != 1 || runs[0].RunID != async.RunID {
		t.Fatalf("recent runs = %+v", runs)
	}
	other := call(`{"action":"scriptRuns","target":"unrelated"}`).([]api.ScriptRun)
	if len(other) != 0 {
		t.Fatalf("filtered runs = %+v", other)
	}
}

func TestPacketTunnelNetworkScriptEvents(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		session := scriptOperationSession(t, compile.Script{ID: "network", Type: "event", EventName: "network-changed"})
		engine := session.profile.engine
		checkRuns := func(want int) {
			t.Helper()
			time.Sleep(time.Second)
			synctest.Wait()
			runs := engine.GetScriptRuns("network", 0)
			if len(runs) != want {
				t.Fatalf("network script runs = %+v, want %d", runs, want)
			}
			for _, run := range runs {
				if run.Trigger != "event" || run.Event != "network-changed" || run.Result != "done" {
					t.Fatalf("network script run = %+v", run)
				}
			}
		}
		session.NetworkChanged(true, false)
		checkRuns(0)
		session.NetworkChanged(true, true)
		checkRuns(1)
		session.NetworkChanged(false, true)
		checkRuns(1)
		session.NetworkChanged(true, false)
		checkRuns(2)
		session.NetworkChanged(true, false)
		checkRuns(2)
	})
}

func scriptOperationSession(t *testing.T, def compile.Script) *Session {
	t.Helper()
	engine := generation.NewEngine(generation.EngineOptions{
		HostPacketFlow: true,
		ScriptEngine:   func() script.Engine { return operationScriptEngine{} },
	})
	t.Cleanup(engine.Close)
	eff, diagnostics := compile.Compile([]byte("schema-version: 1\n"), nil, compile.Options{})
	if diagnostics.HasErrors() {
		t.Fatal(diagnostics)
	}
	source := []byte("$done($argument)")
	def.Supported, def.Hash = true, resource.Hash(source)
	eff.Scripts = []compile.Script{def}
	prepared, err := engine.Prepare(eff)
	if err != nil {
		t.Fatal(err)
	}
	prepared.SetScriptSourceReader(func(string) ([]byte, error) { return source, nil })
	if _, err := engine.ActivatePacketFlowProfile(prepared, 1, "tests", nil); err != nil {
		t.Fatal(err)
	}
	return &Session{ctx: t.Context(), logger: slog.New(slog.DiscardHandler), profile: &profileSession{engine: engine}}
}

type operationScriptEngine struct{}

func (operationScriptEngine) Run(_ context.Context, job *script.Job) (script.Done, error) {
	value, err := json.Marshal(job.Script.Argument)
	return script.Done{Called: true, Value: value}, err
}

func (operationScriptEngine) Purge() {}
