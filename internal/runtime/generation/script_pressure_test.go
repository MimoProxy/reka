package generation

import (
	"fmt"
	"testing"

	"github.com/MimoProxy/reka/internal/api"
	"github.com/MimoProxy/reka/internal/script"
)

func TestScriptPressureCountsAndTakes(t *testing.T) {
	e := NewEngine(EngineOptions{})
	t.Cleanup(e.Close)
	p := &e.scriptPressure
	p.noteMITM(api.MITMScriptRun{ID: "a", Result: "low-memory"}, false)
	p.noteMITM(api.MITMScriptRun{ID: "a", Result: "low-memory"}, false)
	p.noteMITM(api.MITMScriptRun{ID: "a", Result: "low-memory"}, true)
	p.noteMITM(api.MITMScriptRun{ID: "b", Result: "oversize"}, false)
	p.noteMITM(api.MITMScriptRun{ID: "b", Result: "modified"}, true)
	p.noteError("c", fmt.Errorf("run: %w", script.ErrMemoryExceeded))
	p.noteError("c", script.ErrTimeout)

	got := e.TakeScriptPressure(2)
	if got.Skipped != 2 || got.Discarded != 2 || got.Oversize != 1 {
		t.Fatalf("totals = %+v", got)
	}
	want := []api.ScriptPressureCount{{ID: "a", Skipped: 2, Discarded: 1}, {ID: "b", Oversize: 1}}
	if len(got.Scripts) != len(want) || got.Scripts[0] != want[0] || got.Scripts[1] != want[1] {
		t.Fatalf("scripts = %+v, want %+v", got.Scripts, want)
	}
	if again := e.TakeScriptPressure(2); again.Skipped+again.Discarded+again.Oversize != 0 || again.Scripts != nil {
		t.Fatalf("second take = %+v, want empty", again)
	}
}

func TestMITMScriptTableDescribe(t *testing.T) {
	table := mitmScriptTable{responses: []mitmScriptEntry{{id: "x", module: "M", spec: script.Script{Name: "N"}}}}
	if name, module := table.describe("x"); name != "N" || module != "M" {
		t.Fatalf("describe = %q, %q", name, module)
	}
	if name, module := table.describe("y"); name != "" || module != "" {
		t.Fatalf("missing script = %q, %q", name, module)
	}
}
