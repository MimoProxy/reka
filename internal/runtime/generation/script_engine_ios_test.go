package generation

import (
	"testing"

	"github.com/MimoProxy/reka/internal/backend/sagernet"
	"github.com/MimoProxy/reka/internal/config/compile"
	"github.com/MimoProxy/reka/internal/runtime"
	"github.com/MimoProxy/reka/internal/script"
)

func TestIOSMatchesScriptsWithoutExecutions(t *testing.T) {
	engine := NewEngine(EngineOptions{ScriptEngine: func() script.Engine {
		t.Fatal("iOS must not start a script engine")
		return nil
	}})
	t.Cleanup(engine.Close)
	eff := &compile.Effective{MITM: compile.MITM{Enabled: true}, Scripts: []compile.Script{{
		ID: "sample", Type: "http-response", Supported: true, Pattern: ".*", MaxSize: 128, RequiresBody: true,
	}}}
	g := &generation{eff: eff, scripts: newMITMScriptTable(eff.Scripts, engine.scriptLogger())}
	snap := &runtime.Snapshot[*sagernet.Outbound]{Value: g}
	matched := engine.mitmScriptMatcher(snap, routingState{})(script.KindHTTPResponse, "https://example.test/")
	if matched == nil || matched.Run != nil || matched.ID != "sample" {
		t.Fatalf("iOS script match = %+v", matched)
	}
	if got := engine.scriptStatus(g); got.Status != "unsupported" || got.Count != 1 || got.Runs != 0 {
		t.Fatalf("iOS script status = %+v", got)
	}
}
