package generation

import (
	"testing"

	"github.com/MimoProxy/reka/internal/backend/sagernet"
	"github.com/MimoProxy/reka/internal/config/compile"
	"github.com/MimoProxy/reka/internal/runtime"
	"github.com/MimoProxy/reka/internal/script"
)

func TestIOSMatchesScriptsWithOptionalHost(t *testing.T) {
	eff := &compile.Effective{MITM: compile.MITM{Enabled: true}, Scripts: []compile.Script{{
		ID: "sample", Type: "http-response", Supported: true, Pattern: ".*", MaxSize: 128, RequiresBody: true,
	}}}
	for _, tc := range []struct {
		status  string
		factory func() script.Engine
	}{
		{status: "unsupported"},
		{status: "enabled", factory: func() script.Engine { return testScriptEngine{} }},
	} {
		t.Run(tc.status, func(t *testing.T) {
			engine := NewEngine(EngineOptions{ScriptEngine: tc.factory})
			t.Cleanup(engine.Close)
			g := &generation{eff: eff, scripts: newMITMScriptTable(eff.Scripts, engine.scriptLogger())}
			snap := &runtime.Snapshot[*sagernet.Outbound]{Value: g}
			matched := engine.mitmScriptMatcher(snap, routingState{})(script.KindHTTPResponse, "https://example.test/")
			if matched == nil || (matched.Run != nil) != (tc.factory != nil) || matched.ID != "sample" {
				t.Fatalf("iOS script match = %+v", matched)
			}
			if got := engine.scriptStatus(g); got.Status != tc.status || got.Count != 1 || got.Runs != 0 {
				t.Fatalf("iOS script status = %+v", got)
			}
		})
	}
}
