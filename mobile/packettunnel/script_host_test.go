//go:build with_gvisor

package packettunnel

import (
	"context"
	"testing"

	"github.com/MimoProxy/reka/internal/script"
	"github.com/MimoProxy/reka/mobile/profile"
)

func TestPacketTunnelScriptHostSurvivesProfileReplacement(t *testing.T) {
	snapshot := prepareSnapshot(t, "schema-version: 1\n")
	controls := profile.Controls{ScriptState: t.TempDir()}
	factoryCalls := 0
	SetScriptHost(func() script.Engine {
		factoryCalls++
		return testScriptEngine{}
	}, nil)
	t.Cleanup(func() { SetScriptHost(nil, nil) })

	probe, err := StartProbeProfile(snapshot, controls)
	if err != nil {
		t.Fatal(err)
	}
	defer probe.Close()
	if status := probe.profile.engine.MITMStatus().Scripts.Status; status != "unsupported" {
		t.Fatalf("probe script status = %q", status)
	}
	if factoryCalls != 0 {
		t.Fatalf("probe called the script factory %d times", factoryCalls)
	}

	session, err := StartProfile(snapshot, controls, false)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	engine := session.profile.engine
	if status := engine.MITMStatus().Scripts.Status; status != "disabled" || factoryCalls != 1 {
		t.Fatalf("tunnel script status = %q, factory calls = %d", status, factoryCalls)
	}
	if err := session.ReplaceProfile(snapshot, controls); err != nil {
		t.Fatal(err)
	}
	if session.profile.engine != engine || factoryCalls != 1 {
		t.Fatalf("profile replacement changed the script engine, factory calls = %d", factoryCalls)
	}
}

type testScriptEngine struct{}

func (testScriptEngine) Run(context.Context, *script.Job) (script.Done, error) {
	return script.Done{Called: true}, nil
}

func (testScriptEngine) Purge() {}
