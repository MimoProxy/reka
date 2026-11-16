package generation

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/MimoProxy/reka/internal/backend/sagernet"
	"github.com/MimoProxy/reka/internal/config/compile"
)

func TestProcessCollectionAlwaysRuleOffIndependentOfRuleOutcome(t *testing.T) {
	for _, tc := range []struct {
		mode string
		rule bool
		want int32
	}{{"always", false, 1}, {"always", true, 1}, {"rule", false, 0}, {"rule", true, 1}, {"off", true, 0}} {
		t.Run(tc.mode+map[bool]string{true: "-owner-rule", false: "-domain-rule"}[tc.rule], func(t *testing.T) {
			var calls atomic.Int32
			e := NewEngine(EngineOptions{Backend: sagernet.Options{ProcessInfoLookup: func(context.Context, sagernet.Metadata) (sagernet.ProcessInfo, bool) {
				calls.Add(1)
				return sagernet.ProcessInfo{Path: "/Applications/Test.app/Test", UID: 501, UIDKnown: true, PID: 12345}, true
			}}})
			defer e.Close()
			rules := "rules: [{match: {all: true}, outbound: direct}]\n"
			if tc.rule {
				rules = "rules: [{match: {and: [{process-name: Test}, {process-path: /Applications/Test.app/Test}, {uid: 501}]}, outbound: direct}, {match: {all: true}, outbound: direct}]\n"
			}
			profile := []byte("schema-version: 1\nprocess: {mode: " + tc.mode + "}\n" + rules)
			eff, ds := compile.Compile(profile, nil, compile.Options{ProcessLookup: true})
			if ds.HasErrors() {
				t.Fatal(ds)
			}
			p, err := e.Prepare(eff)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = e.Activate(p, 1); err != nil {
				t.Fatal(err)
			}
			rt := e.route(context.Background(), sagernet.Metadata{Network: "tcp"})
			if rt.Outbound == nil {
				t.Fatal("route rejected")
			}
			defer rt.Release()
			if calls.Load() != tc.want {
				t.Fatalf("lookup calls %d want %d", calls.Load(), tc.want)
			}
			info := rt.Info.(*FlowInfo)
			if tc.want == 0 {
				if info.ProcessPath != "" || info.ProcessUID != nil || info.ProcessPID != 0 || rt.Owner.Path != "" {
					t.Fatal("owner leaked without collection", info)
				}
			} else if info.ProcessPID != 12345 || info.ProcessPath != "/Applications/Test.app/Test" || info.ProcessUID == nil || *info.ProcessUID != 501 || rt.Owner.PID != 12345 {
				t.Fatal("owner missing", info)
			}
			page := e.ProcessTraffic(-1, 5000)
			if page.Mode != tc.mode || page.Limit != 100 || !page.Supported {
				t.Fatal(page)
			}
		})
	}
}
