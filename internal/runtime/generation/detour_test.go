package generation

import (
	"context"
	"testing"

	"github.com/MimoProxy/reka/internal/config/compile"
	"github.com/MimoProxy/reka/internal/policy"
)

func TestDetourReusedChildObservesCurrentPolicyManager(t *testing.T) {
	const input = `schema-version: 1
outbounds:
 - {id: child, type: direct, dialer: {proxy: hop}}
 - {id: a, type: direct}
 - {id: b, type: direct}
groups: [{id: hop, type: fallback, members: [a,b], lazy: true, url: 'https://example.test/'}]
rules: [{id: final, match: {all: true}, outbound: child}]
`
	eff, ds := compile.Compile([]byte(input), nil, compile.Options{})
	if ds.HasErrors() {
		t.Fatal(ds)
	}
	e := NewEngine(EngineOptions{})
	defer e.Close()
	activate := func(selected string, revision uint64) *Prepared {
		t.Helper()
		p, err := e.Prepare(eff)
		if err != nil {
			t.Fatal(err)
		}
		if p.policies != nil {
			p.policies.Close()
		}
		// Isolate the generation binding from network health timing. Each manager
		// has a distinct observed choice while the transport graph stays equal.
		p.policies = policy.New([]policy.Group{{ID: "hop", Type: "fallback", Members: []string{"a", "b"}, Selected: selected, Lazy: true}}, func(context.Context, string, string) error { return nil })
		if _, err = e.Activate(p, revision); err != nil {
			t.Fatal(err)
		}
		return p
	}
	p1 := activate("a", 1)
	bridge := p1.detours[0]
	if pin, err := bridge.parent("tcp", "target.test:443"); err != nil || pin != bridge.pins["a"] {
		t.Fatal("first policy", err)
	}
	p2 := activate("b", 2)
	if p1.outbounds["child"] != p2.outbounds["child"] {
		t.Fatal("equal transport rebuilt")
	}
	if pin, err := bridge.parent("tcp", "target.test:443"); err != nil || pin != bridge.pins["b"] {
		t.Fatal("reused child kept a retired policy manager", err)
	}
}
