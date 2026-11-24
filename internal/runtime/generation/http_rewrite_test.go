package generation

import (
	"fmt"
	"testing"

	"github.com/MimoProxy/reka/internal/config/compile"
)

func TestHTTPRewriteReload(t *testing.T) {
	e := NewEngine(EngineOptions{})
	defer e.Close()
	if mitm, set := e.MITM(); mitm.Enabled || set != nil {
		t.Fatalf("idle engine has MITM settings or a rewrite set: %+v, %p", mitm, set)
	}
	compileConfig := func(response string) *compile.Effective {
		t.Helper()
		profile := fmt.Sprintf(`schema-version: 1
mitm: {hostnames: ['*.example.test'], h2: true}
http-rewrites: [{id: ads, match: '^https://ads\.example\.test/', action: reject, response: %q}]
outbounds: [{id: node, type: direct}]
listeners: [{id: proxy, type: http, listen: '127.0.0.1:17890'}]
`, response)
		local := []byte("mitm: {enabled: true, ca: secret://mitm/ca}\n")
		eff, diags := compile.Compile([]byte(profile), local, compile.Options{})
		if diags.HasErrors() {
			t.Fatal(diags)
		}
		return eff
	}
	initialConfig := compileConfig("error")
	// Supply an existing listener configuration so this test needs no socket.
	inbound := &listener{cfg: initialConfig.Listeners[0]}
	e.listeners["proxy"] = inbound
	defer func() {
		if e.listeners["proxy"] == inbound {
			delete(e.listeners, "proxy")
		}
	}()
	p, err := e.Prepare(initialConfig)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.Activate(p, 1); err != nil {
		t.Fatal(err)
	}
	mitm, initial := e.MITM()
	if initial == nil || !mitm.Enabled || mitm.CA != "secret://mitm/ca" || !mitm.H2 ||
		mitm.Matcher == nil || !mitm.Matcher.Match("ads.example.test", 443) {
		t.Fatalf("accessor returned unexpected MITM settings or rewrite set: %+v, %p", mitm, initial)
	}
	outbound := e.OutboundInstance("node")
	if outbound == nil {
		t.Fatal("initial outbound missing")
	}
	activate := func(eff *compile.Effective, revision uint64) {
		t.Helper()
		p, err := e.Prepare(eff)
		if err != nil {
			t.Fatal(err)
		}
		plan := p.Plan()
		for _, changes := range [][]ResourceChange{plan.Outbounds, plan.Listeners} {
			if len(changes) == 0 {
				e.Abort(p)
				t.Fatal("plan omitted unchanged resources")
			}
			for _, change := range changes {
				if change.Action != ActionKeep {
					e.Abort(p)
					t.Fatalf("rewrite reload affected a resource: %+v", change)
				}
			}
		}
		if plan.Interrupts || plan.RulesChanged {
			e.Abort(p)
			t.Fatalf("rewrite reload affected routing or interrupted traffic: %+v", plan)
		}
		if _, err := e.Activate(p, revision); err != nil {
			t.Fatal(err)
		}
		if e.OutboundInstance("node") != outbound || e.listeners["proxy"] != inbound {
			t.Fatal("rewrite reload replaced the outbound or listener")
		}
	}
	changed := compileConfig("gif")
	activate(changed, 2)
	_, current := e.MITM()
	if current == nil || current == initial || current != changed.HTTPRewrite {
		t.Fatalf("rewrite change did not install the new set: %p, want %p", current, changed.HTTPRewrite)
	}
	unchanged := compileConfig("gif")
	fresh := unchanged.HTTPRewrite
	if fresh == current {
		t.Fatal("expected independent compilation to produce a fresh set")
	}
	activate(unchanged, 3)
	_, reused := e.MITM()
	if reused == nil || reused == fresh || unchanged.HTTPRewrite != fresh || !reused.SharesCompiled(current) {
		t.Fatalf("reload must retain compiled expressions without changing the candidate: %p, active %p", reused, current)
	}
}
