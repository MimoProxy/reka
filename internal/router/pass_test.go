package router

import (
	"context"
	"testing"
)

func TestPASSContinuesAfterIndexedAndObservedGroupMatches(t *testing.T) {
	rules := []RuleSpec{{Kind: KindDomain, Values: []string{"example.test"}, Target: "choice"}, {Kind: KindDomain, Values: []string{"example.test"}, Target: "reject"}, {Kind: KindMatch, Target: "direct"}}
	r := mustRouter(t, rules, []Group{{ID: "choice", Members: []string{"direct", "pass"}, Selected: "direct"}}, "direct", "reject", "pass")
	md := Metadata{Domain: "example.test"}
	calls := 0
	resolve := func(d *Decision) {
		calls++
		d.Outbound, d.Chain, _ = r.ResolveDynamic(d.Target, func(Group) string { return "pass" })
	}
	d := r.RouteWithResolver(context.Background(), md, nil, resolve)
	if d.RuleIndex != 1 || d.Outbound != "reject" || calls != 2 {
		t.Fatal(d, calls)
	}
	x := r.ExplainWithResolver(context.Background(), md, nil, resolve)
	if x.RuleIndex != d.RuleIndex || x.Outbound != d.Outbound {
		t.Fatal(x, d)
	}
	r = mustRouter(t, []RuleSpec{{Kind: KindMatch, Target: "pass"}}, nil, "direct", "pass")
	if d = r.Route(context.Background(), Metadata{}, nil); d.Outbound != "direct" || d.RuleIndex != -1 {
		t.Fatal("PASS did not reach final", d)
	}
}
