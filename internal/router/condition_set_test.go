package router

import (
	"bytes"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

func buildTestConditionSet(t *testing.T, specs []RuleSpec) *RuleSet {
	t.Helper()
	var builder ConditionSetBuilder
	for _, spec := range specs {
		if err := builder.Add(spec); err != nil {
			t.Fatal(err)
		}
	}
	set, err := builder.Build()
	if err != nil {
		t.Fatal(err)
	}
	return set
}

func roundTripConditionSet(t *testing.T, set *RuleSet) *RuleSet {
	t.Helper()
	wire, err := set.MarshalPrecompiledRuleSet(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(wire) < 4 || string(wire[:4]) != "RDS\x01" {
		t.Fatal("unexpected precompiled rule set format")
	}
	cached, err := ReadPrecompiledRuleSet(bytes.NewReader(wire), 1<<20, 1000)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := cached.Build(func(_ int, spec RuleSpec) (RuleSpec, error) { return spec, nil })
	if err != nil {
		t.Fatal(err)
	}
	return restored
}

func TestCompactDomainSetAgreesWithOrderedRules(t *testing.T) {
	specs := []RuleSpec{
		{Kind: KindDomain, Values: []string{".EXACT.test.", "bücher.test", "escaped%0a.test", "raw\xff.test"}},
		{Kind: KindDomainSuffix, Values: []string{".SUFFIX.test.", "..DOT.test", "dotted.test..", "reserved\r.test"}},
		{Kind: KindDomainPattern, Values: []string{"+.PLUS.test", ".STRICT.test", "*.wild.test", "literal.test", "+.*.label.test", "�.replace.test"}},
		{Kind: KindDomainKeyword, Values: []string{"NEEDLE"}},
		{Kind: KindDomainRegex, Values: []string{`^re[0-9]+\.test$`, `^$`, `(?i)^Mixed\.test$`}},
	}
	wanted := map[string]bool{
		"": false, ".": false, "EXACT.test.": true, "badexact.test": false, "a.exact.test": false,
		"SUFFIX.test.": true, "sub.suffix.test": true, "endsuffix.test": false, ".suffix.test": true,
		".dot.test": true, "a..dot.test": true, "dot.test": false, "dotted.test..": true,
		"PLUS.test.": true, "a.b.plus.test": true, ".plus.test": false, ".a.plus.test": true, "a\nb.plus.test": false,
		"STRICT.test.": false, ".strict.test": true, "a.b.strict.test": true, "nonstrict.test": false,
		"wild.test": false, "x.wild.test": true, "x.y.wild.test": false, "literal.test": true, "a.literal.test": false,
		"label.test": false, "x.label.test": true, "a.b.label.test": true, "findNeedle.test": true,
		"re12.test": true, "sub.re12.test": false, "MIXED.test.": true, "bücher.test": true,
		"raw\xff.test": true, "raw�.test": false, "\xff.replace.test": true,
		"escaped%0a.test": true, "escaped\n.test": false, "a.reserved\r.test": true, "a.reserved.test": false,
	}
	var queries []string
	rng := rand.New(rand.NewPCG(31, 17))
	for i := range 150 {
		label := fmt.Sprintf("d%x", rng.Uint32())
		host := label + ".random.test"
		kind, value := KindDomain, host
		switch i % 6 {
		case 0:
			value = strings.ToUpper(host) + "."
		case 1:
			kind, value = KindDomainSuffix, "."+host
		case 2:
			kind, value = KindDomainPattern, "+."+host
		case 3:
			kind, value = KindDomainPattern, "."+host
		case 4:
			kind, value = KindDomainKeyword, label
		case 5:
			kind, value = KindDomainRegex, "^"+label+`\.random\.test$`
		}
		specs = append(specs, RuleSpec{Kind: kind, Values: []string{value}})
		queries = append(queries, host, strings.ToUpper(host)+".", "x."+host, "."+host, "x"+host, host+".other")
	}
	ordered, err := CompileRules(specs)
	if err != nil {
		t.Fatal(err)
	}
	compact := buildTestConditionSet(t, specs)
	precompiled := roundTripConditionSet(t, compact)
	if compact.Len() != ordered.Len() || !compact.MatchesDomain() || len(compact.rules) != 0 || len(compact.members.blocks) != 1 {
		t.Fatal("domain members were not compiled as one compact set")
	}
	for _, set := range []*RuleSet{compact, precompiled} {
		if set.Len() != ordered.Len() {
			t.Fatal("rule count changed")
		}
		for i := range ordered.Len() {
			if !reflect.DeepEqual(set.Rule(i), ordered.Rule(i)) {
				t.Fatalf("listed rule %d changed", i)
			}
		}
	}
	evaluate := func(set *RuleSet, raw string) bool {
		md := Metadata{Domain: NormalizeDomain(raw)}
		return set.matches(&evaluation{md: &md, lookupRule: -1})
	}
	for query, want := range wanted {
		if got, old, restored := evaluate(compact, query), evaluate(ordered, query), evaluate(precompiled, query); got != want || old != want || restored != want {
			t.Errorf("%q matched %v with compact rules, %v with ordered rules and %v after loading, want %v", query, got, old, restored, want)
		}
	}
	for _, query := range queries {
		if got, restored, want := evaluate(compact, query), evaluate(precompiled, query), evaluate(ordered, query); got != want || restored != want {
			t.Errorf("%q matched %v with compact rules and %v after loading, want %v", query, got, restored, want)
		}
	}
}

func TestCompactMixedSetPreservesLookupOrder(t *testing.T) {
	specs := []RuleSpec{
		{Kind: KindDomain, Values: []string{"skip.test"}},
		{Kind: KindIPCIDR, Values: []string{"192.0.2.0/24"}},
		{Kind: KindDstPort, Values: []string{"8443"}},
		{Kind: KindDomainSuffix, Values: []string{"after.test"}},
	}
	ordered, err := CompileRules(specs)
	if err != nil {
		t.Fatal(err)
	}
	compact := buildTestConditionSet(t, specs)
	precompiled := roundTripConditionSet(t, compact)
	for i := range ordered.Len() {
		if !reflect.DeepEqual(compact.Rule(i), ordered.Rule(i)) || !reflect.DeepEqual(precompiled.Rule(i), ordered.Rule(i)) {
			t.Fatalf("listed rule %d changed", i)
		}
	}
	for _, test := range []struct {
		name      string
		noResolve bool
		noLookup  bool
		want      string
		lookups   int
	}{
		{"skip.test", false, true, "reject", 0},
		{"after.test", false, true, "", 1},
		{"after.test", false, false, "reject", 1},
		{"after.test", true, true, "reject", 0},
		{"ip.test", false, false, "reject", 1},
	} {
		for _, set := range []*RuleSet{ordered, compact, precompiled} {
			r := mustRouter(t, []RuleSpec{{Kind: KindRuleSet, Values: []string{"mixed"}, Set: set, NoResolve: test.noResolve, Target: "reject"}}, nil)
			env := &fakeEnv{noLookup: test.noLookup, addrs: map[string][]netip.Addr{
				"ip.test": {netip.MustParseAddr("192.0.2.1")}, "after.test": {netip.MustParseAddr("198.51.100.1")},
			}}
			exp := r.Explain(t.Context(), Metadata{Domain: test.name}, env)
			if exp.Decision.Outbound != test.want || env.resolves != test.lookups {
				t.Errorf("%+v got %+v with %d lookups", test, exp, env.resolves)
			}
			if test.lookups == 1 && test.noLookup {
				if !exp.Undetermined || exp.StoppedAt != 0 || exp.StoppedRule.Kind != KindRuleSet {
					t.Errorf("unavailable lookup was not attributed to the outer rule: %+v", exp)
				}
			} else if test.lookups == 1 && exp.Decision.LookupRule != 0 {
				t.Errorf("lookup was not attributed to the outer rule: %+v", exp)
			}
		}
	}
}

func TestCompactSetSharesRepeatedRegexps(t *testing.T) {
	const expr = `^a[^.]+\.test$`
	set := buildTestConditionSet(t, []RuleSpec{
		{Kind: KindDomainRegex, Values: []string{expr, expr}},
		{Kind: KindDstPort, Values: []string{"8443"}},
		{Kind: KindDomainRegex, Values: []string{expr}},
	})
	first, last := set.members.blocks[0].domains.regexps, set.members.blocks[2].domains.regexps
	if len(first) != 1 || len(last) != 1 || first[0] != last[0] {
		t.Fatal("the repeated regexp was compiled more than once")
	}
}
