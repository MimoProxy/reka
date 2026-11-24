package router

import (
	"net/netip"
	"reflect"
	"slices"
	"testing"
	"time"
)

func requirePreMatchDecision(t testing.TB, got PreMatchResult, index int, target, outbound string) {
	t.Helper()
	d := got.Decision
	if !got.Decided || d.RuleIndex != index || d.Target != target || d.Outbound != outbound || d.LookupRule != -1 {
		t.Fatalf("PreMatch returned %+v, want rule %d with target %q and outbound %q", got, index, target, outbound)
	}
}

func requireUndecidedPreMatch(t testing.TB, got PreMatchResult) {
	t.Helper()
	want := PreMatchResult{Decision: Decision{RuleIndex: -1, LookupRule: -1}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("PreMatch returned %+v, want %+v", got, want)
	}
}

func TestPreMatchRespectsDomainBoundary(t *testing.T) {
	md := Metadata{Addr: netip.MustParseAddr("192.0.2.10"), Network: "tcp", Port: 443}
	packet := RuleSpec{Kind: KindDstPort, Values: []string{"443"}, Target: "reject"}
	domain := RuleSpec{Kind: KindDomainSuffix, Values: []string{"example.test"}, Target: "proxy"}
	miss := RuleSpec{Kind: KindNetwork, Values: []string{"udp"}, Target: "reject"}
	pass := RuleSpec{Kind: KindMatch, Target: "pass"}
	negated := RuleSpec{Kind: KindNot, Children: []RuleSpec{domain}, Target: "proxy"}
	for _, tc := range []struct {
		name     string
		rules    []RuleSpec
		want     string
		index    int
		sniffing bool
		domain   string
	}{
		{name: "match before boundary", rules: []RuleSpec{miss, packet, domain}, want: "reject", index: 1, sniffing: true},
		{name: "match after boundary", rules: []RuleSpec{domain, packet}, sniffing: true},
		{name: "final without domain rules", rules: []RuleSpec{miss}, want: "direct", index: -1, sniffing: true},
		{name: "final with domain rules", rules: []RuleSpec{miss, domain}, sniffing: true},
		{name: "pass continues before boundary", rules: []RuleSpec{pass, miss, packet, domain}, want: "reject", index: 2, sniffing: true},
		{name: "pass crosses boundary", rules: []RuleSpec{pass, domain, packet}, sniffing: true},
		{name: "pass reaches domain boundary before final", rules: []RuleSpec{pass, domain}, sniffing: true},
		{name: "pass reaches final without domain rules", rules: []RuleSpec{pass, miss}, want: "direct", index: -1, sniffing: true},
		{name: "negated domain with pending domain", rules: []RuleSpec{negated, packet}, sniffing: true},
		{name: "negated domain with known absence", rules: []RuleSpec{negated, packet}, want: "proxy", index: 0},
		{name: "known absence permits later match", rules: []RuleSpec{domain, packet}, want: "reject", index: 1},
		{name: "known absence permits final", rules: []RuleSpec{miss, domain}, want: "direct", index: -1},
		{name: "supplied domain is already known", rules: []RuleSpec{domain, packet}, want: "proxy", index: 0, sniffing: true, domain: "sub.example.test"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := mustRouter(t, tc.rules, nil, "direct", "proxy", "reject", "pass")
			flow := md
			flow.Domain = tc.domain
			got := r.PreMatch(t.Context(), flow, PreMatchOptions{DomainPending: tc.sniffing})
			if tc.want == "" {
				requireUndecidedPreMatch(t, got)
				return
			}
			requirePreMatchDecision(t, got, tc.index, tc.want, tc.want)
		})
	}
}

func TestPreMatchAllowsEmptyFinal(t *testing.T) {
	rules, err := CompileRules(nil)
	if err != nil {
		t.Fatal(err)
	}
	r, err := New(rules, Options{})
	if err != nil {
		t.Fatal(err)
	}
	md := Metadata{Addr: netip.MustParseAddr("192.0.2.10")}
	requirePreMatchDecision(t, r.PreMatch(t.Context(), md, PreMatchOptions{DomainPending: true}), -1, "", "")
}

func TestPreMatchRespectsReferencedSetDomainBoundary(t *testing.T) {
	const domain = "example.test"
	specs := []RuleSpec{{Kind: KindDomain, Values: []string{domain}}}
	ordered, err := CompileRules(specs)
	if err != nil {
		t.Fatal(err)
	}
	compact := buildTestConditionSet(t, specs)
	precompiled := roundTripConditionSet(t, compact)
	for _, tc := range []struct {
		name string
		set  *RuleSet
	}{
		{"ordered", ordered}, {"compact", compact}, {"precompiled", precompiled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if !tc.set.MatchesDomain() {
				t.Fatal("referenced set lost its domain dependency")
			}
			r := mustRouter(t, []RuleSpec{
				{Kind: KindRuleSet, Values: []string{"sites"}, Set: tc.set, Target: "proxy"},
				{Kind: KindMatch, Target: "reject"},
			}, nil)
			md := Metadata{Addr: netip.MustParseAddr("192.0.2.10")}
			requireUndecidedPreMatch(t, r.PreMatch(t.Context(), md, PreMatchOptions{DomainPending: true}))
			requirePreMatchDecision(t, r.PreMatch(t.Context(), md, PreMatchOptions{}), 1, "reject", "reject")
			md.Domain = domain
			requirePreMatchDecision(t, r.PreMatch(t.Context(), md, PreMatchOptions{}), 0, "proxy", "proxy")
		})
	}
}

func TestPreMatchStopsOnlyAtReachedOwnerRules(t *testing.T) {
	md := Metadata{Addr: netip.MustParseAddr("192.0.2.10"), Port: 443}
	packet := RuleSpec{Kind: KindDstPort, Values: []string{"443"}, Target: "proxy"}
	for _, tc := range []struct {
		kind  Kind
		value string
	}{
		{KindProcessName, "curl"},
		{KindProcessNameWildcard, "cur?"},
		{KindProcessNameRegex, `^curl$`},
		{KindProcessPath, "/usr/bin/curl"},
		{KindProcessPathWildcard, "*/curl"},
		{KindProcessPathRegex, `/curl$`},
		{KindUID, "1000"},
	} {
		t.Run(tc.kind.String(), func(t *testing.T) {
			owner := RuleSpec{Kind: tc.kind, Values: []string{tc.value}, Target: "reject"}
			before := mustRouter(t, []RuleSpec{owner, packet}, nil)
			requireUndecidedPreMatch(t, before.PreMatch(t.Context(), md, PreMatchOptions{}))
			after := mustRouter(t, []RuleSpec{packet, owner}, nil)
			requirePreMatchDecision(t, after.PreMatch(t.Context(), md, PreMatchOptions{}), 0, "proxy", "proxy")
		})
	}
	uid := RuleSpec{Kind: KindUID, Values: []string{"1000"}}
	first := RuleSpec{Kind: KindNot, Children: []RuleSpec{uid}, Target: "reject"}
	r := mustRouter(t, []RuleSpec{first, packet}, nil)
	requireUndecidedPreMatch(t, r.PreMatch(t.Context(), md, PreMatchOptions{}))
	first = RuleSpec{Kind: KindOr, Children: []RuleSpec{packet, uid}, Target: "reject"}
	r = mustRouter(t, []RuleSpec{first, packet}, nil)
	requirePreMatchDecision(t, r.PreMatch(t.Context(), md, PreMatchOptions{}), 0, "reject", "reject")
}

func TestPreMatchPropagatesStoppedLookupsFromConditionSet(t *testing.T) {
	for _, tc := range []struct {
		name string
		md   Metadata
		rule RuleSpec
	}{
		{name: "owner", md: Metadata{Addr: netip.MustParseAddr("192.0.2.10")}, rule: RuleSpec{Kind: KindUID, Values: []string{"1000"}}},
		{name: "DNS", md: Metadata{Domain: "example.test"}, rule: RuleSpec{Kind: KindIPCIDR, Values: []string{"192.0.2.0/24"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			set := buildTestConditionSet(t, []RuleSpec{
				tc.rule,
				{Kind: KindDomain, Values: []string{"example.test"}},
				{Kind: KindMatch},
			})
			for _, members := range []*RuleSet{set, roundTripConditionSet(t, set)} {
				member := RuleSpec{Kind: KindRuleSet, Values: []string{"members"}, Set: members}
				r := mustRouter(t, []RuleSpec{
					{Kind: KindNot, Children: []RuleSpec{member}, Target: "reject"},
					{Kind: KindMatch, Target: "proxy"},
				}, nil)
				requireUndecidedPreMatch(t, r.PreMatch(t.Context(), tc.md, PreMatchOptions{}))
			}
		})
	}
}

func TestPreMatchStopsWhenIPRulesNeedDNS(t *testing.T) {
	md := Metadata{Domain: "example.test"}
	ip := RuleSpec{Kind: KindIPCIDR, Values: []string{"192.0.2.0/24"}, Target: "reject"}
	pass := RuleSpec{Kind: KindMatch, Target: "pass"}
	for _, specs := range [][]RuleSpec{{ip}, {pass, ip}} {
		r := mustRouter(t, specs, nil, "direct", "reject", "pass")
		requireUndecidedPreMatch(t, r.PreMatch(t.Context(), md, PreMatchOptions{}))
		requireUndecidedPreMatch(t, r.PreMatch(t.Context(), Metadata{}, PreMatchOptions{DomainPending: true}))
		requirePreMatchDecision(t, r.PreMatch(t.Context(), Metadata{}, PreMatchOptions{}), -1, "direct", "direct")
	}
	md.Addr = netip.MustParseAddr("192.0.2.10")
	r := mustRouter(t, []RuleSpec{ip}, nil)
	requirePreMatchDecision(t, r.PreMatch(t.Context(), md, PreMatchOptions{}), 0, "reject", "reject")
	ip.NoResolve = true
	r = mustRouter(t, []RuleSpec{ip}, nil)
	md.Addr = netip.Addr{}
	requirePreMatchDecision(t, r.PreMatch(t.Context(), md, PreMatchOptions{}), -1, "direct", "direct")
}

func TestPreMatchChecksActiveOverridesInOrder(t *testing.T) {
	md := Metadata{Addr: netip.MustParseAddr("192.0.2.10"), Port: 443}
	now := time.Unix(1000, 0)
	packet := RuleSpec{Kind: KindDstPort, Values: []string{"443"}, Target: "reject"}
	miss := RuleSpec{Kind: KindDstPort, Values: []string{"80"}, Target: "reject"}
	domain := RuleSpec{Kind: KindDomain, Values: []string{"example.test"}, Target: "proxy"}
	owner := RuleSpec{Kind: KindProcessName, Values: []string{"curl"}, Target: "reject"}
	pass := RuleSpec{Kind: KindMatch, Target: "pass"}
	active := func(specs ...RuleSpec) TimedRule {
		t.Helper()
		set, err := CompileRules(specs)
		if err != nil {
			t.Fatal(err)
		}
		return TimedRule{Match: set, ExpiresAt: now.Add(time.Minute)}
	}
	expired := active(domain)
	expired.ExpiresAt = now
	r := mustRouter(t, []RuleSpec{{Kind: KindMatch, Target: "direct"}}, nil, "direct", "proxy", "reject", "pass")
	for _, tc := range []struct {
		name      string
		overrides []TimedRule
		sniffing  bool
		want      string
		temporary bool
	}{
		{name: "expired domain does not block saved rules", overrides: []TimedRule{expired}, sniffing: true, want: "direct"},
		{name: "active domain blocks saved rules", overrides: []TimedRule{active(domain), active(packet)}, sniffing: true},
		{name: "known absence skips domain override", overrides: []TimedRule{active(domain), active(packet)}, want: "reject", temporary: true},
		{name: "first matching override wins", overrides: []TimedRule{active(miss), active(packet), active(domain)}, sniffing: true, want: "reject", temporary: true},
		{name: "active owner lookup stops evaluation", overrides: []TimedRule{active(owner), active(packet)}},
		{name: "pass reaches later override", overrides: []TimedRule{active(pass), active(packet)}, want: "reject", temporary: true},
		{name: "pass reaches saved rules", overrides: []TimedRule{active(pass)}, want: "direct"},
		{name: "pass reaches pending domain override", overrides: []TimedRule{active(pass), active(domain)}, sniffing: true},
		{name: "compiled override uses its first target", overrides: []TimedRule{active(miss, RuleSpec{Kind: KindMatch, Target: "proxy"})}, want: "reject", temporary: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := r.PreMatch(t.Context(), md, PreMatchOptions{DomainPending: tc.sniffing, At: now, Overrides: tc.overrides})
			if tc.want == "" {
				requireUndecidedPreMatch(t, got)
				return
			}
			index := 0
			if tc.temporary {
				index = -1
			}
			requirePreMatchDecision(t, got, index, tc.want, tc.want)
			if got.Decision.Temporary != tc.temporary {
				t.Fatalf("temporary = %t, want %t", got.Decision.Temporary, tc.temporary)
			}
		})
	}
}

func TestPreMatchUsesPeekForGroupsAndPass(t *testing.T) {
	md := Metadata{Addr: netip.MustParseAddr("192.0.2.10"), Port: 443}
	r := mustRouter(t, []RuleSpec{
		{Kind: KindDstPort, Values: []string{"443"}, Target: "outer"},
		{Kind: KindMatch, Target: "reject"},
	}, []Group{
		{ID: "outer", Members: []string{"inner", "pass"}},
		{ID: "inner", Members: []string{"proxy", "direct"}},
	}, "direct", "proxy", "reject", "pass")
	got := r.PreMatch(t.Context(), md, PreMatchOptions{})
	requirePreMatchDecision(t, got, 0, "outer", "proxy")
	if !slices.Equal(got.Decision.Chain, []string{"outer", "inner"}) {
		t.Fatalf("static chain = %v, want [outer inner]", got.Decision.Chain)
	}
	got = r.PreMatch(t.Context(), md, PreMatchOptions{Peek: func(target string) (string, []string, bool) {
		return "direct", []string{target, "inner"}, true
	}})
	requirePreMatchDecision(t, got, 0, "outer", "direct")
	if !slices.Equal(got.Decision.Chain, []string{"outer", "inner"}) {
		t.Fatalf("peek chain = %v, want [outer inner]", got.Decision.Chain)
	}
	requireUndecidedPreMatch(t, r.PreMatch(t.Context(), md, PreMatchOptions{Peek: func(string) (string, []string, bool) {
		return "proxy", []string{"outer", "inner"}, false
	}}))
	var peeked []string
	got = r.PreMatch(t.Context(), md, PreMatchOptions{Peek: func(target string) (string, []string, bool) {
		peeked = append(peeked, target)
		if target == "outer" {
			return "pass", []string{"outer"}, true
		}
		return target, nil, true
	}})
	requirePreMatchDecision(t, got, 1, "reject", "reject")
	if !slices.Equal(peeked, []string{"outer", "reject"}) || len(got.Decision.Chain) != 0 {
		t.Fatalf("peeked %v and got chain %v after pass", peeked, got.Decision.Chain)
	}
}

func BenchmarkPreMatch(b *testing.B) {
	large := suffixRules(10000)
	packet := RuleSpec{Kind: KindIPCIDR, Values: []string{"10.0.0.0/8"}, NoResolve: true, Target: "reject"}
	md := Metadata{Addr: netip.MustParseAddr("10.1.1.1"), Network: "tcp", Port: 443}
	opts := PreMatchOptions{DomainPending: true}
	for _, tc := range []struct {
		name    string
		rules   []RuleSpec
		decided bool
	}{
		{"match-before-domain-boundary", append([]RuleSpec{packet}, large...), true},
		{"match-after-domain-boundary", large, false},
	} {
		b.Run(tc.name, func(b *testing.B) {
			r := mustRouter(b, tc.rules, nil)
			ctx := b.Context()
			if got := r.PreMatch(ctx, md, opts); got.Decided != tc.decided {
				b.Fatalf("PreMatch returned %+v, want Decided = %t", got, tc.decided)
			}
			b.ReportAllocs()
			for b.Loop() {
				r.PreMatch(ctx, md, opts)
			}
		})
	}
}
