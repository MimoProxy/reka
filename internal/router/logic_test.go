package router

import (
	"context"
	"net/netip"
	"strings"
	"testing"
)

func TestLogicalOrderShortCircuitAndExplain(t *testing.T) {
	for _, syntax := range []string{"AND,((NETWORK,UDP),(DST-PORT,443)),proxy", "AND,(NETWORK,UDP),(DST-PORT,443),proxy", "AND,((NETWORK,UDP),(OR,((DST-PORT,443),(DOMAIN,yes.test)))),proxy"} {
		spec, _, err := ParseClashRule(syntax)
		if err != nil {
			t.Fatal(syntax, err)
		}
		r := mustRouter(t, []RuleSpec{spec, {Kind: KindMatch, Target: "direct"}}, nil)
		if got := r.Route(context.Background(), Metadata{Network: "udp", Port: 443}, nil); got.Outbound != "proxy" {
			t.Fatal(got)
		}
		if got := r.Route(context.Background(), Metadata{Network: "tcp", Port: 443}, nil); got.Outbound != "direct" {
			t.Fatal(got)
		}
		if !strings.Contains(spec.String(), "NETWORK,udp") {
			t.Fatal("explanation omits operands", spec.String())
		}
	}
	for _, syntax := range []string{"AND,((NETWORK,TCP),(IP-CIDR,192.0.2.0/24)),proxy", "OR,((NETWORK,UDP),(IP-CIDR,192.0.2.0/24)),proxy", "NOT,((IP-CIDR,192.0.2.0/24)),proxy"} {
		spec, _, err := ParseClashRule(syntax)
		if err != nil {
			t.Fatal(err)
		}
		r := mustRouter(t, []RuleSpec{spec}, nil)
		env := &fakeEnv{noLookup: true}
		exp := r.Explain(context.Background(), Metadata{Network: "tcp", Domain: "x.test"}, env)
		if !exp.Undetermined || exp.StoppedAt != 0 || env.resolves != 1 {
			t.Fatal(syntax, exp, env.resolves)
		}
	}
	spec, _, err := ParseClashRule("AND,((NETWORK,UDP),(IP-CIDR,192.0.2.0/24)),proxy")
	if err != nil {
		t.Fatal(err)
	}
	r := mustRouter(t, []RuleSpec{spec}, nil)
	env := &fakeEnv{noLookup: true}
	r.Route(context.Background(), Metadata{Network: "tcp", Domain: "x.test"}, env)
	if env.resolves != 0 {
		t.Fatal("short circuit performed DNS")
	}
}
func TestNestedSetOrderNoResolveAndProcess(t *testing.T) {
	set, err := CompileRules([]RuleSpec{{Kind: KindProcessName, Values: []string{"never"}}, {Kind: KindIPCIDR, Values: []string{"192.0.2.0/24"}}, {Kind: KindDomain, Values: []string{"yes.test"}}})
	if err != nil {
		t.Fatal(err)
	}
	specs := []RuleSpec{{Kind: KindRuleSet, Values: []string{"list"}, Set: set, Target: "proxy", NoResolve: true}, {Kind: KindDomainSuffix, Values: []string{"test"}, Target: "reject"}}
	if nested := mustRouter(t, specs[:1], nil); !nested.Rules().MatchesDomain() {
		t.Fatal("nested domain dependency lost")
	}
	r := mustRouter(t, specs, nil)
	if !r.Rules().NeedsProcess() {
		t.Fatal("nested process dependency lost")
	}
	env := &fakeEnv{noLookup: true}
	for _, md := range []Metadata{{Domain: "yes.test"}, {Addr: netip.MustParseAddr("192.0.2.1")}} {
		if got := r.Route(context.Background(), md, env); got.Outbound != "proxy" {
			t.Fatal(got)
		}
	}
	if env.resolves != 0 {
		t.Fatal("no-resolve not propagated")
	}
	env.noLookup = true
	specs[0].NoResolve = false
	r = mustRouter(t, specs, nil)
	exp := r.Explain(context.Background(), Metadata{Domain: "yes.test"}, env)
	if !exp.Undetermined || exp.StoppedAt != 0 {
		t.Fatal(exp)
	}
}
func TestLogicalInvalid(t *testing.T) {
	for _, s := range []string{"NOT,((NETWORK,TCP),(NETWORK,UDP)),direct", "AND,NETWORK,TCP,direct", "AND,(),direct", "AND,((MATCH)),direct", "SUB-RULE,(NETWORK,TCP),x,extra", "AND,((NETWORK,TCP)),direct,no-resolve"} {
		if _, _, err := ParseClashRule(s); err == nil {
			t.Fatal("accepted", s)
		}
	}
}

func TestGeoIPLANAndPatternIndex(t *testing.T) {
	spec, _, err := ParseClashRule("GEOIP,LAN,proxy,no-resolve")
	if err != nil {
		t.Fatal(err)
	}
	r := mustRouter(t, []RuleSpec{spec}, nil)
	for ip, want := range map[string]bool{"127.0.0.1": true, "192.168.1.1": true, "169.254.1.1": true, "224.0.0.1": true, "0.0.0.0": true, "::1": true, "fe80::1": true, "192.0.2.1": false} {
		d := r.Route(context.Background(), Metadata{Addr: netip.MustParseAddr(ip)}, nil)
		if (d.Outbound == "proxy") != want {
			t.Fatal(ip, d)
		}
	}
	specs := []RuleSpec{{Kind: KindDomainPattern, Values: []string{".example.org", "*.wild.test"}, Target: "proxy"}, {Kind: KindDomain, Values: []string{"exact.example.org"}, Target: "reject"}, {Kind: KindDomainSuffix, Values: []string{"example.org"}, Target: "direct"}}
	set, err := CompileRules(specs)
	if err != nil {
		t.Fatal(err)
	}
	if len(set.strictSuffix) != 1 {
		t.Fatal("strict suffix not indexed")
	}
	for _, domain := range []string{"example.org", "exact.example.org", "x.example.org", "badexample.org", "x.wild.test", "a.b.wild.test"} {
		md := Metadata{Domain: domain}
		a := &evaluation{ctx: context.Background(), md: &md}
		b := &evaluation{ctx: context.Background(), md: &md}
		if set.first(a) != set.firstLinear(b) {
			t.Fatal(domain)
		}
	}
}

func TestNoResolveUsesPreviouslyResolvedAddress(t *testing.T) {
	r := mustRouter(t, []RuleSpec{{Kind: KindIPCIDR, Values: []string{"198.51.100.0/24"}, Target: "direct"}, {Kind: KindIPCIDR, Values: []string{"192.0.2.0/24"}, NoResolve: true, Target: "reject"}}, nil)
	env := &fakeEnv{addrs: map[string][]netip.Addr{"cached.test": {netip.MustParseAddr("192.0.2.1")}}}
	d := r.Route(context.Background(), Metadata{Domain: "cached.test"}, env)
	if d.Outbound != "reject" || env.resolves != 1 {
		t.Fatal(d, env.resolves)
	}
}
