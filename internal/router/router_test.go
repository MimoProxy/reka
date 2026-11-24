package router

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"strings"
	"testing"
	"time"
)

type fakeEnv struct {
	addrs    map[string][]netip.Addr
	process  string
	resolves int
	noLookup bool
}

func (f *fakeEnv) Resolve(_ context.Context, domain string) ([]netip.Addr, error) {
	f.resolves++
	if f.noLookup {
		return nil, ErrNoLookup
	}
	if a, ok := f.addrs[domain]; ok {
		return a, nil
	}
	return nil, fmt.Errorf("no such host %s", domain)
}

func (f *fakeEnv) Process(context.Context) (string, bool) { return f.process, f.process != "" }

func mustRouter(t testing.TB, specs []RuleSpec, groups []Group, outbounds ...string) *Router {
	t.Helper()
	rs, err := CompileRules(specs)
	if err != nil {
		t.Fatal(err)
	}
	if len(outbounds) == 0 {
		outbounds = []string{"direct", "proxy", "reject"}
	}
	r, err := New(rs, Options{Outbounds: outbounds, Groups: groups, Final: "direct"})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestFirstMatchWins(t *testing.T) {
	r := mustRouter(t, []RuleSpec{
		{Kind: KindDomainKeyword, Values: []string{"goo"}, Target: "reject"},
		{Kind: KindDomainSuffix, Values: []string{"google.com"}, Target: "proxy"},
		{Kind: KindDomain, Values: []string{"www.google.com"}, Target: "direct"},
	}, nil)
	d := r.Route(context.Background(), Metadata{Network: "tcp", Domain: "www.google.com", Port: 443}, nil)
	if d.RuleIndex != 0 || d.Outbound != "reject" {
		t.Fatalf("got %+v, want rule 0 -> reject", d)
	}
}

func TestDomainSuffixBoundary(t *testing.T) {
	r := mustRouter(t, []RuleSpec{{Kind: KindDomainSuffix, Values: []string{"example.org"}, Target: "proxy"}}, nil)
	for domain, want := range map[string]string{
		"example.org":     "proxy",
		"a.b.example.org": "proxy",
		"badexample.org":  "direct",
		"example.org.cn":  "direct",
	} {
		if d := r.Route(context.Background(), Metadata{Domain: domain}, nil); d.Outbound != want {
			t.Errorf("%s -> %s, want %s", domain, d.Outbound, want)
		}
	}
}

func TestIPRulesResolve(t *testing.T) {
	env := &fakeEnv{addrs: map[string][]netip.Addr{
		"lan.test": {netip.MustParseAddr("fd00::1"), netip.MustParseAddr("192.168.1.10")},
	}}
	r := mustRouter(t, []RuleSpec{
		{Kind: KindIPCIDR, Values: []string{"10.0.0.0/8"}, NoResolve: true, Target: "reject"},
		{Kind: KindIPCIDR, Values: []string{"192.168.0.0/16"}, Target: "proxy"},
	}, nil)
	ctx := context.Background()
	d := r.Route(ctx, Metadata{Domain: "lan.test"}, env)
	if d.Outbound != "proxy" || env.resolves != 1 || d.LookupRule != 1 || d.LookupRuleSpec().String() != "IP-CIDR,192.168.0.0/16,proxy" {
		t.Fatalf("got %+v after %d resolves", d, env.resolves)
	}
	// A failed lookup makes ip rules not match; it does not pick a target.
	d = r.Route(ctx, Metadata{Domain: "unknown.test"}, env)
	if d.Outbound != "direct" || d.ResolveError == nil || d.LookupRule != 1 {
		t.Fatalf("unresolvable: %+v", d)
	}
	// no-resolve rules see addresses only.
	d = r.Route(ctx, Metadata{Addr: netip.MustParseAddr("10.1.2.3")}, env)
	if d.Outbound != "reject" || d.LookupRule != -1 {
		t.Fatalf("address destination: %+v", d)
	}
	// IPv4-mapped destinations match IPv4 prefixes.
	d = r.Route(ctx, Metadata{Addr: netip.MustParseAddr("::ffff:10.1.2.3")}, env)
	if d.Outbound != "reject" {
		t.Fatalf("mapped address: %+v", d)
	}
}

func TestNoResolveBeforeDomainMatch(t *testing.T) {
	// The domain rule is later than the ip rule, so the ip rule must be
	// evaluated (and resolve) first.
	env := &fakeEnv{addrs: map[string][]netip.Addr{"a.test": {netip.MustParseAddr("1.1.1.1")}}}
	r := mustRouter(t, []RuleSpec{
		{Kind: KindIPCIDR, Values: []string{"1.0.0.0/8"}, Target: "reject"},
		{Kind: KindDomain, Values: []string{"a.test"}, Target: "proxy"},
	}, nil)
	if d := r.Route(context.Background(), Metadata{Domain: "a.test"}, env); d.Outbound != "reject" {
		t.Fatalf("got %+v", d)
	}
	// The other order never resolves.
	env.resolves = 0
	r = mustRouter(t, []RuleSpec{
		{Kind: KindDomain, Values: []string{"a.test"}, Target: "proxy"},
		{Kind: KindIPCIDR, Values: []string{"1.0.0.0/8"}, Target: "reject"},
	}, nil)
	if d := r.Route(context.Background(), Metadata{Domain: "a.test"}, env); d.Outbound != "proxy" || env.resolves != 0 {
		t.Fatalf("got %+v, %d resolves", d, env.resolves)
	}
}

func TestLookupRuleAttribution(t *testing.T) {
	matchIP := RuleSpec{Kind: KindIPCIDR, Values: []string{"192.0.2.0/24"}, Target: "proxy"}
	missIP := RuleSpec{Kind: KindIPCIDR, Values: []string{"198.51.100.0/24"}, Target: "proxy"}
	noResolve := matchIP
	noResolve.NoResolve = true
	passIP := matchIP
	passIP.Target = "pass"
	passDomain := RuleSpec{Kind: KindDomain, Values: []string{"resolve.test"}, Target: "pass"}
	fallback := RuleSpec{Kind: KindMatch, Target: "direct"}
	members, err := CompileRules([]RuleSpec{{Kind: KindDomain, Values: []string{"other.test"}}, matchIP})
	if err != nil {
		t.Fatal(err)
	}
	set := RuleSpec{Kind: KindRuleSet, Values: []string{"lan"}, Set: members, Target: "proxy"}
	unmatched := RuleSpec{Kind: KindDomain, Values: []string{"other.test"}, Target: "direct"}
	for _, tc := range []struct {
		name      string
		rules     []RuleSpec
		overrides []RuleSpec
		matched   int
		lookup    int
		trigger   RuleSpec
		temporary bool
	}{
		{name: "rule set", rules: []RuleSpec{unmatched, unmatched, set}, matched: 2, lookup: 2, trigger: set},
		{name: "no resolve", rules: []RuleSpec{noResolve, fallback}, matched: 1, lookup: -1},
		{name: "after pass", rules: []RuleSpec{passDomain, missIP, matchIP}, matched: 2, lookup: 1, trigger: missIP},
		{name: "at pass", rules: []RuleSpec{passIP, matchIP}, matched: 1, lookup: 0, trigger: passIP},
		{name: "temporary match", rules: []RuleSpec{fallback}, overrides: []RuleSpec{unmatched, matchIP}, matched: -1, lookup: 1, trigger: matchIP, temporary: true},
		{name: "temporary miss", rules: []RuleSpec{matchIP}, overrides: []RuleSpec{unmatched, missIP}, matched: 0, lookup: 1, trigger: missIP},
		{name: "saved rule after override", rules: []RuleSpec{matchIP}, overrides: []RuleSpec{noResolve}, matched: 0, lookup: 0, trigger: matchIP},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := mustRouter(t, tc.rules, nil, "direct", "proxy", "pass")
			env := &fakeEnv{addrs: map[string][]netip.Addr{"resolve.test": {netip.MustParseAddr("192.0.2.8")}}}
			md := Metadata{Domain: "resolve.test"}
			now := time.Now()
			var overrides []TimedRule
			for _, spec := range tc.overrides {
				match, err := CompileRules([]RuleSpec{spec})
				if err != nil {
					t.Fatal(err)
				}
				overrides = append(overrides, TimedRule{Match: match, ExpiresAt: now.Add(time.Minute)})
			}
			var d Decision
			if len(overrides) == 0 {
				d = r.Route(t.Context(), md, env)
			} else {
				d = r.ExplainWithOverrides(t.Context(), md, env, nil, overrides, now).Decision
			}
			if d.RuleIndex != tc.matched || d.Temporary != tc.temporary || d.LookupRule != tc.lookup {
				t.Fatalf("unexpected decision: %+v", d)
			}
			if d.LookupRuleSpec().String() != tc.trigger.String() {
				t.Fatalf("trigger = %s, want %s", d.LookupRuleSpec(), tc.trigger)
			}
			wantCalls := 0
			if tc.lookup >= 0 {
				wantCalls = 1
			}
			if env.resolves != wantCalls {
				t.Fatalf("lookup calls = %d, want %d", env.resolves, wantCalls)
			}
		})
	}
}

func TestPortsNetworkProcess(t *testing.T) {
	r := mustRouter(t, []RuleSpec{
		{Kind: KindProcessName, Values: []string{"curl"}, Target: "reject"},
		{Kind: KindNetwork, Values: []string{"udp"}, Target: "reject"},
		{Kind: KindDstPort, Values: []string{"8000-8999", "22"}, Target: "proxy"},
		{Kind: KindSrcPort, Values: []string{"5555"}, Target: "proxy"},
		{Kind: KindSrcIPCIDR, Values: []string{"127.0.0.0/8"}, Target: "proxy"},
	}, nil)
	ctx := context.Background()
	src := netip.MustParseAddrPort("192.0.2.1:40000")
	cases := []struct {
		md   Metadata
		env  *fakeEnv
		want string
	}{
		{Metadata{Network: "tcp", Source: src, Port: 8080}, nil, "proxy"},
		{Metadata{Network: "tcp", Source: src, Port: 22}, nil, "proxy"},
		{Metadata{Network: "tcp", Source: src, Port: 443}, nil, "direct"},
		{Metadata{Network: "udp", Source: src, Port: 443}, nil, "reject"},
		{Metadata{Network: "tcp", Source: netip.MustParseAddrPort("192.0.2.1:5555"), Port: 1}, nil, "proxy"},
		{Metadata{Network: "tcp", Source: netip.MustParseAddrPort("127.0.0.1:1"), Port: 1}, nil, "proxy"},
		{Metadata{Network: "tcp", Source: src, Port: 1}, &fakeEnv{process: "/usr/bin/curl"}, "reject"},
		{Metadata{Network: "tcp", Source: src, Port: 1}, &fakeEnv{process: `C:\Tools\CURL`}, "reject"},
	}
	for i, c := range cases {
		var env Env
		if c.env != nil {
			env = c.env
		}
		if d := r.Route(ctx, c.md, env); d.Outbound != c.want {
			t.Errorf("case %d: %s, want %s", i, d.Outbound, c.want)
		}
	}
}

func TestGroups(t *testing.T) {
	groups := []Group{
		{ID: "select", Members: []string{"auto", "direct"}, Selected: "auto"},
		{ID: "auto", Members: []string{"proxy", "direct"}},
	}
	r := mustRouter(t, []RuleSpec{{Kind: KindMatch, Target: "select"}}, groups)
	d := r.Route(context.Background(), Metadata{Domain: "x.test"}, nil)
	if d.Outbound != "proxy" || strings.Join(d.Chain, ">") != "select>auto" {
		t.Fatalf("got %+v", d)
	}
	rs, _ := CompileRules(nil)
	if _, err := New(rs, Options{Outbounds: []string{"direct"}, Groups: []Group{
		{ID: "a", Members: []string{"b"}}, {ID: "b", Members: []string{"a"}},
	}}); err == nil || !strings.Contains(err.Error(), "cycle") {
		t.Fatalf("cycle not detected: %v", err)
	}
	if _, err := New(rs, Options{Outbounds: []string{"direct"}, Groups: []Group{
		{ID: "a", Members: []string{"direct"}, Selected: "nope"},
	}}); err == nil {
		t.Fatal("selected non-member accepted")
	}
	rs, _ = CompileRules([]RuleSpec{{Kind: KindMatch, Target: "missing"}})
	if _, err := New(rs, Options{Outbounds: []string{"direct"}}); err == nil {
		t.Fatal("unknown target accepted")
	}
}

func TestExplainDoesNotResolve(t *testing.T) {
	r := mustRouter(t, []RuleSpec{
		{Kind: KindDomainSuffix, Values: []string{"cn"}, Target: "direct"},
		{Kind: KindIPCIDR, Values: []string{"10.0.0.0/8"}, Target: "reject"},
		{Kind: KindMatch, Target: "proxy"},
	}, nil)
	env := &fakeEnv{noLookup: true}
	ctx := context.Background()
	if x := r.Explain(ctx, Metadata{Domain: "a.cn"}, env); x.Undetermined || x.RuleIndex != 0 {
		t.Fatalf("a.cn: %+v", x)
	}
	if x := r.Explain(ctx, Metadata{Domain: "a.com"}, env); !x.Undetermined || x.StoppedAt != 1 {
		t.Fatalf("a.com: %+v", x)
	}
	if x := r.Explain(ctx, Metadata{Addr: netip.MustParseAddr("8.8.8.8")}, env); x.Undetermined || x.Outbound != "proxy" {
		t.Fatalf("8.8.8.8: %+v", x)
	}
}

func TestCompileErrors(t *testing.T) {
	for _, spec := range []RuleSpec{
		{Kind: KindIPCIDR, Values: []string{"300.0.0.0/8"}, Target: "x"},
		{Kind: KindDstPort, Values: []string{"9-1"}, Target: "x"},
		{Kind: KindDomainRegex, Values: []string{"("}, Target: "x"},
		{Kind: KindNetwork, Values: []string{"sctp"}, Target: "x"},
		{Kind: KindDomain, Target: "x"},
		{Kind: KindDomain, Values: []string{"a.test"}, NoResolve: true, Target: "x"},
		{Kind: KindMatch, Values: []string{"x"}, Target: "x"},
	} {
		if _, err := CompileRules([]RuleSpec{spec}); err == nil {
			t.Errorf("%v compiled", spec)
		}
	}
}

// randomRules builds a rule list that mixes indexed and unindexed kinds
// over a small vocabulary, so that overlaps (and duplicate keys) are common.
func randomRules(rng *rand.Rand, n int) []RuleSpec {
	labels := []string{"a", "b", "c", "cn", "com", "example", "x"}
	domain := func() string {
		k := 1 + rng.IntN(3)
		parts := make([]string, k)
		for i := range parts {
			parts[i] = labels[rng.IntN(len(labels))]
		}
		return strings.Join(parts, ".")
	}
	targets := []string{"direct", "proxy", "reject"}
	specs := make([]RuleSpec, n)
	for i := range specs {
		s := RuleSpec{Target: targets[rng.IntN(len(targets))]}
		switch rng.IntN(10) {
		case 0, 1, 2:
			s.Kind, s.Values = KindDomainSuffix, []string{domain()}
		case 3, 4:
			s.Kind, s.Values = KindDomain, []string{domain(), domain()}
		case 5:
			s.Kind, s.Values = KindDomainKeyword, []string{labels[rng.IntN(len(labels))]}
		case 6:
			s.Kind, s.Values = KindIPCIDR, []string{fmt.Sprintf("10.%d.0.0/16", rng.IntN(4))}
			s.NoResolve = rng.IntN(2) == 0
		case 7:
			s.Kind, s.Values = KindDstPort, []string{fmt.Sprint(80 + rng.IntN(3))}
		case 8:
			s.Kind, s.Values = KindDomainRegex, []string{"^" + labels[rng.IntN(len(labels))] + `\.`}
		default:
			s.Kind, s.Values = KindNetwork, []string{[]string{"tcp", "udp"}[rng.IntN(2)]}
		}
		specs[i] = s
	}
	return specs
}

// TestIndexMatchesLinear checks the indexed lookup against a plain scan
// over random rule lists and destinations.
func TestIndexMatchesLinear(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	labels := []string{"a", "b", "c", "cn", "com", "example", "x", "zz"}
	for round := 0; round < 300; round++ {
		specs := randomRules(rng, 1+rng.IntN(60))
		rs, err := CompileRules(specs)
		if err != nil {
			t.Fatal(err)
		}
		env := &fakeEnv{addrs: map[string][]netip.Addr{}}
		for q := 0; q < 50; q++ {
			md := Metadata{Network: []string{"tcp", "udp"}[rng.IntN(2)], Port: uint16(79 + rng.IntN(4))}
			if rng.IntN(5) == 0 {
				md.Addr = netip.AddrFrom4([4]byte{10, byte(rng.IntN(5)), 1, 1})
			} else {
				k := 1 + rng.IntN(4)
				parts := make([]string, k)
				for i := range parts {
					parts[i] = labels[rng.IntN(len(labels))]
				}
				md.Domain = strings.Join(parts, ".")
				if rng.IntN(2) == 0 {
					env.addrs[md.Domain] = []netip.Addr{netip.AddrFrom4([4]byte{10, byte(rng.IntN(5)), 2, 2})}
				}
			}
			got := rs.first(&evaluation{ctx: context.Background(), md: md, env: env})
			want := rs.firstLinear(&evaluation{ctx: context.Background(), md: md, env: env})
			if got != want {
				t.Fatalf("round %d: %+v: index %d, linear %d\nrules: %v", round, md, got, want, specs)
			}
		}
	}
}

// suffixRules builds n inline domain-suffix and domain rules, the shape
// subscriptions ship, plus a few unindexed ones and a final match.
func suffixRules(n int) []RuleSpec {
	specs := make([]RuleSpec, 0, n+3)
	for i := 0; i < n; i++ {
		kind := KindDomainSuffix
		if i%10 == 0 {
			kind = KindDomain
		}
		specs = append(specs, RuleSpec{Kind: kind, Values: []string{fmt.Sprintf("site%d.example%d.com", i, i%97)}, Target: "proxy"})
		if i%1000 == 500 {
			specs = append(specs, RuleSpec{Kind: KindDomainKeyword, Values: []string{fmt.Sprintf("kw%d", i)}, Target: "reject"})
		}
	}
	specs = append(specs, RuleSpec{Kind: KindIPCIDR, Values: []string{"10.0.0.0/8"}, NoResolve: true, Target: "direct"})
	specs = append(specs, RuleSpec{Kind: KindMatch, Target: "proxy"})
	return specs
}

func TestTenThousandRules(t *testing.T) {
	specs := suffixRules(10000)
	start := time.Now()
	rs, err := CompileRules(specs)
	if err != nil {
		t.Fatal(err)
	}
	r, err := New(rs, Options{Outbounds: []string{"direct", "proxy", "reject"}, Final: "direct"})
	if err != nil {
		t.Fatal(err)
	}
	compile := time.Since(start)
	d := r.Route(context.Background(), Metadata{Domain: "a.site9999.example8.com"}, nil)
	if d.RuleIndex < 0 || d.Rule.Values[0] != "site9999.example8.com" {
		t.Fatalf("got %+v", d)
	}
	t.Logf("compiled %d rules in %v", len(specs), compile)
	if compile > 500*time.Millisecond {
		t.Errorf("compiling 10k rules took %v", compile)
	}
}

func BenchmarkCompile10k(b *testing.B) {
	specs := suffixRules(10000)
	for b.Loop() {
		if _, err := CompileRules(specs); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRoute10k(b *testing.B) {
	specs := suffixRules(10000)
	rs, _ := CompileRules(specs)
	r, _ := New(rs, Options{Outbounds: []string{"direct", "proxy", "reject"}, Final: "direct"})
	queries := []Metadata{
		{Domain: "www.site1234.example70.com", Network: "tcp", Port: 443},
		{Domain: "unmatched.domain.test", Network: "tcp", Port: 443},
		{Addr: netip.MustParseAddr("10.1.1.1"), Network: "tcp", Port: 443},
	}
	ctx := context.Background()
	for i := 0; b.Loop(); i++ {
		r.Route(ctx, queries[i%len(queries)], nil)
	}
}
