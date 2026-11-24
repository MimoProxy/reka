package router

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestPreMatchAgreesWithRouteAcrossLookupOutcomes(t *testing.T) {
	rng := rand.New(rand.NewPCG(23, 57))
	var decided [3]int
	for range 512 {
		for i, hit := range checkPreMatchAgreement(t, rng.Uint64()) {
			if hit {
				decided[i]++
			}
		}
	}
	for i, name := range []string{"IP with no domain", "IP with a pending domain", "known domain with no IP"} {
		if decided[i] == 0 {
			t.Errorf("pre-match never decided for %s", name)
		}
	}
}

func FuzzPreMatchAgreesWithRoute(f *testing.F) {
	for _, seed := range []uint64{0, 1, 42, ^uint64(0)} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, seed uint64) {
		checkPreMatchAgreement(t, seed)
	})
}

type preMatchPropertyEnv struct {
	info  ProcessInfo
	found bool
	addrs []netip.Addr
	err   error
}

func (e preMatchPropertyEnv) Process(context.Context) (string, bool) {
	return e.info.Path, e.found && e.info.Path != ""
}

func (e preMatchPropertyEnv) ProcessInfo(context.Context) (ProcessInfo, bool) {
	return e.info, e.found
}

func (e preMatchPropertyEnv) Resolve(context.Context, string) ([]netip.Addr, error) {
	return e.addrs, e.err
}

type preMatchRuleGenerator struct {
	rng     *rand.Rand
	domains [2]string
	sets    [2]*RuleSet
}

func (g *preMatchRuleGenerator) condition(depth int) RuleSpec {
	kinds := []Kind{
		KindDomain, KindDomainSuffix, KindDomainKeyword, KindDomainRegex, KindDomainPattern,
		KindIPCIDR, KindGeoIP, KindDstPort, KindSrcPort, KindNetwork, KindProcessName,
		KindProcessPath, KindUID, KindInboundName, KindNetworkScene, KindMatch,
	}
	if g.sets[0] != nil {
		kinds = append(kinds, KindRuleSet)
	}
	if depth > 0 {
		kinds = append(kinds, KindAnd, KindOr, KindNot)
	}
	spec := RuleSpec{Kind: choosePreMatchValue(g.rng, kinds...)}
	domain := g.domains[g.rng.IntN(len(g.domains))]
	switch spec.Kind {
	case KindDomain, KindDomainSuffix:
		spec.Values = []string{domain}
	case KindDomainKeyword:
		label, _, _ := strings.Cut(domain, ".")
		spec.Values = []string{label}
	case KindDomainRegex:
		spec.Values = []string{`^` + regexp.QuoteMeta(domain) + `$`}
	case KindDomainPattern:
		spec.Values = []string{"." + domain}
	case KindIPCIDR:
		spec.Values = []string{choosePreMatchValue(g.rng, "192.0.2.0/24", "2001:db8::/32")}
		spec.NoResolve = g.rng.IntN(2) == 0
	case KindGeoIP:
		spec.Values = []string{"LAN"}
		spec.NoResolve = g.rng.IntN(2) == 0
	case KindDstPort:
		spec.Values = []string{choosePreMatchValue(g.rng, "443", "8000-9000")}
	case KindSrcPort:
		spec.Values = []string{choosePreMatchValue(g.rng, "10000", "60000-61000")}
	case KindNetwork:
		spec.Values = []string{choosePreMatchValue(g.rng, "tcp", "udp")}
	case KindProcessName:
		spec.Values = []string{"browser"}
	case KindProcessPath:
		spec.Values = []string{"/opt/tools/fetcher"}
	case KindUID:
		spec.Values = []string{choosePreMatchValue(g.rng, "1000", "1500-1503")}
	case KindInboundName:
		spec.Values = []string{choosePreMatchValue(g.rng, "tun", "lan")}
	case KindNetworkScene:
		spec.Values = []string{choosePreMatchValue(g.rng, "wifi", "cellular")}
	case KindRuleSet:
		spec.Set = g.sets[g.rng.IntN(len(g.sets))]
		spec.Values = []string{"members"}
		spec.NoResolve = g.rng.IntN(2) == 0
	case KindAnd, KindOr:
		spec.Children = []RuleSpec{g.condition(depth - 1), g.condition(depth - 1)}
	case KindNot:
		spec.Children = []RuleSpec{g.condition(depth - 1)}
	}
	return spec
}

func choosePreMatchValue[T any](rng *rand.Rand, values ...T) T {
	return values[rng.IntN(len(values))]
}

func checkPreMatchAgreement(t testing.TB, seed uint64) (decided [3]bool) {
	t.Helper()
	rng := rand.New(rand.NewPCG(seed, 57))
	g := preMatchRuleGenerator{rng: rng, domains: [2]string{
		fmt.Sprintf("site-%x.test", rng.Uint64()), fmt.Sprintf("site-%x.test", rng.Uint64()),
	}}
	var builder ConditionSetBuilder
	var members []RuleSpec
	for range rng.IntN(6) + 1 {
		spec := g.condition(0)
		members = append(members, spec)
		if err := builder.Add(spec); err != nil {
			t.Fatalf("seed %d: add set member: %v", seed, err)
		}
	}
	var err error
	if g.sets[0], err = CompileRules(members); err != nil {
		t.Fatalf("seed %d: compile set: %v", seed, err)
	}
	if g.sets[1], err = builder.Build(); err != nil {
		t.Fatalf("seed %d: build set: %v", seed, err)
	}
	outbounds := []string{"direct", "reject", "pass"}
	groups := []Group{
		{ID: "choice", Members: outbounds, Selected: choosePreMatchValue(rng, outbounds...)},
		{ID: "nested", Members: []string{"choice", "direct"}},
	}
	rule := func() RuleSpec {
		spec := g.condition(3)
		spec.Target = choosePreMatchValue(rng, "direct", "reject", "pass", "choice", "nested")
		return spec
	}
	rules := make([]RuleSpec, rng.IntN(18))
	for i := range rules {
		rules[i] = rule()
	}
	set, err := CompileRules(rules)
	if err != nil {
		t.Fatalf("seed %d: compile rules: %v", seed, err)
	}
	final := choosePreMatchValue(rng, "direct", "reject", "pass", "choice", "nested")
	r, err := New(set, Options{Outbounds: outbounds, Groups: groups, Final: final})
	if err != nil {
		t.Fatalf("seed %d: build router: %v", seed, err)
	}
	at := time.Unix(100, 0)
	opts := PreMatchOptions{At: at}
	for range rng.IntN(4) {
		match, err := CompileRules([]RuleSpec{rule()})
		if err != nil {
			t.Fatalf("seed %d: compile override: %v", seed, err)
		}
		expiry := at.Add(choosePreMatchValue(rng, -time.Second, time.Second))
		opts.Overrides = append(opts.Overrides, TimedRule{Match: match, ExpiresAt: expiry})
	}
	var resolve func(*Decision)
	if rng.IntN(2) == 0 {
		choice := choosePreMatchValue(rng, outbounds...)
		peek := func(target string) (outbound string, chain []string, ok bool) {
			outbound, chain, err := r.ResolveDynamic(target, func(group Group) string {
				if group.ID == "choice" {
					return choice
				}
				return group.Selected
			})
			return outbound, chain, err == nil
		}
		opts.Peek = peek
		resolve = func(d *Decision) { d.Outbound, d.Chain, _ = peek(d.Target) }
	}

	insideV4 := netip.MustParseAddr("192.0.2.7")
	insideV6 := netip.MustParseAddr("2001:db8::7")
	outside := netip.MustParseAddr("203.0.113.7")
	lan := netip.MustParseAddr("192.168.1.7")
	packet := Metadata{
		Addr:         choosePreMatchValue(rng, insideV4, insideV6, outside, lan),
		Port:         choosePreMatchValue[uint16](rng, 53, 443, 8443),
		Source:       netip.AddrPortFrom(lan, choosePreMatchValue[uint16](rng, 9999, 10000, 60007)),
		Network:      choosePreMatchValue(rng, "tcp", "udp"),
		Inbound:      choosePreMatchValue(rng, "tun", "lan", "other"),
		NetworkScene: choosePreMatchValue(rng, "wifi", "cellular", "ethernet"),
	}
	domains := []string{"", g.domains[0], "sub." + g.domains[0], g.domains[1], "sub." + g.domains[1], fmt.Sprintf("random-%x.test", rng.Uint64())}
	paths := []string{"", "browser", "/usr/bin/browser", "/opt/tools/fetcher", fmt.Sprintf("/opt/random-%x", rng.Uint64())}
	uids := []uint32{0, 1000, 1501, rng.Uint32()}
	dns := []preMatchPropertyEnv{
		{addrs: []netip.Addr{insideV4}}, {addrs: []netip.Addr{insideV6}},
		{addrs: []netip.Addr{outside}}, {addrs: []netip.Addr{lan}},
		{err: errors.New("DNS lookup failed")},
	}
	var outcomes []preMatchPropertyEnv
	for _, path := range paths {
		for _, uid := range uids {
			for _, env := range dns {
				env.info = ProcessInfo{Path: path, UID: uid, UIDKnown: uid != 0}
				env.found = path != "" || env.info.UIDKnown
				outcomes = append(outcomes, env)
			}
		}
	}
	fakeIP := packet
	fakeIP.Addr, fakeIP.Domain = netip.Addr{}, choosePreMatchValue(rng, domains[1:]...)
	for i, flow := range []struct {
		md      Metadata
		pending bool
		domains []string
	}{
		{packet, false, domains[:1]},
		{packet, true, domains},
		{fakeIP, false, []string{fakeIP.Domain}},
	} {
		md := flow.md
		opts.DomainPending = flow.pending
		result := r.PreMatch(t.Context(), md, opts)
		if !result.Decided {
			continue
		}
		decided[i] = true
		for _, domain := range flow.domains {
			md.Domain = domain
			for _, env := range outcomes {
				var full Decision
				if len(opts.Overrides) == 0 {
					full = r.RouteWithResolver(t.Context(), md, env, resolve)
				} else {
					full = r.ExplainWithOverrides(t.Context(), md, env, resolve, opts.Overrides, at).Decision
				}
				if before := result.Decision; full.Outbound != before.Outbound || full.RuleIndex != before.RuleIndex {
					t.Fatalf("seed %d, domain pending %v, flow %+v, environment %+v: pre-match rule %d -> %q, full rule %d -> %q; rules %v, final %q",
						seed, opts.DomainPending, md, env, before.RuleIndex, before.Outbound, full.RuleIndex, full.Outbound, rules, final)
				}
			}
		}
	}
	return decided
}
