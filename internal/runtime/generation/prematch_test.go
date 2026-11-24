package generation

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MimoProxy/reka/internal/api"
	"github.com/MimoProxy/reka/internal/backend/sagernet"
	"github.com/MimoProxy/reka/internal/config/compile"
	"github.com/MimoProxy/reka/internal/config/model"
	"github.com/MimoProxy/reka/internal/dns"
	"github.com/MimoProxy/reka/internal/policy"
	D "github.com/miekg/dns"
)

func TestPreMatchAgreesWithRoute(t *testing.T) {
	const (
		ipReject    = "rules: [{id: deny-address, match: {ip-cidr: 192.0.2.0/24}, outbound: reject}]\n"
		afterDomain = `rules:
  - {match: {domain: allowed.test}, outbound: direct}
  - {id: deny-address, match: {ip-cidr: 192.0.2.0/24}, outbound: reject}
`
		beforeDomain = `rules:
  - {id: deny-address, match: {ip-cidr: 192.0.2.0/24}, outbound: reject}
  - {match: {domain: allowed.test}, outbound: direct}
`
		drop          = "rules: [{id: discard, match: {all: true}, outbound: reject-drop}]\n"
		direct        = "rules: [{match: {all: true}, outbound: direct}]\n"
		sniffedDomain = `rules:
  - {match: {domain: blocked.test}, outbound: reject}
  - {match: {all: true}, outbound: direct}
`
		proxy = `outbounds: [{id: proxy, type: socks, server: 192.0.2.45, port: 1080}]
rules: [{match: {all: true}, outbound: proxy}]
`
	)
	const (
		cont       = sagernet.PreMatchContinue
		reject     = sagernet.PreMatchReject
		dropAction = sagernet.PreMatchDrop
	)
	tcp := preMatchTestMetadata("tcp", 443)
	udp := preMatchTestMetadata("udp", 443)
	quic := preMatchTestMetadata("udp", 8443)
	quic.Protocol = "quic"
	blocked := tcp
	blocked.SniffedDomain = "blocked.test"
	sniffed := tcp
	sniffed.SniffedDomain = "allowed.test"

	cases := []struct {
		name, profile  string
		md             sagernet.Metadata
		want           sagernet.PreMatchAction
		routed, reason string
	}{
		{"IP rule with no domain rules", ipReject, tcp, reject, "", ""},
		{"IP rule before a sniffable domain rule", beforeDomain, sniffed, reject, "", ""},
		{"IP rule after a sniffable domain rule", afterDomain, tcp, cont, "", ""},
		{"sniffed domain may allow the flow", afterDomain, sniffed, cont, "direct", ""},
		{"IP rule after a domain rule with sniffing disabled", "sniff: {enabled: false}\n" + afterDomain, tcp, reject, "", ""},
		{"default sniffing preserves a known sniffed domain", sniffedDomain, blocked, reject, "", ""},
		{"existing sniffed domain may be replaced", "sniff: {enabled: true}\n" + sniffedDomain, blocked, cont, "", ""},
		{"replacement sniffed domain may allow the flow", "sniff: {enabled: true}\n" + sniffedDomain, sniffed, cont, "direct", ""},
		{"reject-drop TCP", drop, tcp, dropAction, "reject-drop", ""},
		{"reject-drop UDP bypasses block-quic", "routing: {block-quic: all}\n" + drop, udp, dropAction, "reject-drop", ""},
		{"named reject outbound", `outbounds: [{id: denied, type: reject}]
rules: [{match: {all: true}, outbound: denied}]
`, tcp, reject, "", ""},
		{"select group rejects", `groups: [{id: policy, type: select, members: [direct, reject], selected: reject}]
rules: [{match: {all: true}, outbound: policy}]
`, tcp, reject, "", ""},
		{"dynamic round robin is undecided", `groups: [{id: policy, type: load-balance, strategy: round-robin, members: [reject, direct]}]
rules: [{match: {all: true}, outbound: policy}]
`, tcp, cont, "", ""},
		{"dynamic consistent hashing is undecided", `groups: [{id: policy, type: load-balance, strategy: consistent-hashing, members: [reject, direct]}]
rules: [{match: {all: true}, outbound: policy}]
`, tcp, cont, "", ""},
		{"load balancing with an explicit choice rejects", `groups: [{id: policy, type: load-balance, members: [direct, reject], selected: reject}]
rules: [{match: {all: true}, outbound: policy}]
`, tcp, reject, "", ""},
		{"observed fallback does not depend on the flow", `groups: [{id: policy, type: fallback, members: [reject, direct]}]
rules: [{match: {all: true}, outbound: policy}]
`, tcp, reject, "", ""},
		{"group disallows UDP before block-quic", `routing: {block-quic: all}
groups: [{id: policy, type: select, members: [reject-drop], disable-udp: true}]
rules: [{match: {all: true}, outbound: policy}]
`, udp, reject, "", ""},
		{"outbound disallows UDP before block-quic", `routing: {block-quic: all}
outbounds: [{id: tcp-only, type: http, server: 192.0.2.45, port: 8080}]
rules: [{match: {all: true}, outbound: tcp-only}]
`, udp, reject, "", ""},
		{"block-quic off", "routing: {block-quic: off}\n" + proxy, udp, cont, "proxy", ""},
		{"block-quic proxy", "routing: {block-quic: proxy}\n" + proxy, udp, reject, "", "block-quic"},
		{"block-quic proxy direct exception", "routing: {block-quic: proxy}\n" + direct, udp, cont, "direct", ""},
		{"block-quic all", "routing: {block-quic: all}\n" + direct, udp, reject, "", "block-quic"},
		{"block-quic with already-known QUIC", "routing: {block-quic: all}\n" + direct, quic, reject, "", "block-quic"},
		{"block-quic cannot assume other UDP is QUIC", "routing: {block-quic: all}\nsniff: {enabled: true}\n" + direct, preMatchTestMetadata("udp", 8443), cont, "direct", ""},
		{"global mode ignores saved rules", "routing: {mode: global, global: reject}\n" + direct, tcp, reject, "", ""},
		{"global mode selects drop", "routing: {mode: global, global: reject-drop}\n" + drop, tcp, dropAction, "reject-drop", ""},
		{"direct mode ignores saved rules", "routing: {mode: direct}\n" + ipReject, tcp, cont, "direct", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e, observations := preMatchTestEngine(t, EngineOptions{HostPacketFlow: true})
			pinFlowApply(t, e, "schema-version: 1\n"+tc.profile, "", 42)
			checkPreMatchAgainstRoute(t, e, observations, tc.md, tc.want, tc.routed, tc.reason)
		})
	}
}

func TestPreMatchInboundAdmission(t *testing.T) {
	e, observations := preMatchTestEngine(t, EngineOptions{})
	udp := preMatchTestMetadata("udp", 443)
	if got := e.preMatch(udp); got.Action != sagernet.PreMatchContinue {
		t.Fatalf("unconfigured generation returned %v", got.Action)
	}
	pinFlowApply(t, e, "schema-version: 1\nrules: [{match: {all: true}, outbound: reject-drop}]\n", "", 42)
	checkPreMatchAgainstRoute(t, e, observations, udp, sagernet.PreMatchReject, "", "")
	for _, inbound := range []string{"mixed", "socks", ""} {
		md := preMatchTestMetadata("tcp", 443)
		md.InboundType = inbound
		checkPreMatchAgainstRoute(t, e, observations, md, sagernet.PreMatchContinue, "reject-drop", "")
	}
}

func TestPreMatchTemporaryRuleAndNetworkScene(t *testing.T) {
	e, observations := preMatchTestEngine(t, EngineOptions{HostPacketFlow: true})
	const profile = `schema-version: 1
groups: [{id: policy, type: select, members: [reject-drop]}]
rules:
  - id: deny-lab
    match: {and: [{network-scene: lab}, {in-type: tun}, {in-port: 8080}]}
    outbound: policy
  - {match: {all: true}, outbound: direct}
`
	eff, diagnostics := compile.Compile([]byte(profile), []byte("network-scenes: [{id: lab}]\n"), compile.Options{})
	if diagnostics.HasErrors() {
		t.Fatal(diagnostics)
	}
	p, err := e.Prepare(eff)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.activateProfile(p, 42, "test-profile", map[string]string{"policy": "Policy", "reject-drop": "Drop"}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.SetNetworkScene("lab"); err != nil {
		t.Fatal(err)
	}
	md := preMatchTestMetadata("tcp", 443)
	md.InboundPort = 8080
	info := checkPreMatchAgainstRoute(t, e, observations, md, sagernet.PreMatchDrop, "reject-drop", "")
	if info.RuleID != "deny-lab" || info.NetworkScene != "lab" || info.PolicyName != "Policy" || info.OutboundName != "Drop" {
		t.Fatalf("incorrect scene routing info: %+v", info)
	}
	rule, err := e.AddTemporaryRule(api.TemporaryRuleRequest{Rule: "IP-CIDR,192.0.2.0/24,reject", TTLSeconds: 300})
	if err != nil {
		t.Fatal(err)
	}
	info = checkPreMatchAgainstRoute(t, e, observations, md, sagernet.PreMatchReject, "", "")
	if info.RuleSource != "temporary" || info.RuleID != rule.ID || info.NetworkScene != "lab" {
		t.Fatalf("incorrect temporary rule info: %+v", info)
	}
	rules := e.temporary.Load()
	expired := *rules
	expired.rules = append(expired.rules[:0:0], rules.rules...)
	expired.rules[0].ExpiresAt = time.Now().Add(-time.Minute)
	e.temporary.Store(&expired)
	checkPreMatchAgainstRoute(t, e, observations, md, sagernet.PreMatchDrop, "reject-drop", "")
}

func TestPreMatchFakeIPDoesNotChangePool(t *testing.T) {
	e, observations := preMatchTestEngine(t, EngineOptions{HostPacketFlow: true})
	e.fake.Close()
	e.fake = dns.NewFakePool(2)
	pinFlowApply(t, e, `schema-version: 1
rules:
  - {match: {ip-cidr: 198.18.0.0/29, no-resolve: true}, outbound: direct}
  - {match: {domain: mapped.test}, outbound: reject-drop}
  - {match: {all: true}, outbound: direct}
`, "", 42)
	prefix := netip.MustParsePrefix("198.18.0.0/29")
	allocate := func(domain string) netip.Addr {
		t.Helper()
		ip, err := e.fake.Allocate(1, domain, prefix)
		if err != nil {
			t.Fatal(err)
		}
		return ip
	}
	mapped, recent := allocate("mapped.test"), allocate("recent.test")
	md := preMatchTestMetadata("tcp", 443)
	md.Destination.Addr = mapped
	if got := e.preMatch(md); got.Action != sagernet.PreMatchDrop || got.Info.(*FlowInfo).DestinationDomain != "mapped.test" {
		t.Fatalf("mapped destination returned %+v", got)
	}
	if size := e.fake.Size(); size != 2 {
		t.Fatalf("pre-match changed the pool size to %d", size)
	}
	allocate("new.test")
	if _, ok := e.fake.Peek(mapped); ok {
		t.Fatal("pre-match leased the mapping or changed its recency")
	}
	if domain, ok := e.fake.Peek(recent); !ok || domain != "recent.test" {
		t.Fatalf("pre-match changed the other mapping: %q, %t", domain, ok)
	}
	checkPreMatchAgainstRoute(t, e, observations, md, sagernet.PreMatchReject, "", "fake-ip-unavailable")
	md.Destination.Addr = allocate("mapped.test")
	checkPreMatchAgainstRoute(t, e, observations, md, sagernet.PreMatchDrop, "reject-drop", "")
}

func TestPreMatchUsesObservedPoliciesWithoutAdvancingRoundRobin(t *testing.T) {
	e, observations := preMatchTestEngine(t, EngineOptions{})
	eff, diagnostics := compile.Compile([]byte(`schema-version: 1
groups:
  - {id: balanced, type: load-balance, strategy: round-robin, lazy: false, members: [reject, direct]}
  - {id: tested, type: url-test, lazy: false, members: [direct, reject-drop], url: http://health.test/url-test}
rules:
  - {match: {dst-port: 8443}, outbound: tested}
  - {match: {all: true}, outbound: balanced}
`), nil, compile.Options{})
	if diagnostics.HasErrors() {
		t.Fatal(diagnostics)
	}
	p, err := e.Prepare(eff)
	if err != nil {
		t.Fatal(err)
	}
	manager := policy.New(eff.AutoGroups, func(_ context.Context, member, url string) error {
		if member == "direct" && url == "http://health.test/url-test" {
			return errors.New("unavailable in URL test")
		}
		return nil
	})
	p.policies = manager
	if _, err := e.Activate(p, 42); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		groups := e.GroupStatus()
		results := groups[0].Results
		if results[0].Alive && results[1].Alive && groups[1].Selected == "reject-drop" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("expected health selections were unavailable: %+v", groups)
		}
		time.Sleep(time.Millisecond)
	}
	checkPreMatchAgainstRoute(t, e, observations, preMatchTestMetadata("tcp", 8443), sagernet.PreMatchDrop, "reject-drop", "")
	if next := manager.Peek("balanced", "", ""); next != "reject" {
		t.Fatalf("unexpected first member %q", next)
	}
	md := preMatchTestMetadata("tcp", 443)
	checkPreMatchAgainstRoute(t, e, observations, md, sagernet.PreMatchContinue, "", "")
	if next := manager.Peek("balanced", "", ""); next != "direct" {
		t.Fatalf("pre-match and the subsequent route should consume one choice, next member is %q", next)
	}
}

func TestPreMatchDoesNotLookUpDNSOrProcess(t *testing.T) {
	t.Run("DNS", func(t *testing.T) {
		var lookups atomic.Int32
		e, observations := preMatchTestEngine(t, EngineOptions{})
		resolver, err := dns.New(dns.Config{Nameservers: []string{"192.0.2.53"}}, dns.Options{
			Exchange: func(_ context.Context, _ dns.Endpoint, q *D.Msg, _ func(context.Context, string) ([]netip.Addr, error)) (*D.Msg, error) {
				lookups.Add(1)
				reply := new(D.Msg).SetReply(q)
				if question := q.Question[0]; question.Qtype == D.TypeA {
					reply.Answer = []D.RR{&D.A{
						Hdr: D.RR_Header{Name: question.Name, Rrtype: D.TypeA, Class: D.ClassINET},
						A:   net.IPv4(192, 0, 2, 20),
					}}
				}
				return reply, nil
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(resolver.Retire)
		eff, diagnostics := compile.Compile([]byte(`schema-version: 1
rules:
  - {match: {ip-cidr: 192.0.2.0/24}, outbound: direct}
  - {match: {all: true}, outbound: reject}
`), nil, compile.Options{})
		if diagnostics.HasErrors() {
			t.Fatal(diagnostics)
		}
		p, err := e.Prepare(eff)
		if err != nil {
			t.Fatal(err)
		}
		p.dns = resolver
		if _, err := e.Activate(p, 42); err != nil {
			t.Fatal(err)
		}
		md := preMatchTestMetadata("tcp", 443)
		md.Destination = sagernet.Destination{Domain: "lookup.test", Port: 443}
		if got := e.preMatch(md); got.Action != sagernet.PreMatchContinue || lookups.Load() != 0 {
			t.Fatalf("pre-match returned %v with %d lookups", got.Action, lookups.Load())
		}
		checkPreMatchAgainstRoute(t, e, observations, md, sagernet.PreMatchContinue, "direct", "")
		if lookups.Load() == 0 {
			t.Fatal("normal routing did not exercise the DNS fixture")
		}
	})

	t.Run("process", func(t *testing.T) {
		var lookups int
		e, observations := preMatchTestEngine(t, EngineOptions{Backend: sagernet.Options{
			ProcessInfoLookup: func(context.Context, sagernet.Metadata) (sagernet.ProcessInfo, bool) {
				lookups++
				return sagernet.ProcessInfo{Path: "/test/allowed"}, true
			},
		}})
		eff, diagnostics := compile.Compile([]byte(`schema-version: 1
rules:
  - {match: {process-name: allowed}, outbound: direct}
  - {match: {all: true}, outbound: reject}
`), nil, compile.Options{ProcessLookup: true})
		if diagnostics.HasErrors() {
			t.Fatal(diagnostics)
		}
		p, err := e.Prepare(eff)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := e.Activate(p, 42); err != nil {
			t.Fatal(err)
		}
		md := preMatchTestMetadata("tcp", 443)
		if got := e.preMatch(md); got.Action != sagernet.PreMatchContinue || lookups != 0 {
			t.Fatalf("pre-match returned %v with %d lookups", got.Action, lookups)
		}
		checkPreMatchAgainstRoute(t, e, observations, md, sagernet.PreMatchContinue, "direct", "")
		if lookups != 1 {
			t.Fatalf("normal routing made %d process lookups, want one", lookups)
		}
	})
}

func preMatchTestEngine(t *testing.T, opts EngineOptions) (*Engine, *[]RouteObservation) {
	t.Helper()
	var observations []RouteObservation
	opts.ObserveRoute = func(o RouteObservation) { observations = append(observations, o) }
	e := NewEngine(opts)
	t.Cleanup(func() { e.Close() })
	return e, &observations
}

func preMatchTestMetadata(network string, port uint16) sagernet.Metadata {
	return sagernet.Metadata{
		Inbound: "tun", InboundType: "tun", InboundProtocol: "tun", Network: network,
		Source:      netip.MustParseAddrPort("198.51.100.14:54321"),
		Destination: sagernet.Destination{Addr: netip.MustParseAddr("192.0.2.20"), Port: port},
	}
}

func checkPreMatchAgainstRoute(t *testing.T, e *Engine, observations *[]RouteObservation, md sagernet.Metadata, want sagernet.PreMatchAction, routed, reason string) *FlowInfo {
	t.Helper()
	*observations = nil
	groups := e.GroupStatus()
	got := e.preMatch(md)
	if got.Action != want {
		t.Fatalf("pre-match action = %v, want %v", got.Action, want)
	}
	if after := e.GroupStatus(); !reflect.DeepEqual(groups, after) {
		t.Fatalf("pre-match changed group state from %+v to %+v", groups, after)
	}
	beforeRoute := *observations
	*observations = nil
	route := e.route(t.Context(), md)
	var tag string
	if route.Outbound != nil {
		defer route.Release()
		tag = route.Outbound.Tag()
		if got.Action != sagernet.PreMatchContinue {
			typ := route.Outbound.Type()
			if got.Action == sagernet.PreMatchReject && typ != model.OutboundReject ||
				got.Action == sagernet.PreMatchDrop && typ != "reject-drop" {
				t.Fatalf("pre-match action %v differs from routed outbound type %q", got.Action, typ)
			}
		}
	} else if got.Action == sagernet.PreMatchDrop {
		t.Fatal("pre-match would silently drop an actively rejected route")
	}
	if tag != routed {
		t.Fatalf("route outbound = %q, want %q", tag, routed)
	}
	if got.Action == sagernet.PreMatchContinue {
		if len(beforeRoute) != 0 {
			t.Fatalf("continuing flow was observed before routing: %+v", beforeRoute)
		}
		return nil
	}
	info, ok := got.Info.(*FlowInfo)
	if !ok || info.RejectReason != reason || got.Scope != route.Scope {
		t.Fatalf("pre-match info or scope differed from expected: %+v, route scope %+v", got, route.Scope)
	}
	if len(beforeRoute) != 1 || !reflect.DeepEqual(beforeRoute, *observations) {
		t.Fatalf("pre-match observations %+v differ from normal route %+v", beforeRoute, *observations)
	}
	if routedInfo, ok := route.Info.(*FlowInfo); ok {
		if !reflect.DeepEqual(info, routedInfo) {
			t.Fatalf("pre-match flow info %+v differs from normal route %+v", info, routedInfo)
		}
	} else if reason != "fake-ip-unavailable" || route.Info != nil ||
		info.Generation != route.Scope.Generation || info.Revision != route.Scope.Revision {
		t.Fatalf("unexpected route info %v, pre-match flow info %+v", route.Info, info)
	}
	return info
}
