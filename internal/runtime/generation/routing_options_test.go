package generation

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"testing"

	"github.com/MimoProxy/reka/internal/backend/sagernet"
	"github.com/MimoProxy/reka/internal/config/compile"
)

func activateProfile(t *testing.T, e *Engine, profile string, revision uint64) {
	t.Helper()
	eff, ds := compile.Compile([]byte(profile), nil, compile.Options{})
	if ds.HasErrors() {
		t.Fatal(ds)
	}
	prepared, err := e.Prepare(eff)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.Activate(prepared, revision); err != nil {
		t.Fatal(err)
	}
}

func routeTag(t *testing.T, e *Engine, md sagernet.Metadata) (string, *FlowInfo) {
	t.Helper()
	rt := e.route(context.Background(), md)
	var tag string
	if rt.Outbound != nil {
		defer rt.Release()
		tag = rt.Outbound.Tag()
	}
	return tag, rt.Info.(*FlowInfo)
}

func TestRouteUDPFallback(t *testing.T) {
	const profile = `schema-version: 1
routing: {udp-fallback: %s}
outbounds:
  - {id: tcp-only, type: http, server: 127.0.0.1, port: 9}
  - {id: node, type: socks, server: 127.0.0.1, port: 9}
groups:
  - {id: no-udp, type: select, members: [node], selected: node, disable-udp: true}
rules:
  - {match: {domain: http.test}, outbound: tcp-only}
  - {match: {domain: group.test}, outbound: no-udp}
  - {match: {domain: reject.test}, outbound: reject}
  - {match: {all: true}, outbound: node}
`
	e := NewEngine(EngineOptions{HostPacketFlow: true})
	defer e.Close()
	for i, mode := range []string{"reject", "direct"} {
		activateProfile(t, e, fmt.Sprintf(profile, mode), uint64(i+1))
		for _, tt := range []struct{ domain, original string }{{"http.test", "tcp-only"}, {"group.test", "node"}} {
			tag, info := routeTag(t, e, sagernet.Metadata{
				InboundType: "tun", Network: "udp", Destination: sagernet.Destination{Domain: tt.domain, Port: 3478},
			})
			if mode == "reject" {
				if tag != "" || info.RejectReason != udpUnsupported || info.UDPFallback != "" {
					t.Fatalf("%s %s: routed to %q, reason %q, fallback %q", mode, tt.domain, tag, info.RejectReason, info.UDPFallback)
				}
				continue
			}
			if tag != "direct" || info.Outbound != "direct" || info.UDPFallback != tt.original || info.RejectReason != "" {
				t.Fatalf("%s %s: routed to %q (info %q), fallback %q, reason %q", mode, tt.domain, tag, info.Outbound, info.UDPFallback, info.RejectReason)
			}
		}
		// A reject rule still rejects UDP.
		if tag, info := routeTag(t, e, sagernet.Metadata{InboundType: "tun", Network: "udp", Destination: sagernet.Destination{Domain: "reject.test", Port: 3478}}); tag != "" || info.Outbound != "reject" || info.UDPFallback != "" || info.RejectReason != "" {
			t.Fatalf("%s reject: routed to %q (info %q), fallback %q, reason %q", mode, tag, info.Outbound, info.UDPFallback, info.RejectReason)
		}
		// TCP and UDP-capable routes are unchanged.
		if tag, info := routeTag(t, e, sagernet.Metadata{InboundType: "tun", Network: "tcp", Destination: sagernet.Destination{Domain: "http.test", Port: 80}}); tag != "tcp-only" || info.UDPFallback != "" {
			t.Fatalf("%s TCP: routed to %q, fallback %q", mode, tag, info.UDPFallback)
		}
		if tag, _ := routeTag(t, e, sagernet.Metadata{InboundType: "tun", Network: "udp", Destination: sagernet.Destination{Domain: "other.test", Port: 3478}}); tag != "node" {
			t.Fatalf("%s UDP: routed to %q", mode, tag)
		}
	}
}

func TestRouteBlockQUICPerPolicy(t *testing.T) {
	const profile = `schema-version: 1
routing: {block-quic: %s}
outbounds:
  - {id: blocked, type: socks, server: 127.0.0.1, port: 9, block-quic: true}
  - {id: open, type: socks, server: 127.0.0.1, port: 9}
groups:
  - {id: pick, type: select, members: [blocked, open], selected: blocked}
  - {id: quiet, type: select, members: [open], block-quic: true}
rules:
  - {match: {domain: open.test}, outbound: open}
  - {match: {domain: group.test}, outbound: quiet}
  - {match: {all: true}, outbound: pick}
`
	e := NewEngine(EngineOptions{HostPacketFlow: true})
	defer e.Close()
	for i, mode := range []string{"off", "per-policy"} {
		activateProfile(t, e, fmt.Sprintf(profile, mode), uint64(i+1))
		for domain, blocked := range map[string]bool{"open.test": false, "blocked.test": mode == "per-policy", "group.test": mode == "per-policy"} {
			tag, info := routeTag(t, e, sagernet.Metadata{
				InboundType: "tun", Network: "udp", Destination: sagernet.Destination{Domain: domain, Port: 443},
			})
			if blocked != (tag == "" && info.RejectReason == blockQUIC) {
				t.Fatalf("%s %s: routed to %q, reason %q", mode, domain, tag, info.RejectReason)
			}
		}
	}
}

func TestRouteDNSFailureReject(t *testing.T) {
	const profile = `schema-version: 1
routing: {dns-failure: reject}
rules:
  - {match: {ip-cidr: [10.0.0.0/8]}, outbound: reject}
  - {match: {all: true}, outbound: direct}
`
	resolver := &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
		return nil, fmt.Errorf("offline")
	}}
	e := NewEngine(EngineOptions{HostPacketFlow: true, Resolver: resolver})
	defer e.Close()
	activateProfile(t, e, profile, 1)
	tag, info := routeTag(t, e, sagernet.Metadata{
		InboundType: "tun", Network: "tcp", Destination: sagernet.Destination{Domain: "unresolved.invalid", Port: 443},
	})
	if tag != "" || info.RejectReason != dnsFailed || !info.DNSFailure {
		t.Fatalf("routed to %q, reason %q, DNS failure %v", tag, info.RejectReason, info.DNSFailure)
	}
	if hits := e.RuleHits(); len(hits.Rules) != 0 || hits.Final != 0 {
		t.Fatalf("a rejected lookup failure was counted: %+v", hits)
	}
}

func TestRuleHits(t *testing.T) {
	const profile = `schema-version: 1
rules:
  - {id: a, match: {domain: a.test}, outbound: direct}
  - {match: {domain: %s}, outbound: reject}
  - {match: {domain: c.test}, outbound: direct}
`
	e := NewEngine(EngineOptions{HostPacketFlow: true})
	defer e.Close()
	route := func(domain string) {
		t.Helper()
		_, _ = routeTag(t, e, sagernet.Metadata{InboundType: "tun", Network: "tcp", Destination: sagernet.Destination{Domain: domain, Port: 443}})
	}
	activateProfile(t, e, fmt.Sprintf(profile, "b.test"), 1)
	for _, domain := range []string{"a.test", "a.test", "b.test", "c.test", "other.test"} {
		route(domain)
	}
	hits := e.RuleHits()
	want := []RuleHit{{Index: 0, ID: "a", Hits: 2}, {Index: 1, Anonymous: 1, Hits: 1}, {Index: 2, Anonymous: 2, Hits: 1}}
	if fmt.Sprint(hits.Rules) != fmt.Sprint(want) || hits.Final != 1 || hits.RuleCount != 3 {
		t.Fatalf("got %+v", hits)
	}
	// Reloading keeps the counts of unchanged rules and drops changed ones.
	activateProfile(t, e, fmt.Sprintf(profile, "changed.test"), 2)
	hits = e.RuleHits()
	want = []RuleHit{{Index: 0, ID: "a", Hits: 2}, {Index: 2, Anonymous: 2, Hits: 1}}
	if fmt.Sprint(hits.Rules) != fmt.Sprint(want) || hits.Final != 1 {
		t.Fatalf("after reload: %+v", hits)
	}
	e.ResetRuleHits()
	if hits = e.RuleHits(); len(hits.Rules) != 0 || hits.Final != 0 {
		t.Fatalf("after reset: %+v", hits)
	}
	// Address destinations rejected before any rule are not counted.
	_, _ = routeTag(t, e, sagernet.Metadata{InboundType: "socks", Inbound: "missing", Network: "udp", Destination: sagernet.Destination{Addr: netip.MustParseAddr("192.0.2.1"), Port: 53}})
	if hits = e.RuleHits(); len(hits.Rules) != 0 || hits.Final != 0 {
		t.Fatalf("precondition rejection counted: %+v", hits)
	}
}
