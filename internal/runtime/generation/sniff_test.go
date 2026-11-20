package generation

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/MimoProxy/reka/internal/backend/sagernet"
	"github.com/MimoProxy/reka/internal/config/compile"
	D "github.com/miekg/dns"
)

func TestRouteReportsFakeIPDomainAlongsideSniffedDomain(t *testing.T) {
	e := NewEngine(EngineOptions{})
	defer e.Close()
	eff, ds := compile.Compile([]byte("schema-version: 1\nrules: [{match: {domain: mapped.test}, outbound: direct}, {match: {all: true}, outbound: reject}]\n"), nil, compile.Options{})
	if ds.HasErrors() {
		t.Fatal(ds)
	}
	p, err := e.Prepare(eff)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.Activate(p, 1); err != nil {
		t.Fatal(err)
	}
	ip, err := e.fake.Allocate(1, "mapped.test", netip.MustParsePrefix("198.18.0.0/16"), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	md := sagernet.Metadata{Network: "tcp", Destination: sagernet.Destination{Addr: ip, Port: 443}}
	if prepared := e.prepareFlow(ctx, md); prepared.Sniff.Enabled {
		prepared.Release()
		t.Fatal("default sniffing did not use the known Fake IP mapping")
	}
	md.SniffedDomain = "sniff.test"
	route := e.route(ctx, md)
	if route.Outbound == nil {
		t.Fatal("Fake IP flow did not route")
	}
	defer route.Release()
	if info := route.Info.(*FlowInfo); info.DestinationDomain != "mapped.test" || info.SniffedDomain != "sniff.test" {
		t.Fatalf("expected both names on the connection: %+v", info)
	}
}

func TestPreparedSniffFlowRetainsConfigurationAcrossCommit(t *testing.T) {
	e := NewEngine(EngineOptions{})
	defer e.Close()
	apply := func(profile string, revision uint64) *Prepared {
		t.Helper()
		eff, ds := compile.Compile([]byte(profile), nil, compile.Options{})
		if ds.HasErrors() {
			t.Fatal(ds)
		}
		p, err := e.Prepare(eff)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := e.Activate(p, revision); err != nil {
			t.Fatal(err)
		}
		return p
	}
	old := apply("schema-version: 1\nsniff: {enabled: true}\noutbounds: [{id: first, type: direct}]\nrules: [{match: {domain: sniff.test}, outbound: first}, {match: {all: true}, outbound: reject}]\n", 1)
	md := sagernet.Metadata{Network: "tcp", Inbound: "test", SniffedDomain: "sniff.test"}
	prepared := e.prepareFlow(context.Background(), md)
	defer prepared.Release()
	apply("schema-version: 1\nsniff: {enabled: false}\nrules: [{match: {all: true}, outbound: reject}]\n", 2)
	if !old.outbounds["first"].Lease().Retired() {
		t.Fatal("old outbound was not retired")
	}
	result := prepared.Route(context.Background(), md)
	if result.Outbound != old.outbounds["first"] {
		t.Fatalf("sniff flow switched configuration: %+v", result)
	}
	prepared.Release()
	if result.Outbound.Lease().Active() != 1 {
		t.Fatalf("prepare pin was not transferred: %d", result.Outbound.Lease().Active())
	}
	if info := result.Info.(*FlowInfo); info.Revision != 1 {
		t.Fatalf("revision=%d", info.Revision)
	}
	result.Release()
	if got := e.route(context.Background(), md); got.Outbound != nil {
		got.Release()
		t.Fatal("new flow did not use new rejecting configuration")
	}
}

func TestPreparedSniffFlowCanResolveThroughRetiredSnapshotOutbound(t *testing.T) {
	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &D.Server{PacketConn: packet, Handler: D.HandlerFunc(func(w D.ResponseWriter, q *D.Msg) {
		m := new(D.Msg)
		m.SetReply(q)
		rr, _ := D.NewRR(q.Question[0].Name + " 30 IN A 192.0.2.7")
		m.Answer = []D.RR{rr}
		_ = w.WriteMsg(m)
	})}
	started := make(chan struct{})
	server.NotifyStartedFunc = func() { close(started) }
	go server.ActivateAndServe()
	<-started
	defer server.Shutdown()
	e := NewEngine(EngineOptions{})
	defer e.Close()
	apply := func(text string, revision uint64) {
		t.Helper()
		eff, ds := compile.Compile([]byte(text), nil, compile.Options{})
		if ds.HasErrors() {
			t.Fatal(ds)
		}
		p, err := e.Prepare(eff)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := e.Activate(p, revision); err != nil {
			t.Fatal(err)
		}
	}
	apply(fmt.Sprintf("schema-version: 1\nsniff: {enabled: true}\noutbounds: [{id: old, type: direct}, {id: resolver, type: direct}]\ndns: {nameserver: [%q]}\nrules: [{match: {ip-cidr: 192.0.2.0/24}, outbound: old}, {match: {all: true}, outbound: reject}]\n", "udp://"+packet.LocalAddr().String()+"#resolver"), 1)
	md := sagernet.Metadata{Network: "tcp", Destination: sagernet.Destination{Domain: "captured-dns.test", Port: 443}}
	prepared := e.prepareFlow(context.Background(), md)
	defer prepared.Release()
	apply("schema-version: 1\nrules: [{match: {all: true}, outbound: reject}]\n", 2)
	result := prepared.Route(context.Background(), md)
	if result.Outbound == nil {
		t.Fatal("captured DNS could not borrow its retired resolver outbound")
	}
	defer result.Release()
	if result.Outbound.Tag() != "old" {
		t.Fatal("wrong route", result.Outbound.Tag())
	}
}

func TestConditionalSniffUsesFirstMatchingRule(t *testing.T) {
	const profile = `schema-version: 1
sniff:
  override-destination: true
  skip-domains: ["+.private.test"]
  rules:
    - match: {src-ip-cidr: 10.3.0.0/16}
      action: skip
    - match: {and: [{in-name: mixed}, {dst-port: [443, 8443-8445]}]}
      action: sniff
      protocols: [tls]
      override-destination: false
`
	eff, ds := compile.Compile([]byte(profile), nil, compile.Options{})
	if ds.HasErrors() {
		t.Fatal(ds)
	}
	if eff.SniffForRouting {
		t.Fatal("explicit sniff rules must apply even when routing does not need to recover a domain")
	}
	ctx := context.Background()
	md := sagernet.Metadata{Network: "tcp", Inbound: "mixed", Source: netip.MustParseAddrPort("192.0.2.4:1234"),
		Destination: sagernet.Destination{Addr: netip.MustParseAddr("203.0.113.7"), Port: 8444}}
	got := flowSniffOptions(ctx, eff, md, "")
	if !got.Enabled || got.OverrideDestination || len(got.Protocols) != 1 || got.Protocols[0] != "tls" {
		t.Fatalf("unexpected sniff decision: %+v", got)
	}
	if got.SkipDomain == nil || !got.SkipDomain("a.private.test") || got.SkipDomain("elsewhere.test") {
		t.Fatal("domain exclusion was not compiled")
	}
	known := md
	known.Destination.Domain = "private.test"
	if flowSniffOptions(ctx, eff, known, "").Enabled {
		t.Fatal("known excluded domain was inspected")
	}
	md.Source = netip.MustParseAddrPort("10.3.4.5:1234")
	if flowSniffOptions(ctx, eff, md, "").Enabled {
		t.Fatal("later inclusion took precedence over earlier skip")
	}
	md.Source, md.Inbound = netip.MustParseAddrPort("192.0.2.4:1234"), "other"
	if flowSniffOptions(ctx, eff, md, "").Enabled {
		t.Fatal("unmatched inlet was inspected")
	}
}
