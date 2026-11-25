package generation

import (
	"context"
	"fmt"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/MimoProxy/reka/internal/backend/sagernet"
	"github.com/MimoProxy/reka/internal/config/compile"
	"github.com/MimoProxy/reka/internal/mitm/ca"
	"github.com/MimoProxy/reka/internal/secret"
)

func TestMITMQUICAdmission(t *testing.T) {
	now := time.Now()
	e := NewEngine(EngineOptions{HostPacketFlow: true, mitmNow: func() time.Time { return now }})
	t.Cleanup(e.Close)
	const profile = `schema-version: 1
mitm:
  hostnames: ['allow.test:0']
  client-source-address: ['192.0.2.0/24', '-192.0.2.9']
  quic-block: true
`
	store := newMITMTestStore(t)
	saveMITMTestCA(t, store)
	gen := activateMITMTestConfig(t, e, store, profile, 1)
	if !e.MITMStatus().CALoaded {
		t.Fatalf("MITM CA failed to load: %s", e.MITMStatus().CAError)
	}
	if status := e.MITMStatus(); status.H2 != "disabled" {
		t.Fatalf("default HTTP/2 status = %q", status.H2)
	}

	fakeIP, err := e.fake.Allocate(gen, "allow.test", netip.MustParsePrefix("198.18.0.0/15"))
	if err != nil {
		t.Fatal(err)
	}
	md := sagernet.Metadata{
		InboundType: "tun", Network: "udp",
		Source:      netip.MustParseAddrPort("192.0.2.8:50000"),
		Destination: sagernet.Destination{Addr: fakeIP, Port: 443},
	}
	check := func(md sagernet.Metadata, reject bool) {
		t.Helper()
		wantAction := sagernet.PreMatchContinue
		if reject {
			wantAction = sagernet.PreMatchReject
		}
		verdict := e.preMatch(md)
		if verdict.Action != wantAction {
			t.Fatalf("pre-match action = %v, want %v", verdict.Action, wantAction)
		}
		if reject && verdict.Info.(*FlowInfo).RejectReason != "mitm-quic" {
			t.Fatalf("pre-match info = %+v", verdict.Info)
		}
		rt := e.route(context.Background(), md)
		if rt.Release != nil {
			defer rt.Release()
		}
		if (rt.Outbound == nil) != reject || reject && rt.Info.(*FlowInfo).RejectReason != "mitm-quic" {
			t.Fatalf("route rejected = %v, info = %+v", rt.Outbound == nil, rt.Info)
		}
	}
	check(md, true)
	excluded := md
	excluded.Source = netip.MustParseAddrPort("192.0.2.9:50000")
	check(excluded, false)
	unknown := md
	unknown.Destination.Addr = netip.MustParseAddr("203.0.113.8")
	check(unknown, false)
	unknown.SniffedDomain = "other.test"
	check(unknown, false)
	sniffed := unknown
	sniffed.Destination.Port = 8443
	sniffed.SniffedDomain, sniffed.Protocol = "ALLOW.TEST.", "quic"
	check(sniffed, true)
	sniffed.Protocol = ""
	check(sniffed, false)

	e.mitmBypasses.insert("allow.test", "unknown_ca")
	check(md, false)
	activateMITMTestConfig(t, e, store, profile, 2)
	check(md, false)
	now = now.Add(mitmBypassDuration)
	check(md, true)
	if len(e.MITMStatus().PinningBypasses) != 0 {
		t.Fatal("expired bypass remained visible")
	}
}

func TestMITMIssuerLifetime(t *testing.T) {
	const profile = "schema-version: 1\nmitm: {hostnames: [origin.test], h2: true}\n"
	e := NewEngine(EngineOptions{})
	t.Cleanup(e.Close)
	store := newMITMTestStore(t)
	activateMITMTestConfig(t, e, store, profile, 1)
	if status := e.MITMStatus(); !status.Enabled || status.CALoaded || status.CAError == "" ||
		status.HostnameCount != 1 || status.H2 != "enabled" {
		t.Fatalf("status with missing CA = %+v", status)
	}

	saveMITMTestCA(t, store)
	activateMITMTestConfig(t, e, store, profile, 2)
	_, previous := e.current()
	md := sagernet.Metadata{Network: "tcp", Destination: sagernet.Destination{Domain: "origin.test", Port: 443}}
	rt := e.route(context.Background(), md)
	if rt.Release != nil {
		defer rt.Release()
	}
	if rt.MITM == nil || rt.MITM.Issuer != previous.mitm.issuer.Issuer {
		t.Fatal("matching route did not receive its generation's issuer")
	}
	if !rt.MITM.H2 {
		t.Fatal("matching route did not receive its generation's HTTP/2 setting")
	}
	leaf, err := rt.MITM.Issuer.Certificate("origin.test")
	if err != nil {
		t.Fatal(err)
	}
	activateMITMTestConfig(t, e, store, profile, 3)
	_, same := e.current()
	if same.mitm.issuer != previous.mitm.issuer || same.mitm.issuer.refs.Load() != 2 {
		t.Fatal("activation did not reuse the same CA issuer")
	}
	if stillCached, err := same.mitm.issuer.Certificate("origin.test"); err != nil || stillCached != leaf {
		t.Fatal("activation lost the leaf cache")
	}
	saveMITMTestCA(t, store)
	activateMITMTestConfig(t, e, store, profile, 4)
	_, replacement := e.current()
	if replacement.mitm.issuer == previous.mitm.issuer || previous.mitm.issuer.refs.Load() != 1 {
		t.Fatal("activation did not retire the old CA with the running route retained")
	}
	if _, err := rt.MITM.Issuer.Certificate("old.origin.test"); err != nil {
		t.Fatal(err)
	}
	rt.Release()
	if previous.mitm.issuer.refs.Load() != 0 || previous.mitm.issuer.Issuer != nil {
		t.Fatal("connection release left the retired issuer live")
	}
	e.Close()
	if replacement.mitm.issuer.refs.Load() != 0 || replacement.mitm.issuer.Issuer != nil {
		t.Fatal("engine shutdown left its active issuer live")
	}
}

func TestMITMRerouteRetainsOriginalGeneration(t *testing.T) {
	e := NewEngine(EngineOptions{})
	t.Cleanup(e.Close)
	store := newMITMTestStore(t)
	saveMITMTestCA(t, store)
	const rewrite = `schema-version: 1
mitm: {hostnames: [origin.test]}
http-rewrites:
  - {id: change-host, match: '^https://origin[.]test/', action: header, target: 'https://target.test/'}
`
	const routes = `outbounds: [{id: rewritten, type: direct}]
rules: [{match: {domain: target.test}, outbound: rewritten}]
`
	oldGeneration := activateMITMTestConfig(t, e, store, rewrite+routes, 1)
	original := e.route(context.Background(), sagernet.Metadata{
		Network: "tcp", Destination: sagernet.Destination{Domain: "origin.test", Port: 443},
	})
	if original.Release != nil {
		defer original.Release()
	}
	if original.MITM == nil || original.MITM.Reroute == nil {
		t.Fatal("original route did not support URL rewriting")
	}
	oldTarget := e.OutboundInstance("rewritten")
	activateMITMTestConfig(t, e, store, rewrite, 2)
	if !oldTarget.Lease().Retired() || oldTarget.Lease().Active() == 0 {
		t.Fatal("old reroute target did not retain its pin")
	}
	dest := sagernet.Destination{Domain: "target.test", Port: 443}
	rt := original.MITM.Reroute(context.Background(), dest)
	if rt.Release != nil {
		defer rt.Release()
	}
	if rt.MITM != nil || rt.Outbound != oldTarget || rt.Destination == nil ||
		*rt.Destination != dest || rt.Info.(*FlowInfo).Generation != oldGeneration {
		t.Fatalf("changed authority did not follow the original generation: %+v", rt)
	}
	rt.Release()
	original.Release()
	if oldTarget.Lease().Active() != 0 {
		t.Fatal("connection release retained the replaced outbound")
	}
}

func TestMITMTCPAdmissionUsesSocketPeer(t *testing.T) {
	e := NewEngine(EngineOptions{})
	t.Cleanup(e.Close)
	store := newMITMTestStore(t)
	saveMITMTestCA(t, store)
	const profile = `schema-version: 1
mitm:
  hostnames: [origin.test]
  client-source-address: [192.0.2.8]
`
	activateMITMTestConfig(t, e, store, profile, 1)
	md := sagernet.Metadata{
		Network: "tcp", InboundType: "http",
		Source:       netip.MustParseAddrPort("192.0.2.8:50000"),
		ClientSource: netip.MustParseAddr("192.0.2.9"),
		Destination:  sagernet.Destination{Domain: "origin.test", Port: 443},
	}
	check := func(want bool) {
		t.Helper()
		rt := e.route(context.Background(), md)
		if rt.Release != nil {
			defer rt.Release()
		}
		if rt.Outbound == nil || (rt.MITM != nil) != want {
			t.Fatalf("forwarding available = %v, MITM selected = %v, want MITM = %v", rt.Outbound != nil, rt.MITM != nil, want)
		}
	}
	check(false)
	md.Source = netip.MustParseAddrPort("192.0.2.9:50000")
	md.ClientSource = netip.MustParseAddr("192.0.2.8")
	check(true)
	md.SkipMITM = true
	check(false)
}

func TestMITMRequestsSniffingWithoutDomainRules(t *testing.T) {
	e := NewEngine(EngineOptions{})
	t.Cleanup(e.Close)
	store := newMITMTestStore(t)
	saveMITMTestCA(t, store)
	activateMITMTestConfig(t, e, store, "schema-version: 1\nmitm: {hostnames: [origin.test]}\n", 1)
	md := sagernet.Metadata{Network: "tcp", Destination: sagernet.Destination{Addr: netip.MustParseAddr("203.0.113.8"), Port: 8443}}
	p := e.prepareFlow(context.Background(), md)
	if p.Sniff.Enabled {
		if p.Release != nil {
			p.Release()
		}
		t.Fatal("port outside the MITM scope requested sniffing")
	}
	md.Destination.Port = 443
	p = e.prepareFlow(context.Background(), md)
	if p.Release != nil {
		defer p.Release()
	}
	if !p.Sniff.Enabled {
		t.Fatal("MITM did not request a domain hint")
	}
	md.SniffedDomain, md.Protocol = "origin.test", "tls"
	rt := p.Route(context.Background(), md)
	if rt.Release != nil {
		defer rt.Release()
	}
	if rt.MITM == nil || rt.Destination != nil {
		t.Fatalf("sniffing selected MITM = %v, destination override = %v", rt.MITM != nil, rt.Destination)
	}
}

func TestMITMBypassCapacityAndExpiry(t *testing.T) {
	now := time.Now()
	bypasses := mitmBypassTable{now: func() time.Time { return now }}
	for i := range mitmBypassCapacity + 1 {
		bypasses.insert(fmt.Sprintf("host-%d.test", i), "unknown_ca")
		now = now.Add(time.Second)
	}
	if bypasses.contains("host-0.test") || len(bypasses.list()) != mitmBypassCapacity {
		t.Fatal("bypass table did not evict the earliest expiry at capacity")
	}
	now = now.Add(mitmBypassDuration)
	if len(bypasses.list()) != 0 {
		t.Fatal("bypass table retained expired entries")
	}
}

func newMITMTestStore(t *testing.T) secret.Store {
	t.Helper()
	store, err := secret.NewFileStore(filepath.Join(t.TempDir(), "secrets.json"), nil)
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func saveMITMTestCA(t *testing.T, store secret.Store) {
	t.Helper()
	authority, err := ca.Generate(ca.GenerateOptions{CommonName: "MITM test CA"})
	if err != nil {
		t.Fatal(err)
	}
	if err := ca.Save(store, authority); err != nil {
		t.Fatal(err)
	}
}

func activateMITMTestConfig(t *testing.T, e *Engine, store secret.Store, profile string, revision uint64) uint64 {
	t.Helper()
	local := "mitm: {enabled: true, ca: 'secret://mitm/ca'}"
	effective, diagnostics := compile.Compile([]byte(profile), []byte(local), compile.Options{Secrets: store})
	if diagnostics.HasErrors() {
		t.Fatal(diagnostics)
	}
	prepared, err := e.Prepare(effective)
	if err != nil {
		t.Fatal(err)
	}
	generation, err := e.Activate(prepared, revision)
	if err != nil {
		t.Fatal(err)
	}
	return generation
}
