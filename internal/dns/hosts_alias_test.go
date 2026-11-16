package dns

import (
	"context"
	D "github.com/miekg/dns"
	"net/netip"
	"testing"
)

func TestHostsAliasAnswersAndUpstreamRewrite(t *testing.T) {
	calls := 0
	cfg := Config{Nameservers: []string{"192.0.2.1"}, UseHosts: true, IPv6: true, Hosts: []Host{
		{ID: "local.test", Addresses: []string{"next.test"}},
		{ID: "next.test", Addresses: []string{"192.0.2.4", "2001:db8::4"}},
		{ID: "remote.test", Addresses: []string{"external.test"}},
	}}
	s := service(t, cfg, func(_ context.Context, _ Endpoint, q *D.Msg, _ func(context.Context, string) ([]netip.Addr, error)) (*D.Msg, error) {
		calls++
		if q.Question[0].Name != "external.test." {
			t.Fatalf("upstream question: %v", q.Question)
		}
		return answer(q, "192.0.2.9"), nil
	})
	for _, typ := range []uint16{D.TypeA, D.TypeAAAA, D.TypeCNAME} {
		q := query("local.test")
		q.Question[0].Qtype = typ
		m, e := s.Exchange(context.Background(), q, "normal", false)
		if e != nil || len(m.Answer) != 1 || m.Answer[0].Header().Rrtype != typ || m.Answer[0].Header().Name != "local.test." || m.Answer[0].Header().Ttl != 10 {
			t.Fatalf("%v %v", m, e)
		}
		if typ == D.TypeCNAME && m.Answer[0].(*D.CNAME).Target != "next.test." {
			t.Fatal(m)
		}
	}
	m, e := s.Exchange(context.Background(), query("remote.test"), "normal", false)
	if e != nil || calls != 1 || len(m.Answer) != 2 || m.Question[0].Name != "remote.test." || m.Answer[0].(*D.CNAME).Target != "external.test." || m.Answer[1].Header().Name != "external.test." {
		t.Fatalf("%v %v calls=%d", m, e, calls)
	}
}

func TestHostsAliasCyclesAndInvalidValues(t *testing.T) {
	s := service(t, Config{Nameservers: []string{"192.0.2.1"}, UseHosts: true, Hosts: []Host{{ID: "a.test", Addresses: []string{"b.test"}}, {ID: "b.test", Addresses: []string{"a.test"}}}}, nil)
	if _, e := s.Exchange(context.Background(), query("a.test"), "normal", false); e == nil {
		t.Fatal("alias cycle accepted")
	}
	for _, values := range [][]string{{"192.0.2.1", "alias.test"}, {"bad domain.test"}, {"singlelabel"}} {
		c := Config{Nameservers: []string{"192.0.2.1"}, Hosts: []Host{{ID: "x.test", Addresses: values}}}
		if Validate(&c) == nil {
			t.Fatalf("invalid alias accepted: %v", values)
		}
	}
}

func TestExplicitZeroFakeTTLRetainsUsableMapping(t *testing.T) {
	zero := 0
	pool := NewFakePool(8)
	s, e := New(Config{Nameservers: []string{"192.0.2.1"}, Mode: "fake-ip", TTL: &zero}, Options{Pool: pool, Generation: 1})
	if e != nil {
		t.Fatal(e)
	}
	m, e := s.Exchange(context.Background(), query("zero.test"), "normal", true)
	if e != nil || m.Answer[0].Header().Ttl != 0 {
		t.Fatalf("%v %v", m, e)
	}
	ip, _ := netip.AddrFromSlice(m.Answer[0].(*D.A).A)
	domain, release, ok := pool.Acquire(ip.Unmap())
	if !ok || domain != "zero.test" {
		t.Fatal("zero DNS TTL expired connection mapping")
	}
	release()
	if (Config{}).FakeTTL() != 60 {
		t.Fatal("omitted TTL default changed")
	}
}
