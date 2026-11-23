package dns

import (
	"context"
	"net/netip"
	"testing"
	"testing/synctest"
	"time"

	D "github.com/miekg/dns"
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

func TestWireFakeTTLAndMappingLifetime(t *testing.T) {
	for _, tc := range []struct {
		name     string
		wireTTL  int
		explicit bool
	}{
		{name: "default", wireTTL: 1},
		{name: "explicit zero", wireTTL: 0, explicit: true},
		{name: "explicit nonzero", wireTTL: 120, explicit: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				pool := NewFakePool(8)
				cfg := Config{Nameservers: []string{"192.0.2.1"}, Mode: "fake-ip"}
				if tc.explicit {
					cfg.TTL = &tc.wireTTL
				}
				if got := cfg.FakeTTL(); got != tc.wireTTL {
					t.Fatalf("FakeTTL = %d, want %d", got, tc.wireTTL)
				}
				s, err := New(cfg, Options{Pool: pool, Generation: 1})
				if err != nil {
					t.Fatal(err)
				}
				defer s.Retire()
				m, err := s.Exchange(t.Context(), query("mapping.test"), "normal", true)
				if err != nil || len(m.Answer) != 1 || m.Answer[0].Header().Ttl != uint32(tc.wireTTL) {
					t.Fatalf("DNS TTL %d: %v %v", tc.wireTTL, m, err)
				}
				ip, _ := netip.AddrFromSlice(m.Answer[0].(*D.A).A)
				time.Sleep(max(time.Minute, time.Duration(tc.wireTTL)*time.Second) + time.Second)
				checkFakeMapping(t, pool, ip.Unmap(), "mapping.test")
			})
		})
	}
}
