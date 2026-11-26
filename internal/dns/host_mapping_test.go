package dns

import (
	"context"
	"net/netip"
	"sync"
	"testing"

	D "github.com/miekg/dns"
)

func TestClientExchangeMapsRealAnswers(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mode   string
		fake   bool
		filter []string
	}{
		{name: "default", fake: true},
		{name: "redir-host", mode: "redir-host", fake: true},
		{name: "filtered fake-ip", mode: "fake-ip", fake: true, filter: []string{"mixed.test"}},
		{name: "forced real answer", mode: "fake-ip"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ip4 := netip.MustParseAddr("192.0.2.4")
			otherIP := netip.MustParseAddr("192.0.2.5")
			ip6 := netip.MustParseAddr("2001:db8::6")
			cfg := Config{Nameservers: []string{"192.0.2.1"}, IPv6: true, Mode: tc.mode, FakeFilter: tc.filter}
			s := service(t, cfg, func(_ context.Context, _ Endpoint, q *D.Msg, _ func(context.Context, string) ([]netip.Addr, error)) (*D.Msg, error) {
				m := new(D.Msg).SetReply(q)
				m.Answer = []D.RR{hostCNAME(q.Question[0].Name, "alias.test")}
				if q.Question[0].Qtype == D.TypeA {
					m.Answer = append(m.Answer, addressRR("alias.test.", D.TypeA, ip4, 30), addressRR("alias.test.", D.TypeA, otherIP, 30))
				} else {
					m.Answer = append(m.Answer, addressRR("alias.test.", D.TypeAAAA, ip6, 30))
				}
				return m, nil
			})
			t.Cleanup(s.Retire)
			for _, typ := range []uint16{D.TypeA, D.TypeAAAA} {
				q := new(D.Msg).SetQuestion("MiXeD.test.", typ)
				if _, err := s.Exchange(t.Context(), q, "normal", tc.fake); err != nil {
					t.Fatal(err)
				}
			}
			for _, ip := range []netip.Addr{ip4, otherIP, ip6} {
				if got, ok := s.opts.Mapping.Lookup(ip); !ok || got != "mixed.test" {
					t.Errorf("domain for %s = %q, %t", ip, got, ok)
				}
			}
		})
	}
}

func TestHostMappingUsesOnlyClientAnswers(t *testing.T) {
	ip := netip.MustParseAddr("192.0.2.8")
	cfg := Config{Mode: "fake-ip", Nameservers: []string{"192.0.2.1"}, FakeFilter: []string{"real.test"}}
	s := service(t, cfg, func(_ context.Context, _ Endpoint, q *D.Msg, _ func(context.Context, string) ([]netip.Addr, error)) (*D.Msg, error) {
		return answer(q, ip.String()), nil
	})
	t.Cleanup(s.Retire)
	if _, err := s.Lookup(t.Context(), "real.test", "normal"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.LookupIPFamily(t.Context(), "real.test", "normal", D.TypeA); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ExchangeResolver(t.Context(), query("real.test"), "normal", true); err != nil {
		t.Fatal(err)
	}
	if got, ok := s.opts.Mapping.Lookup(ip); ok {
		t.Fatalf("internal lookup mapped %s to %q", ip, got)
	}
	if _, err := s.Exchange(t.Context(), query("real.test"), "normal", true); err != nil {
		t.Fatal(err)
	}
	if got, ok := s.opts.Mapping.Lookup(ip); !ok || got != "real.test" {
		t.Fatalf("domain for cached client answer = %q, %t", got, ok)
	}
	m, err := s.Exchange(t.Context(), query("synthetic.test"), "normal", true)
	if err != nil {
		t.Fatal(err)
	}
	fakeIP, _ := netip.AddrFromSlice(m.Answer[0].(*D.A).A)
	if got, ok := s.opts.Mapping.Lookup(fakeIP); ok {
		t.Fatalf("synthetic IP %s entered the real address mapping as %q", fakeIP, got)
	}
}

func TestClientExchangeMapsHostTables(t *testing.T) {
	cfg := Config{Nameservers: []string{"192.0.2.1"}, UseHosts: true, Hosts: []Host{
		{ID: "alias.test", Addresses: []string{"local.test"}},
		{ID: "local.test", Addresses: []string{"192.0.2.7"}},
	}}
	s := service(t, cfg, nil)
	t.Cleanup(s.Retire)
	s.systemHosts = []Host{{ID: "system.test", Addresses: []string{"127.0.0.1"}}}
	for _, tc := range []struct{ domain, ip string }{{"alias.test", "192.0.2.7"}, {"system.test", "127.0.0.1"}} {
		if _, err := s.Exchange(t.Context(), query(tc.domain), "normal", true); err != nil {
			t.Fatal(err)
		}
		if got, ok := s.opts.Mapping.Lookup(netip.MustParseAddr(tc.ip)); !ok || got != tc.domain {
			t.Errorf("domain for %s = %q, %t", tc.ip, got, ok)
		}
	}
}

func TestHostMappingLRUAndUnmap(t *testing.T) {
	m := NewHostMapping()
	address := func(i int) netip.Addr {
		return netip.AddrFrom4([4]byte{10, 0, byte(i >> 8), byte(i)})
	}
	for i := range hostMappingCapacity {
		m.recordAnswers("first.test.", []D.RR{addressRR("first.test.", D.TypeA, address(i), 1)})
	}
	mapped := netip.AddrFrom16(address(0).As16())
	if got, ok := m.Lookup(mapped); !ok || got != "first.test" {
		t.Fatalf("mapped IPv4 lookup = %q, %t", got, ok)
	}
	m.recordAnswers("next.test.", []D.RR{addressRR("next.test.", D.TypeA, address(hostMappingCapacity), 1)})
	if got, ok := m.Lookup(address(1)); ok {
		t.Fatalf("least recently used address still mapped to %q", got)
	}
	if got, ok := m.Lookup(address(0)); !ok || got != "first.test" {
		t.Fatalf("recent address was evicted, got %q, %t", got, ok)
	}
	m.recordAnswers("Latest.test.", []D.RR{addressRR("Latest.test.", D.TypeAAAA, mapped, 1)})
	if got, ok := m.Lookup(address(0)); !ok || got != "latest.test" {
		t.Fatalf("mapped AAAA failed to update the IPv4 entry, got %q, %t", got, ok)
	}
}

func TestHostMappingConcurrentReadWrite(t *testing.T) {
	m := NewHostMapping()
	ip := netip.MustParseAddr("192.0.2.9")
	answers := []D.RR{addressRR("shared.test.", D.TypeA, ip, 30)}
	var wg sync.WaitGroup
	for _, domain := range []string{"one.test", "two.test", "three.test", "four.test"} {
		wg.Go(func() {
			for range 100 {
				m.recordAnswers(domain, answers)
				if got, ok := m.Lookup(ip); !ok || got == "" {
					t.Errorf("domain for shared address = %q, %t", got, ok)
					return
				}
			}
		})
	}
	wg.Wait()
}
