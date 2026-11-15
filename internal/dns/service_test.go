package dns

import (
	"context"
	D "github.com/miekg/dns"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

func service(t *testing.T, c Config, fn ExchangeFunc) *Service {
	t.Helper()
	s, err := New(c, Options{Exchange: fn, Match: func(p, d string, _ netip.Addr) bool { return p == d }, Generation: 1})
	if err != nil {
		t.Fatal(err)
	}
	return s
}
func query(d string) *D.Msg { q := new(D.Msg); q.SetQuestion(D.Fqdn(d), D.TypeA); return q }
func answer(q *D.Msg, ip string) *D.Msg {
	m := new(D.Msg)
	m.SetReply(q)
	m.Answer = []D.RR{addressRR(q.Question[0].Name, D.TypeA, netip.MustParseAddr(ip), 2)}
	return m
}
func TestPolicyFallbackScopedCacheAndHosts(t *testing.T) {
	var calls atomic.Int32
	cfg := Config{Nameservers: []string{"192.0.2.1"}, Bootstrap: []string{"192.0.2.2"}, Proxy: []string{"192.0.2.3"}, Direct: []string{"192.0.2.4"}, Policies: []Policy{{ID: "policy", Pattern: "special.test", Servers: []string{"192.0.2.5"}}}, Fallback: []string{"192.0.2.6"}, Filter: FallbackFilter{IPCIDR: []string{"192.0.2.1/32"}}, UseHosts: true, Hosts: []Host{{ID: "local.test", Addresses: []string{"127.0.0.1"}}}}
	s := service(t, cfg, func(_ context.Context, ep Endpoint, q *D.Msg, _ func(context.Context, string) ([]netip.Addr, error)) (*D.Msg, error) {
		calls.Add(1)
		return answer(q, ep.Host), nil
	})
	for _, tc := range []struct{ domain, scope, want string }{{"special.test", "normal", "192.0.2.5"}, {"normal.test", "normal", "192.0.2.6"}, {"normal.test", "bootstrap", "192.0.2.2"}, {"normal.test", "proxy", "192.0.2.3"}, {"normal.test", "direct", "192.0.2.4"}, {"local.test", "normal", "127.0.0.1"}} {
		ips, err := s.Lookup(context.Background(), tc.domain, tc.scope)
		if err != nil || ips[0].String() != tc.want {
			t.Fatal(tc, ips, err)
		}
	}
	before := calls.Load()
	q := query("normal.test")
	q.Id = 42
	m, err := s.Exchange(context.Background(), q, "normal", false)
	if err != nil || m.Id != 42 || calls.Load() != before {
		t.Fatal("cache miss", m, err)
	}
	m.Answer[0].Header().Ttl = 0
	m2, _ := s.Exchange(context.Background(), q, "normal", false)
	if m2.Answer[0].Header().Ttl == 0 {
		t.Fatal("cached answer mutated")
	}
	h, _ := s.Stats()
	if h < 2 {
		t.Fatal(h)
	}
}
func TestNegativeCacheTTLAndQuestionIsolation(t *testing.T) {
	var count atomic.Int32
	s := service(t, Config{Nameservers: []string{"192.0.2.1"}}, func(_ context.Context, _ Endpoint, q *D.Msg, _ func(context.Context, string) ([]netip.Addr, error)) (*D.Msg, error) {
		count.Add(1)
		m := new(D.Msg)
		m.SetRcode(q, D.RcodeNameError)
		m.Ns = []D.RR{&D.SOA{Hdr: D.RR_Header{Name: "test.", Rrtype: D.TypeSOA, Class: D.ClassINET, Ttl: 30}, Minttl: 1}}
		return m, nil
	})
	q := query("absent.test")
	s.Exchange(context.Background(), q, "normal", false)
	s.Exchange(context.Background(), q, "normal", false)
	if count.Load() != 1 {
		t.Fatal(count.Load())
	}
	q.CheckingDisabled = true
	s.Exchange(context.Background(), q, "normal", false)
	if count.Load() != 2 {
		t.Fatal("CD cache collision")
	}
	time.Sleep(1100 * time.Millisecond)
	s.Exchange(context.Background(), query("absent.test"), "normal", false)
	if count.Load() != 3 {
		t.Fatal("negative TTL ignored")
	}
}
func TestFakeGenerationsRangesAndLease(t *testing.T) {
	p := NewFakePool(8)
	prefix := netip.MustParsePrefix("198.18.0.0/29")
	a, err := p.Allocate(1, "old.test", prefix, 30*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	name, release, ok := p.Acquire(a)
	if !ok || name != "old.test" {
		t.Fatal(name)
	}
	time.Sleep(40 * time.Millisecond)
	b, _ := p.Allocate(2, "new.test", prefix, time.Second)
	if a == b {
		t.Fatal("leased old address reused")
	}
	name, r2, ok := p.Acquire(a)
	if !ok || name != "old.test" {
		t.Fatal("retired mapping lost")
	}
	r2()
	release()
	c, _ := p.Allocate(3, "new-range.test", netip.MustParsePrefix("198.19.0.0/29"), time.Second)
	if prefix.Contains(c) {
		t.Fatal(c)
	}
	if _, _, ok := p.Acquire(a); ok {
		t.Fatal("expired mapping retained after leases drained")
	}
}
func TestDNSCycleValidation(t *testing.T) {
	for _, c := range []Config{{Nameservers: []string{"1.1.1.1"}, Bootstrap: []string{"https://host.test/dns-query"}}, {Nameservers: []string{"1.1.1.1"}, Proxy: []string{"1.1.1.1#proxy"}}} {
		if Validate(&c) == nil {
			t.Fatal("cycle accepted")
		}
	}
}

func TestFallbackRetainsBudgetAfterPrimaryTimeout(t *testing.T) {
	s := service(t, Config{Nameservers: []string{"192.0.2.1"}, Fallback: []string{"192.0.2.2"}}, func(ctx context.Context, ep Endpoint, q *D.Msg, _ func(context.Context, string) ([]netip.Addr, error)) (*D.Msg, error) {
		if ep.Host == "192.0.2.1" {
			<-ctx.Done()
			return nil, ctx.Err()
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return answer(q, "192.0.2.2"), nil
	})
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	got, err := s.Lookup(ctx, "fallback.test", "normal")
	if err != nil || len(got) != 1 || got[0].String() != "192.0.2.2" {
		t.Fatal("fallback budget exhausted", got, err)
	}
}
