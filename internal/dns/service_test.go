package dns

import (
	"context"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MimoProxy/reka/internal/history"
	D "github.com/miekg/dns"
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

func TestFakeIPAnswersServiceBindingsLocally(t *testing.T) {
	for _, tc := range []struct {
		mode           string
		faked, forward string
	}{{"", "faked.test", "filtered.test"}, {"whitelist", "filtered.test", "faked.test"}} {
		t.Run("mode="+tc.mode, func(t *testing.T) {
			var forwarded []D.Question
			cfg := Config{Mode: "fake-ip", Nameservers: []string{"192.0.2.1"}, FakeFilter: []string{"filtered.test"}, FakeFilterMode: tc.mode}
			s := service(t, cfg, func(_ context.Context, _ Endpoint, q *D.Msg, _ func(context.Context, string) ([]netip.Addr, error)) (*D.Msg, error) {
				forwarded = append(forwarded, q.Question[0])
				m := new(D.Msg).SetReply(q)
				if q.Question[0].Qtype == D.TypeA {
					m.Answer = []D.RR{addressRR(q.Question[0].Name, D.TypeA, netip.MustParseAddr("192.0.2.8"), 10)}
				}
				return m, nil
			})
			t.Cleanup(s.Retire)
			observed := make(chan history.DNSObservation, 1)
			ctx := history.WithDNSObserver(t.Context(), func(o history.DNSObservation) { observed <- o })
			exchange := func(name string, typ uint16, fake bool) (*D.Msg, string) {
				t.Helper()
				q := new(D.Msg).SetQuestion(D.Fqdn(name), typ)
				m, err := s.Exchange(ctx, q, "normal", fake)
				if err != nil || m.Rcode != D.RcodeSuccess {
					t.Fatalf("%s %s: %v, %v", name, D.TypeToString[typ], m, err)
				}
				return m, (<-observed).Source
			}

			for _, typ := range []uint16{D.TypeHTTPS, D.TypeSVCB} {
				if m, source := exchange(tc.faked, typ, true); len(m.Answer) != 0 || source != "fake_ip_empty" || len(forwarded) != 0 {
					t.Fatalf("faked %s = %v from %s, forwarded %v", D.TypeToString[typ], m.Answer, source, forwarded)
				}
			}
			m, source := exchange(tc.faked, D.TypeA, true)
			if ip, _ := netip.AddrFromSlice(m.Answer[0].(*D.A).A); source != "fake_ip" || !netip.MustParsePrefix(s.cfg.FakeRange).Contains(ip) || len(forwarded) != 0 {
				t.Fatalf("faked A = %v from %s, forwarded %v", m.Answer, source, forwarded)
			}

			// Diagnostics without fake answers and domains left out of fake-ip
			// still reach the configured resolvers.
			for _, tc := range []struct {
				name string
				typ  uint16
				fake bool
			}{{tc.faked, D.TypeHTTPS, false}, {tc.forward, D.TypeHTTPS, true}, {tc.forward, D.TypeSVCB, true}, {tc.forward, D.TypeA, true}} {
				before := len(forwarded)
				if _, source := exchange(tc.name, tc.typ, tc.fake); source != "upstream" || len(forwarded) != before+1 ||
					forwarded[before].Name != D.Fqdn(tc.name) || forwarded[before].Qtype != tc.typ {
					t.Fatalf("%s %s from %s, forwarded %v", tc.name, D.TypeToString[tc.typ], source, forwarded)
				}
			}
		})
	}
}
