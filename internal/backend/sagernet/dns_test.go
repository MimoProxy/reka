package sagernet

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"testing"

	RD "github.com/MimoProxy/reka/internal/dns"
	"github.com/MimoProxy/reka/internal/history"
	D "github.com/miekg/dns"
	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
)

func TestDNSRouterConnectionEvents(t *testing.T) {
	resolver, err := RD.New(RD.Config{Nameservers: []string{"192.0.2.1"}, IPv6: true}, RD.Options{
		Exchange: func(_ context.Context, _ RD.Endpoint, q *D.Msg, _ func(context.Context, string) ([]netip.Addr, error)) (*D.Msg, error) {
			if q.Question[0].Qtype == D.TypeA {
				return dnsTestAnswer(q), nil
			}
			m := new(D.Msg).SetReply(q)
			rr, err := D.NewRR(q.Question[0].Name + " 30 IN AAAA 2001:db8::8")
			m.Answer = []D.RR{rr}
			return m, err
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer resolver.Retire()
	if _, err := resolver.Exchange(t.Context(), new(D.Msg).SetQuestion("proxy.test.", D.TypeAAAA), "normal", false); err != nil {
		t.Fatal(err)
	}
	lookup := func(ctx context.Context, name string) ([]netip.Addr, error) {
		return resolver.Lookup(ctx, name, "normal")
	}
	router := &dnsRouter{resolver: &net.Resolver{}}
	for _, tc := range []struct {
		name, domain, source string
		lookup               LookupFunc
		strategy             C.DomainStrategy
		counts               []int
	}{
		{name: "resolver policy", domain: "proxy.test", source: "cache", lookup: lookup, strategy: C.DomainStrategyPreferIPv6, counts: []int{1, 1}},
		{name: "system", domain: "127.0.0.1", source: "system", counts: []int{1, 0}},
		{
			name: "no usable address", domain: "proxy.test", source: "error", strategy: C.DomainStrategyIPv6Only, counts: []int{0, 0},
			lookup: func(context.Context, string) ([]netip.Addr, error) {
				return []netip.Addr{netip.MustParseAddr("192.0.2.8")}, nil
			},
		},
		{
			name: "resolver error", domain: "proxy.test", source: "error", counts: []int{0, 0},
			lookup: func(context.Context, string) ([]netip.Addr, error) { return nil, errors.New("resolver unavailable") },
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			attempt := (&Backend{}).beginConnection(t.Context(), Metadata{})
			ctx := withAttempt(t.Context(), attempt)
			_, err := router.Lookup(WithLookup(ctx, tc.lookup), tc.domain, adapter.DNSQueryOptions{Strategy: tc.strategy})
			if (err != nil) != (tc.source == "error") {
				t.Fatalf("unexpected lookup error: %v", err)
			}
			// A completed lookup outside the flow must not add another event.
			for _, background := range []context.Context{context.Background(), history.WithFlow(context.WithoutCancel(ctx), 0)} {
				if _, err := router.Lookup(background, "127.0.0.1", adapter.DNSQueryOptions{}); err != nil {
					t.Fatal(err)
				}
			}
			events := attempt.trace(0, 0).Events
			checkConnectionEventKinds(t, events, "accepted", "server_dns")
			event := events[1]
			if event.Name != tc.domain || event.Code != tc.source || !slices.Equal(event.N, tc.counts) || event.MS == nil {
				t.Fatalf("unexpected server DNS event: %+v", event)
			}
		})
	}
}
