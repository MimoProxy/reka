package dns

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/MimoProxy/reka/internal/history"
	D "github.com/miekg/dns"
)

func TestExchangeDNSObserverSources(t *testing.T) {
	lookupErr := errors.New("upstream unavailable")
	s := service(t, Config{Nameservers: []string{"192.0.2.1"}, Bootstrap: []string{"192.0.2.1"}, StaleTTL: 60}, func(ctx context.Context, _ Endpoint, q *D.Msg, lookup func(context.Context, string) ([]netip.Addr, error)) (*D.Msg, error) {
		switch q.Question[0].Name {
		case "error.test.":
			return nil, lookupErr
		case "bootstrap.test.":
			return answer(q, "192.0.2.1"), nil
		}
		if _, err := lookup(ctx, "bootstrap.test"); err != nil {
			return nil, err
		}
		m := answer(q, "192.0.2.2")
		m.Answer = append(m.Answer, addressRR(q.Question[0].Name, D.TypeA, netip.MustParseAddr("192.0.2.3"), 2))
		return m, nil
	})
	defer s.Retire()

	// The service has no history store. Only the requested exchange is reported,
	// even when it uses a separate bootstrap query to obtain the result.
	observed := make(chan history.DNSObservation, 8)
	ctx := history.WithDNSObserver(t.Context(), func(o history.DNSObservation) { observed <- o })
	check := func(name, source string, answers int, wantErr error) {
		t.Helper()
		_, err := s.Exchange(ctx, query(name), "normal", false)
		if !errors.Is(err, wantErr) {
			t.Fatalf("exchange error = %v, want %v", err, wantErr)
		}
		select {
		case o := <-observed:
			if o.Name != D.Fqdn(name) || o.Type != "A" || o.Source != source || o.Answers != answers ||
				o.AddressAnswers != [2]int{answers, 0} || o.Duration < 0 || !errors.Is(o.Err, wantErr) {
				t.Fatalf("unexpected observation: %+v", o)
			}
		default:
			t.Fatalf("no observation for %s", name)
		}
		select {
		case o := <-observed:
			t.Fatalf("extra observation: %+v", o)
		default:
		}
	}

	check("answer.test", "upstream", 2, nil)
	check("answer.test", "cache", 2, nil)
	s.mu.Lock()
	for key, entry := range s.cache {
		if entry.msg.Question[0].Name == "answer.test." {
			entry.until = time.Now().Add(-time.Second)
			s.cache[key] = entry
		}
	}
	s.mu.Unlock()
	check("answer.test", "stale", 2, nil)
	check("error.test", "error", 0, lookupErr)
}
