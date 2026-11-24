package dns

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	D "github.com/miekg/dns"
)

func TestSystemAddressQueriesFallBackToNativeLookup(t *testing.T) {
	exchangeErr := errors.New("bound dial failed")
	var native int
	s, err := New(Config{Nameservers: []string{"system"}}, Options{
		SystemExchange: func(context.Context, *D.Msg) (*D.Msg, netip.Addr, error) {
			return nil, netip.Addr{}, exchangeErr
		},
		System: func(context.Context, string) ([]netip.Addr, error) {
			native++
			return []netip.Addr{netip.MustParseAddr("192.0.2.21")}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Retire()

	m, err := s.Exchange(t.Context(), new(D.Msg).SetQuestion("fallback.test.", D.TypeA), "normal", false)
	if err != nil || len(m.Answer) != 1 || native != 1 {
		t.Fatalf("address query after a failed exchange: %v, %v, %d native lookups", m, err, native)
	}
	if a, ok := m.Answer[0].(*D.A); !ok || a.A.String() != "192.0.2.21" {
		t.Fatalf("unexpected answer %v", m.Answer[0])
	}

	// The native lookup cannot answer other record types.
	if _, err := s.Exchange(t.Context(), new(D.Msg).SetQuestion("fallback.test.", D.TypeHTTPS), "normal", false); !errors.Is(err, exchangeErr) {
		t.Fatalf("HTTPS query error = %v, want the exchange error", err)
	}
	if native != 1 {
		t.Fatalf("HTTPS query used the native lookup")
	}
}

func TestSystemQueriesStopWhenCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	var native int
	s, err := New(Config{Nameservers: []string{"system"}}, Options{
		SystemExchange: func(ctx context.Context, _ *D.Msg) (*D.Msg, netip.Addr, error) {
			cancel()
			return nil, netip.Addr{}, ctx.Err()
		},
		System: func(context.Context, string) ([]netip.Addr, error) {
			native++
			return nil, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Retire()
	q := new(D.Msg).SetQuestion("canceled.test.", D.TypeAAAA)
	if _, err := s.querySystem(ctx, q, &resolutionHistory{}); !errors.Is(err, context.Canceled) || native != 0 {
		t.Fatalf("canceled query: error %v, %d native lookups", err, native)
	}
}
