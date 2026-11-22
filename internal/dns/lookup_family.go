package dns

import (
	"context"
	"errors"
	"net/netip"
	"strings"

	D "github.com/miekg/dns"

	"github.com/MimoProxy/reka/internal/history"
)

// LookupIPFamily resolves real addresses of a single family for diagnostics.
// It uses the named scope even when client AAAA answers are disabled.
func (s *Service) LookupIPFamily(ctx context.Context, domain, scope string, qtype uint16) ([]netip.Addr, error) {
	if qtype != D.TypeA && qtype != D.TypeAAAA {
		return nil, errors.New("invalid address question type")
	}
	ctx = history.WithDNSOrigin(ctx, history.DNSOrigin{Kind: "resolver"})
	seen := make(map[string]bool)
	name := D.Fqdn(domain)
	for len(seen) < 8 && !seen[strings.ToLower(name)] {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		seen[strings.ToLower(name)] = true
		q := new(D.Msg).SetQuestion(name, qtype)
		m, err := s.exchangeRecorded(ctx, q, scope, exchangeOptions{includeIPv6: true})
		if err != nil {
			return nil, err
		}
		if m.Rcode == D.RcodeNameError {
			return nil, nil
		}
		if m.Rcode != D.RcodeSuccess || m.Truncated {
			return nil, errors.New("DNS lookup failed")
		}
		var addrs []netip.Addr
		var alias string
		for _, rr := range m.Answer {
			switch a := rr.(type) {
			case *D.CNAME:
				alias = a.Target
			case *D.A:
				if ip, ok := netip.AddrFromSlice(a.A); ok && qtype == D.TypeA {
					addrs = append(addrs, ip.Unmap())
				}
			case *D.AAAA:
				if ip, ok := netip.AddrFromSlice(a.AAAA); ok && qtype == D.TypeAAAA {
					addrs = append(addrs, ip)
				}
			}
		}
		if len(addrs) != 0 || alias == "" {
			return addrs, nil
		}
		name = D.Fqdn(alias)
	}
	return nil, errors.New("DNS CNAME loop or depth exceeded")
}
