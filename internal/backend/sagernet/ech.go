package sagernet

import (
	"context"
	"errors"
	"slices"
	"strings"

	"github.com/miekg/dns"
)

type ECHSpec struct {
	Config, QueryServerName string
	Lookup                  func(context.Context, string) ([]byte, error)
}

func configureECHContext(ctx context.Context, s *TLSSpec) context.Context {
	if s == nil || s.ECH == nil || s.ECH.Lookup == nil {
		return ctx
	}
	return context.WithValue(ctx, "reka.tls.ech.lookup.v1", s.ECH.Lookup)
}

// ResolveECH uses the proxy-server DNS scope supplied by the generation. It
// never substitutes address lookups, Fake IP or an unprotected system socket.
func ResolveECH(ctx context.Context, name string, exchange func(context.Context, *dns.Msg) (*dns.Msg, error)) ([]byte, error) {
	seen := map[string]bool{}
	for range 8 {
		name = strings.ToLower(dns.Fqdn(name))
		if seen[name] {
			return nil, errors.New("ECH DNS alias cycle")
		}
		seen[name] = true
		q := new(dns.Msg)
		q.SetQuestion(name, dns.TypeHTTPS)
		answer, err := exchange(ctx, q)
		if err != nil {
			return nil, err
		}
		if answer == nil || answer.Rcode != dns.RcodeSuccess {
			return nil, errors.New("ECH DNS query failed")
		}
		records := map[string][]*dns.HTTPS{}
		cnames := map[string]string{}
		for _, rr := range answer.Answer {
			switch value := rr.(type) {
			case *dns.CNAME:
				cnames[strings.ToLower(value.Hdr.Name)] = value.Target
			case *dns.HTTPS:
				records[strings.ToLower(value.Hdr.Name)] = append(records[strings.ToLower(value.Hdr.Name)], value)
			}
		}
		current := name
		localSeen := map[string]bool{}
		queryAlias := false
		for range 8 {
			if localSeen[current] {
				return nil, errors.New("ECH DNS alias cycle")
			}
			localSeen[current] = true
			items := records[current]
			slices.SortStableFunc(items, func(a, b *dns.HTTPS) int { return int(a.Priority) - int(b.Priority) })
			alias := cnames[current]
			for _, record := range items {
				if record.Priority == 0 {
					if record.Target != "." {
						alias = record.Target
					}
					break
				}
				for _, param := range record.Value {
					if ech, ok := param.(*dns.SVCBECHConfig); ok && len(ech.ECH) > 0 {
						return append([]byte{}, ech.ECH...), nil
					}
				}
			}
			if alias != "" {
				current = strings.ToLower(dns.Fqdn(alias))
				continue
			}
			if current != name {
				name = current
				queryAlias = true
				break
			}
			return nil, errors.New("no ECH config in HTTPS DNS response")
		}
		if !queryAlias {
			return nil, errors.New("ECH DNS alias depth exceeded")
		}
	}
	return nil, errors.New("ECH DNS alias depth exceeded")
}
