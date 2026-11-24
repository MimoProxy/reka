package dns

import (
	"context"
	"errors"
	"strings"

	D "github.com/miekg/dns"
)

// ErrSystemDNSUnavailable means the platform cannot safely perform a packet
// exchange. Address queries can still use the native hostname lookup.
var ErrSystemDNSUnavailable = errors.New("system DNS packet exchange unavailable")

func (s *Service) querySystem(ctx context.Context, q *D.Msg, outcome *resolutionHistory) (*D.Msg, error) {
	if s.opts.SystemExchange != nil {
		m, server, err := s.opts.SystemExchange(ctx, q)
		if err == nil && m != nil {
			if server.IsValid() {
				outcome.SystemServers = []string{server.String()}
			}
			return m, nil
		}
		if err == nil {
			return nil, errors.New("empty system DNS response")
		}
		if !errors.Is(err, ErrSystemDNSUnavailable) {
			return nil, err
		}
	}
	if s.opts.System == nil {
		return nil, ErrSystemDNSUnavailable
	}
	question := q.Question[0]
	if question.Qtype != D.TypeA && question.Qtype != D.TypeAAAA {
		return nil, ErrSystemDNSUnavailable
	}
	addresses, err := s.opts.System(ctx, strings.TrimSuffix(question.Name, "."))
	if err != nil {
		return nil, err
	}
	if s.opts.History != nil {
		outcome.SystemServers = systemResolverServers()
	}
	m := new(D.Msg).SetReply(q)
	for _, ip := range addresses {
		if rr := addressRR(question.Name, question.Qtype, ip, 30); rr != nil {
			m.Answer = append(m.Answer, rr)
		}
	}
	return m, nil
}
