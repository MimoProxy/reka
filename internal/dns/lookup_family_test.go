package dns

import (
	"context"
	"net/netip"
	"slices"
	"testing"

	D "github.com/miekg/dns"
)

func TestLookupIPFamilyUsesRealScopedDNS(t *testing.T) {
	var questions []D.Question
	cfg := Config{Mode: "fake-ip", Nameservers: []string{"192.0.2.1"}, Direct: []string{"192.0.2.2"}}
	s := service(t, cfg, func(_ context.Context, ep Endpoint, q *D.Msg, _ func(context.Context, string) ([]netip.Addr, error)) (*D.Msg, error) {
		if ep.Scope != "direct" || ep.Host != "192.0.2.2" {
			t.Fatalf("unexpected resolver %s in %s scope", ep.Host, ep.Scope)
		}
		question := q.Question[0]
		questions = append(questions, question)
		m := new(D.Msg).SetReply(q)
		switch question.Name {
		case "alias.test.":
			m.Answer = []D.RR{hostCNAME(question.Name, "target.test.")}
		case "target.test.":
			ip := netip.MustParseAddr("192.0.2.8")
			if question.Qtype == D.TypeAAAA {
				ip = netip.MustParseAddr("2001:db8::8")
			}
			m.Answer = []D.RR{addressRR(question.Name, question.Qtype, ip, 10)}
		case "absent.test.":
			m.Rcode = D.RcodeNameError
		case "failure.test.":
			m.Rcode = D.RcodeServerFailure
		}
		return m, nil
	})
	t.Cleanup(s.Retire)
	for _, tc := range []struct {
		typ  uint16
		want string
	}{{D.TypeA, "192.0.2.8"}, {D.TypeAAAA, "2001:db8::8"}} {
		got, err := s.LookupIPFamily(t.Context(), "alias.test", "direct", tc.typ)
		if err != nil || !slices.Equal(got, []netip.Addr{netip.MustParseAddr(tc.want)}) {
			t.Fatalf("lookup %s = %v, %v", D.TypeToString[tc.typ], got, err)
		}
	}
	if len(questions) != 4 || questions[0].Qtype != D.TypeA || questions[1].Qtype != D.TypeA ||
		questions[2].Qtype != D.TypeAAAA || questions[3].Qtype != D.TypeAAAA {
		t.Fatalf("unexpected questions %v", questions)
	}
	q := new(D.Msg).SetQuestion("target.test.", D.TypeAAAA)
	if m, err := s.Exchange(t.Context(), q, "direct", false); err != nil || len(m.Answer) != 0 || len(questions) != 4 {
		t.Fatalf("ordinary AAAA exchange was not filtered: %v, %v", m, err)
	}
	for _, name := range []string{"empty.test", "absent.test"} {
		if got, err := s.LookupIPFamily(t.Context(), name, "direct", D.TypeAAAA); err != nil || len(got) != 0 {
			t.Fatalf("lookup %s = %v, %v", name, got, err)
		}
	}
	if _, err := s.LookupIPFamily(t.Context(), "failure.test", "direct", D.TypeAAAA); err == nil {
		t.Fatal("server failure was treated as a missing record")
	}
}
