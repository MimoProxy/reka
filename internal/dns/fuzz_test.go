package dns

import (
	"context"
	D "github.com/miekg/dns"
	"net/netip"
	"testing"
)

func FuzzDNSMessages(f *testing.F) {
	q := new(D.Msg)
	q.SetQuestion("fixture.test.", D.TypeA)
	b, _ := q.Pack()
	f.Add(b)
	f.Add([]byte{0xc0, 0x0c})
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 65535 {
			t.Skip()
		}
		q := new(D.Msg)
		if q.Unpack(b) != nil {
			return
		}
		s, err := New(Config{Nameservers: []string{"223.5.5.5"}, CacheSize: 16}, Options{Exchange: func(_ context.Context, _ Endpoint, q *D.Msg, _ func(context.Context, string) ([]netip.Addr, error)) (*D.Msg, error) {
			m := new(D.Msg)
			m.SetReply(q)
			return m, nil
		}})
		if err != nil {
			t.Fatal(err)
		}
		m, err := s.Exchange(context.Background(), q, "normal", false)
		if err == nil {
			if m == nil {
				t.Fatal("nil successful reply")
			}
			if wire, err := m.Pack(); err == nil {
				r := new(D.Msg)
				if err = r.Unpack(wire); err != nil {
					t.Fatal(err)
				}
			}
		}
	})
}
