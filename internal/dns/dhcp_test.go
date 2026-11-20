package dns

import (
	"context"
	"net/netip"
	"testing"

	D "github.com/miekg/dns"
)

func TestDHCPDNSEndpointsAndLocalRouting(t *testing.T) {
	for raw, want := range map[string]string{"dhcp://en0": "en0", "dhcp://Ethernet%202": "Ethernet 2"} {
		ep, err := ParseEndpoint(raw)
		if err != nil || ep.Scheme != "dhcp" || ep.Host != want || ep.Port != "53" {
			t.Errorf("%s: %+v %v", raw, ep, err)
		}
	}
	for _, bad := range []string{"dhcp://", "dhcp://en0:53", "dhcp://en0#proxy", "dhcp://en0/path", "dhcp://bad%2Fname", "dhcp://-help"} {
		if _, err := ParseEndpoint(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	if ep, err := ParseEndpoint("dhcp://system"); err != nil || ep.Scheme != "system" {
		t.Fatal("legacy system alias changed", ep, err)
	}
	svc, err := New(Config{Nameservers: []string{"dhcp://en0"}, Bootstrap: []string{"dhcp://en0"}, RespectRules: true}, Options{
		Route: func(context.Context, Endpoint) string {
			t.Error("DHCP DNS attempted normal outbound selection")
			return ""
		},
		Exchange: func(_ context.Context, e Endpoint, q *D.Msg, _ func(context.Context, string) ([]netip.Addr, error)) (*D.Msg, error) {
			if e.Scheme != "dhcp" || e.Host != "en0" || e.Via != "" {
				t.Errorf("wrong resolver: %+v", e)
			}
			return new(D.Msg).SetReply(q), nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Retire()
	if _, err := svc.Exchange(context.Background(), new(D.Msg).SetQuestion("example.test.", D.TypeTXT), "normal", false); err != nil {
		t.Fatal(err)
	}
}
