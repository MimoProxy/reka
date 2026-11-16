package dns

import (
	"context"
	D "github.com/miekg/dns"
	"net/netip"
	"testing"
)

func TestEndpointOptionsAndScoping(t *testing.T) {
	raw := "https://1.1.1.1/dns-query#h3=true&proxy&ecs=192.0.2.123/24&ecs-override=true"
	scoped := RemapEndpointTarget(raw, func(s string) string { return "source/" + s })
	ep, e := ParseEndpoint(scoped)
	if e != nil || ep.Scheme != "h3" || ep.Via != "source/proxy" || ep.Params["ecs"] != "192.0.2.123/24" {
		t.Fatal(ep, e)
	}
	for _, value := range []string{"https://x.test#h3=1", "udp://1.1.1.1#h3=true", "https://x.test#ecs=invalid", "https://x.test#unknown=true", "https://x.test#disable-qtype-999999=true", "https://x.test#proxy&other", "https://x.test#h3=true&h3=false", "http://x.test#skip-cert-verify=true"} {
		if _, e := ParseEndpoint(value); e == nil {
			t.Fatal("invalid endpoint accepted", value)
		}
	}
}

func TestEndpointECSAndDisabledQuery(t *testing.T) {
	calls := 0
	cfg := Config{Nameservers: []string{"192.0.2.1#ecs=198.51.100.27/24&disable-ipv6=true"}, IPv6: true}
	s := service(t, cfg, func(_ context.Context, ep Endpoint, q *D.Msg, _ func(context.Context, string) ([]netip.Addr, error)) (*D.Msg, error) {
		calls++
		opt := q.IsEdns0()
		if opt == nil || len(opt.Option) != 1 {
			t.Fatal("missing ECS")
		}
		subnet := opt.Option[0].(*D.EDNS0_SUBNET)
		if subnet.SourceNetmask != 24 || subnet.Address.String() != "198.51.100.0" {
			t.Fatal(subnet)
		}
		return answer(q, "192.0.2.9"), nil
	})
	q := query("ecs.test")
	if _, e := s.Exchange(context.Background(), q, "normal", false); e != nil {
		t.Fatal(e)
	}
	if q.IsEdns0() != nil {
		t.Fatal("endpoint ECS mutated caller's request")
	}
	q.Question[0].Qtype = D.TypeAAAA
	m, e := s.Exchange(context.Background(), q, "normal", false)
	if e != nil || len(m.Answer) != 0 || calls != 1 {
		t.Fatal("disabled type used upstream", m, e, calls)
	}
	ep, _ := ParseEndpoint("1.1.1.1#ecs=2001:db8::/32")
	original := query("ecs.test")
	original.SetEdns0(1232, false)
	original.IsEdns0().Option = []D.EDNS0{&D.EDNS0_SUBNET{Code: D.EDNS0SUBNET, Family: 1, SourceNetmask: 24, Address: netip.MustParseAddr("192.0.2.0").AsSlice()}}
	if ep.Request(original) != original {
		t.Fatal("existing ECS should be retained without override")
	}
	ep.Params["ecs-override"] = "true"
	changed := ep.Request(original)
	if changed.IsEdns0().Option[0].(*D.EDNS0_SUBNET).Family != 2 || original.IsEdns0().Option[0].(*D.EDNS0_SUBNET).Family != 1 {
		t.Fatal("ECS override or isolation failed")
	}
}
