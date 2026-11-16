package importer

import (
	"context"
	"net/netip"
	"os"
	"testing"

	"github.com/MimoProxy/reka/internal/config/compile"
	RD "github.com/MimoProxy/reka/internal/dns"
	"github.com/MimoProxy/reka/internal/resource"
	"github.com/MimoProxy/reka/internal/router"
	D "github.com/miekg/dns"
)

func TestDNSFallbackGeoSiteUsesLockedResource(t *testing.T) {
	data, e := os.ReadFile("../../../testdata/rules/geosite.dat")
	if e != nil {
		t.Fatal(e)
	}
	req := request("dns: {enable: true, nameserver: [192.0.2.1], fallback: [192.0.2.2], fallback-filter: {geoip: false, geosite: [test@cn]}}")
	if r := ImportBundle(req, nil, nil); r.Report.CanApply {
		t.Fatal("missing GeoSite asset accepted")
	}
	result := ImportBundle(req, nil, map[string][]byte{"geosite": data})
	if !result.Report.CanApply {
		t.Fatal(result.Report)
	}
	eff, ds := compile.Compile([]byte("schema-version: 1\nimports: [{source: airport, rule-sets: true}]\ndns: {from: airport}\n"), nil, compile.Options{Sources: []byte(result.Preview(true).Sources), ReadResource: func(hash string) ([]byte, error) {
		if hash != resource.Hash(data) {
			t.Fatal("wrong asset requested")
		}
		return data, nil
	}})
	if ds.HasErrors() {
		t.Fatal(ds)
	}
	service, e := RD.New(*eff.DNS, RD.Options{Match: func(pattern, domain string, addr netip.Addr) bool {
		matcher := eff.DNSMatches[pattern]
		if matcher == nil {
			return false
		}
		return matcher.Route(context.Background(), router.Metadata{Domain: domain, Addr: addr}, nil).Outbound == "yes"
	}, Exchange: func(_ context.Context, ep RD.Endpoint, q *D.Msg, _ func(context.Context, string) ([]netip.Addr, error)) (*D.Msg, error) {
		m := new(D.Msg)
		m.SetReply(q)
		rr, e := D.NewRR(q.Question[0].Name + " 30 IN A " + ep.Host)
		if e != nil {
			t.Fatal(e)
		}
		m.Answer = []D.RR{rr}
		return m, nil
	}})
	if e != nil {
		t.Fatal(e)
	}
	for _, tc := range []struct{ domain, want string }{{"x.suffix.test", "192.0.2.2"}, {"exact.test", "192.0.2.1"}} {
		ips, e := service.Lookup(context.Background(), tc.domain, "normal")
		if e != nil || len(ips) != 1 || ips[0].String() != tc.want {
			t.Fatal(tc, ips, e)
		}
	}
}
