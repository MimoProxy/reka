package importer

import (
	"context"
	"net/netip"
	"os"
	"strings"
	"testing"

	"github.com/MimoProxy/reka/internal/config/compile"
	"github.com/MimoProxy/reka/internal/resource"
	"github.com/MimoProxy/reka/internal/router"
)

func TestImportLogicSubRulesAndInline(t *testing.T) {
	data := `rule-providers:
  websites: {type: inline, behavior: domain, payload: ['+.example.org', '*.one.test']}
sub-rules:
 tls:
  - AND,((RULE-SET,websites),(NOT,((NETWORK,UDP)))),REJECT
rules:
 - SUB-RULE,(DST-PORT,443),tls
 - MATCH,DIRECT
`
	result := Import(request(data))
	if !result.Report.CanApply || result.Report.Partial {
		t.Fatal(result.Report)
	}
	eff := compileImport(t, result)
	for _, tc := range []struct {
		domain, network, want string
		port                  uint16
	}{{"a.example.org", "tcp", "reject", 443}, {"x.one.test", "tcp", "reject", 443}, {"x.y.one.test", "tcp", "direct", 443}, {"a.example.org", "udp", "direct", 443}, {"a.example.org", "tcp", "direct", 80}} {
		d := eff.Router.Route(context.Background(), router.Metadata{Domain: tc.domain, Network: tc.network, Port: tc.port}, nil)
		if d.Outbound != tc.want {
			t.Fatal(tc, d)
		}
	}
	bad := strings.Replace(data, "AND,((RULE-SET,websites),(NOT,((NETWORK,UDP)))),REJECT", "SUB-RULE,(NETWORK,TCP),tls", 1)
	req := request(bad)
	req.AllowPartial = true
	if r := Import(req); r.Report.CanApply {
		t.Fatal("cycle accepted", r.Report)
	}
}
func TestImportedRuleProviderAndGeodataBundle(t *testing.T) {
	data := `rule-providers:
 sites: {type: http, behavior: classical, format: text, url: https://rules.example/list}
rules: ['AND,((RULE-SET,sites),(NETWORK,TCP)),REJECT', 'GEOIP,CN,DIRECT,no-resolve', 'MATCH,REJECT']
`
	req := request(data)
	ps, err := Providers(req)
	if err != nil || len(ps) != 1 {
		t.Fatal(ps, err)
	}
	payloads := map[string][]byte{ps[0].ID: []byte("GEOSITE,test@cn\nDOMAIN,other.test\n")}
	geo := map[string][]byte{}
	for _, kind := range []string{"geoip", "geosite"} {
		b, err := os.ReadFile("../../../testdata/rules/" + kind + ".dat")
		if err != nil {
			t.Fatal(err)
		}
		geo[kind] = b
	}
	result := ImportBundle(req, payloads, geo)
	if !result.Report.CanApply {
		t.Fatal(result.Report)
	}
	blobs := map[string][]byte{}
	for _, v := range payloads {
		blobs[resource.Hash(v)] = v
	}
	for _, v := range geo {
		blobs[resource.Hash(v)] = v
	}
	profile := []byte("schema-version: 1\nrules: [{source: airport}]")
	eff, ds := compile.Compile(profile, nil, compile.Options{Sources: []byte(result.Preview(true).Sources), ReadResource: func(h string) ([]byte, error) { return blobs[h], nil }})
	if ds.HasErrors() {
		t.Fatal(ds)
	}
	if got := eff.Router.Route(context.Background(), router.Metadata{Domain: "x.suffix.test", Network: "tcp"}, nil); got.Outbound != "reject" || got.RuleIndex != 0 {
		t.Fatal(got)
	}
	if bad := ImportBundle(req, payloads, map[string][]byte{"geoip": geo["geoip"]}); bad.Report.CanApply {
		t.Fatal("missing GeoSite accepted")
	}
	if bad := ImportBundle(req, payloads, map[string][]byte{"geoip": []byte{0xff}, "geosite": geo["geosite"]}); bad.Report.CanApply {
		t.Fatal("corrupt geo accepted")
	}
}

func TestImportedASNUsesExplicitDatabase(t *testing.T) {
	req := request("rules: ['IP-ASN,13335,REJECT,no-resolve','MATCH,DIRECT']")
	data, err := os.ReadFile("../../../testdata/rules/asn.mmdb")
	if err != nil {
		t.Fatal(err)
	}
	if result := ImportBundle(req, nil, nil); result.Report.CanApply {
		t.Fatal("missing ASN database accepted")
	}
	result := ImportBundle(req, nil, map[string][]byte{"asn": data})
	if !result.Report.CanApply {
		t.Fatal(result.Report)
	}
	eff, ds := compile.Compile([]byte("schema-version: 1\nrules: [{source: airport}]"), nil, compile.Options{Sources: []byte(result.Preview(true).Sources), ReadResource: func(h string) ([]byte, error) { return data, nil }})
	if ds.HasErrors() {
		t.Fatal(ds)
	}
	if got := eff.Router.Route(context.Background(), router.Metadata{Addr: netip.MustParseAddr("192.0.2.42")}, nil); got.Outbound != "reject" {
		t.Fatal(got)
	}
}
