package rulesdata

import (
	"context"
	"encoding/binary"
	"net/netip"
	"os"
	"testing"

	"github.com/MimoProxy/reka/internal/router"
	"github.com/klauspost/compress/zstd"
)

func load(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("../../testdata/rules/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func testRouter(t *testing.T, specs []router.RuleSpec) *router.Router {
	t.Helper()
	for i := range specs {
		specs[i].Target = "reject"
	}
	set, err := router.CompileRules(specs)
	if err != nil {
		t.Fatal(err)
	}
	r, err := router.New(set, router.Options{Outbounds: []string{"direct", "reject"}, Final: "direct"})
	if err != nil {
		t.Fatal(err)
	}
	return r
}
func TestMRSReferenceDomainAndIP(t *testing.T) {
	specs, err := Decode("domain", "mrs", "", load(t, "domain.mrs"))
	if err != nil {
		t.Fatal(err)
	}
	r := testRouter(t, specs)
	for domain, want := range map[string]bool{"exact.test": true, "a.exact.test": false, "suffix.test": true, "a.b.suffix.test": true, "sub.test": false, "a.b.sub.test": true, "x.one.test": true, "x.y.one.test": false, "a.b.nested.test": true, "a.b.c.nested.test": false, "bad.test": false} {
		got := r.Route(context.Background(), router.Metadata{Domain: domain}, nil)
		if (got.Outbound == "reject") != want {
			t.Errorf("%s: %+v want %v", domain, got, want)
		}
	}
	specs, err = Decode("ipcidr", "mrs", "", load(t, "ipcidr.mrs"))
	if err != nil {
		t.Fatal(err)
	}
	r = testRouter(t, specs)
	for ip, want := range map[string]bool{"192.0.2.1": true, "192.0.3.1": false, "2001:db8::1": true, "2001:db9::1": false} {
		got := r.Route(context.Background(), router.Metadata{Addr: netip.MustParseAddr(ip)}, nil)
		if (got.Outbound == "reject") != want {
			t.Fatal(ip, got)
		}
	}
}
func TestGeoReferenceSelectors(t *testing.T) {
	for _, tc := range []struct {
		behavior, code, name string
		ips, domains         map[string]bool
	}{
		{"geoip", "cn", "geoip.dat", map[string]bool{"192.0.2.1": true, "2001:db8::1": true, "198.51.100.1": false}, nil},
		{"geoip", "reverse", "geoip.dat", map[string]bool{"192.0.2.1": false, "198.51.100.1": true}, nil},
		{"geosite", "test", "geosite.dat", nil, map[string]bool{"suffix.test": true, "x.suffix.test": true, "exact.test": true, "x.exact.test": false, "a-keyword.test": true, "regex12.test": true}},
		{"geosite", "test@cn", "geosite.dat", nil, map[string]bool{"x.suffix.test": true, "exact.test": false, "keyword.test": false}},
	} {
		specs, err := Decode(tc.behavior, "dat", tc.code, load(t, tc.name))
		if err != nil {
			t.Fatal(err)
		}
		r := testRouter(t, specs)
		for ip, want := range tc.ips {
			got := r.Route(context.Background(), router.Metadata{Addr: netip.MustParseAddr(ip)}, nil)
			if (got.Outbound == "reject") != want {
				t.Fatal(tc.code, ip, got)
			}
		}
		for domain, want := range tc.domains {
			got := r.Route(context.Background(), router.Metadata{Domain: domain}, nil)
			if (got.Outbound == "reject") != want {
				t.Fatal(tc.code, domain, got)
			}
		}
	}
	for _, code := range []string{"missing", "test@missing"} {
		if _, err := Decode("geosite", "dat", code, load(t, "geosite.dat")); err == nil {
			t.Fatal("missing code accepted")
		}
	}
}
func TestRuleFormatsAndCorruption(t *testing.T) {
	for _, tc := range []struct{ behavior, format, body string }{{"domain", "yaml", "payload: ['+.example.org','exact.test']"}, {"domain", "text", "# comment\n+.example.org\nexact.test\n"}, {"classical", "yaml", "payload: ['AND,((NETWORK,TCP),(DST-PORT,443))','DOMAIN,yes.test']"}} {
		specs, err := Decode(tc.behavior, tc.format, "", []byte(tc.body))
		if err != nil || len(specs) == 0 {
			t.Fatal(tc, err)
		}
	}
	for _, body := range []string{"payload: [10]", "payload: ['x']\nother: 1", "payload: &x [*x]"} {
		if _, err := Decode("domain", "yaml", "", []byte(body)); err == nil {
			t.Fatal("invalid YAML accepted", body)
		}
	}
	for _, s := range []string{"MATCH", "RULE-SET,other", "DOMAIN,yes.test,direct", "AND,((NETWORK,TCP),(UNKNOWN,x))", "AND,((RULE-SET,other),(NETWORK,TCP))"} {
		if _, err := Decode("classical", "text", "", []byte(s)); err == nil {
			t.Fatal("invalid classical accepted", s)
		}
	}
	data := load(t, "domain.mrs")
	for i := 0; i < len(data); i++ {
		if _, err := Decode("domain", "mrs", "", data[:i]); err == nil {
			t.Fatal("truncated MRS accepted", i)
		}
	}
	z, _ := zstd.NewWriter(nil)
	defer z.Close()
	raw := []byte{'M', 'R', 'S', 1, 0}
	raw = binary.BigEndian.AppendUint64(raw, 1)
	raw = binary.BigEndian.AppendUint64(raw, ^uint64(0))
	if _, err := Decode("domain", "mrs", "", z.EncodeAll(raw, nil)); err == nil {
		t.Fatal("huge length accepted")
	}
	if _, err := Decode("ipcidr", "mrs", "", data); err == nil {
		t.Fatal("behavior mismatch accepted")
	}
	if _, err := Decode("geoip", "dat", "cn", []byte{0xff}); err == nil {
		t.Fatal("corrupt geodata accepted")
	}
}
func FuzzDecodeMRS(f *testing.F) {
	for _, name := range []string{"domain.mrs", "ipcidr.mrs"} {
		b, err := os.ReadFile("../../testdata/rules/" + name)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 1<<20 {
			t.Skip()
		}
		_, _ = Decode("domain", "mrs", "", b)
		_, _ = Decode("ipcidr", "mrs", "", b)
	})
}
