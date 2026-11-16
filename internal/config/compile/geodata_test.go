package compile

import (
	"context"
	"fmt"
	"github.com/MimoProxy/reka/internal/resource"
	"github.com/MimoProxy/reka/internal/router"
	"net/netip"
	"os"
	"strings"
	"testing"
)

func TestNativeGeoIPGeoSiteASNAndDatabaseHashValidation(t *testing.T) {
	blobs := map[string][]byte{}
	var definitions strings.Builder
	for _, entry := range []struct{ kind, format, file string }{{"geoip", "dat", "geoip.dat"}, {"geosite", "dat", "geosite.dat"}, {"asn", "mmdb", "asn.mmdb"}} {
		data, err := os.ReadFile("../../../testdata/rules/" + entry.file)
		if err != nil {
			t.Fatal(err)
		}
		hash := resource.Hash(data)
		blobs[hash] = data
		fmt.Fprintf(&definitions, " - {id: %s, format: %s, hash: %s}\n", entry.kind, entry.format, hash)
	}
	for _, test := range []struct{ condition, value, address, domain string }{{"geoip", "CN", "192.0.2.3", ""}, {"geosite", "test", "", "suffix.test"}, {"ip-asn", "AS13335", "2001:db8::7", ""}} {
		profile := "schema-version: 1\ngeodata:\n" + definitions.String() + fmt.Sprintf("rules: [{id: geo, match: {%s: %s}, outbound: reject}, {match: {all: true}, outbound: direct}]\n", test.condition, test.value)
		eff, ds := Compile([]byte(profile), nil, Options{ReadResource: func(hash string) ([]byte, error) { return blobs[hash], nil }})
		if ds.HasErrors() {
			t.Fatal(test, ds)
		}
		metadata := router.Metadata{Domain: test.domain}
		if test.address != "" {
			metadata.Addr = netip.MustParseAddr(test.address)
		}
		if got := eff.Router.Route(context.Background(), metadata, nil); got.Outbound != "reject" {
			t.Fatal(test, got)
		}
		_, ds = Compile([]byte(profile), nil, Options{ReadResource: func(hash string) ([]byte, error) { return []byte("bad database"), nil }})
		if !ds.HasErrors() {
			t.Fatal("hash mismatch accepted")
		}
	}
	for _, profile := range []string{
		"geodata: [{id: unknown, hash: " + strings.Repeat("a", 64) + ", format: dat}]",
		"rules: [{match: {geosite: test}, outbound: reject}]",
		"rules: [{match: {ip-asn: 13335}, outbound: reject}]",
	} {
		if _, ds := Compile([]byte("schema-version: 1\n"+profile), nil, Options{}); !ds.HasErrors() {
			t.Fatal("invalid database configuration accepted", profile)
		}
	}
}
