package importer

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"testing"

	"github.com/MimoProxy/reka/internal/config/compile"
	"github.com/MimoProxy/reka/internal/resource"
	"github.com/MimoProxy/reka/internal/router"
)

func TestImportLockedMMDBGEOIP(t *testing.T) {
	data, err := os.ReadFile("../../../testdata/rules/country.mmdb")
	if err != nil {
		t.Fatal(err)
	}
	result := ImportBundle(request("proxies: []\nrules: ['GEOIP,CN,REJECT','MATCH,DIRECT']\n"), nil, map[string][]byte{"geoip": data})
	if !result.Report.CanApply {
		t.Fatalf("MMDB import: %+v", result.Report)
	}
	// ImportBundle binds the original resource hash, then the normal compiler
	// and router must execute the resulting country selector.
	eff, ds := compile.Compile([]byte("schema-version: 1\nimports: [{source: airport, rule-sets: true}]\nrules: [{source: airport}]\n"), nil, compile.Options{Sources: []byte(result.Preview(true).Sources), ReadResource: func(hash string) ([]byte, error) {
		if hash != resource.Hash(data) {
			return nil, fmt.Errorf("unexpected resource hash")
		}
		return data, nil
	}})
	if ds.HasErrors() {
		t.Fatal(ds)
	}
	if decision := eff.Router.Route(context.Background(), router.Metadata{Addr: netip.MustParseAddr("192.0.2.42")}, nil); decision.Outbound != "reject" {
		t.Fatalf("imported MMDB did not route: %+v", decision)
	}
}
