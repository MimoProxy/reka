// mmdbfixture creates tiny original country fixtures; no third-party data.
package main

import (
	"net"
	"os"

	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/mmdbtype"
)

func main() {
	tree, err := mmdbwriter.New(mmdbwriter.Options{DatabaseType: "GeoIP2-Country", Description: map[string]string{"en": "Original Reka documentation-prefix fixture"}, Languages: []string{"en"}, RecordSize: 24, IPVersion: 6, IncludeReservedNetworks: true, BuildEpoch: 1})
	must(err)
	for cidr, code := range map[string]string{"192.0.2.0/24": "CN", "198.51.100.0/24": "US", "2001:db8::/32": "CN"} {
		_, network, e := net.ParseCIDR(cidr)
		must(e)
		must(tree.Insert(network, mmdbtype.Map{"country": mmdbtype.Map{"iso_code": mmdbtype.String(code)}}))
	}
	file, err := os.Create("../../testdata/rules/country.mmdb")
	must(err)
	_, err = tree.WriteTo(file)
	must(err)
	must(file.Close())
}
func must(err error) {
	if err != nil {
		panic(err)
	}
}
