package rulesdata

import (
	"context"
	"net/netip"
	"testing"

	"github.com/MimoProxy/reka/internal/router"
)

func TestMMDBCountryRoutesBothFamilies(t *testing.T) {
	data := load(t, "country.mmdb")
	specs, err := Decode("geoip", "mmdb", "cn", data)
	if err != nil {
		t.Fatal(err)
	}
	r := testRouter(t, specs)
	for ip, want := range map[string]bool{"192.0.2.42": true, "198.51.100.42": false, "2001:db8::42": true, "2001:db9::42": false} {
		d := r.Route(context.Background(), router.Metadata{Addr: netip.MustParseAddr(ip)}, nil)
		if (d.Outbound == "reject") != want {
			t.Fatalf("%s -> %+v", ip, d)
		}
	}
	for _, code := range []string{"", "unknown", "cn@attribute"} {
		if _, err = Decode("geoip", "mmdb", code, data); err == nil {
			t.Fatal("invalid selector accepted", code)
		}
	}
	if _, err = Decode("geoip", "mmdb", "cn", data[:len(data)/2]); err == nil {
		t.Fatal("corrupt MMDB accepted")
	}
}
