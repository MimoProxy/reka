package rulesdata

import (
	"bytes"
	"context"
	"net/netip"
	"reflect"
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

func TestASNDatabaseBothFamiliesAndMalformedSelectors(t *testing.T) {
	data := load(t, "asn.mmdb")
	specs, err := Decode("asn", "mmdb", "AS13335", data)
	if err != nil {
		t.Fatal(err)
	}
	router := testRouter(t, specs)
	for ip, want := range map[string]bool{"192.0.2.7": true, "2001:db8::42": true, "198.51.100.3": false, "203.0.113.1": false} {
		got := router.Route(context.Background(), routerMetadata(ip), nil)
		if (got.Outbound == "reject") != want {
			t.Fatal(ip, got)
		}
	}
	for _, code := range []string{"0", "4294967296", "bogus", "64513", ""} {
		if _, err := Decode("asn", "mmdb", code, data); err == nil {
			t.Fatal("invalid ASN accepted", code)
		}
	}
	if err := ValidateDatabase("asn", "mmdb", data); err != nil {
		t.Fatal(err)
	}
	if err := ValidateDatabase("asn", "dat", data); err == nil {
		t.Fatal("wrong format accepted")
	}
	if _, err := Decode("asn", "mmdb", "13335", data[:len(data)/2]); err == nil {
		t.Fatal("truncated ASN database accepted")
	}
}
func routerMetadata(ip string) router.Metadata { return router.Metadata{Addr: netip.MustParseAddr(ip)} }

func TestSubsetMMDBPreservesSelectedNetworks(t *testing.T) {
	for _, tc := range []struct {
		kind, file, code, excluded string
	}{
		{"asn", "asn.mmdb", "AS13335", "64512"},
		{"geoip", "country.mmdb", "cn", "us"},
	} {
		t.Run(tc.kind, func(t *testing.T) {
			full := load(t, tc.file)
			subset, err := SubsetDatabase(tc.kind, full, []string{tc.code})
			if err != nil {
				t.Fatal(err)
			}
			if len(subset) >= len(full)/4 || GeodataFormat(tc.kind, subset) != "dat" {
				t.Fatalf("expected compact DAT, got %d bytes from %d bytes", len(subset), len(full))
			}
			if err := ValidateDatabase(tc.kind, "dat", subset); err != nil {
				t.Fatal(err)
			}
			before, err := Decode(tc.kind, "mmdb", tc.code, full)
			if err != nil {
				t.Fatal(err)
			}
			after, err := Decode(tc.kind, "dat", tc.code, subset)
			if err != nil || !reflect.DeepEqual(after, before) {
				t.Fatalf("subset changed networks: %v, %v", after, err)
			}
			if _, err := Decode(tc.kind, "dat", tc.excluded, subset); err == nil {
				t.Fatalf("unselected code %s is present", tc.excluded)
			}
			if _, err := SubsetDatabase(tc.kind, full[:len(full)/2], []string{tc.code}); err == nil {
				t.Fatal("truncated MMDB accepted")
			}
		})
	}
}

func TestSubsetASNProducesDeterministicDAT(t *testing.T) {
	full := load(t, "asn.mmdb")
	first, err := SubsetDatabase("asn", full, []string{"64512", "AS013335", "13335"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := SubsetDatabase("asn", full, []string{"AS13335", "64512"})
	if err != nil || !bytes.Equal(first, second) {
		t.Fatal("changing selector order or spelling changed the DAT", err)
	}
	onlySecond, err := SubsetDatabase("asn", second, []string{"AS064512"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decode("asn", "dat", "AS64512", onlySecond); err != nil {
		t.Fatal(err)
	}
	if _, err := Decode("asn", "dat", "13335", onlySecond); err == nil {
		t.Fatal("unselected ASN is present")
	}
	for _, code := range []string{"0", "4294967296", "bogus", "64513"} {
		if _, err := SubsetDatabase("asn", full, []string{code}); err == nil {
			t.Fatal("invalid or missing ASN accepted", code)
		}
	}
	if err := ValidateDatabase("asn", "dat", load(t, "geoip.dat")); err == nil {
		t.Fatal("non-numeric ASN DAT code accepted")
	}
}
