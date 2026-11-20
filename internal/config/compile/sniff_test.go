package compile

import (
	"slices"
	"testing"
)

func TestSniffDefaultsAndExplicitOptOut(t *testing.T) {
	for _, tt := range []struct {
		name, profile, local string
		enabled              bool
		origin               string
	}{
		{name: "omitted", enabled: true, origin: LayerDefault},
		{name: "profile options", profile: "sniff: {timeout-ms: 450}\n", enabled: true, origin: LayerDefault},
		{name: "local options", profile: "sniff: {enabled: false}\n", local: "sniff: {}\n", enabled: true, origin: LayerDefault},
		{name: "profile disabled", profile: "sniff: {enabled: false}\n", origin: LayerProfile},
		{name: "local disabled", local: "sniff: {enabled: false}\n", origin: LayerLocal},
		{name: "profile null", profile: "sniff: null\n", origin: LayerProfile},
		{name: "local null", profile: "sniff: {enabled: true}\n", local: "sniff: null\n", origin: LayerLocal},
	} {
		t.Run(tt.name, func(t *testing.T) {
			eff, ds := Compile([]byte("schema-version: 1\n"+tt.profile), []byte(tt.local), Options{})
			if ds.HasErrors() {
				t.Fatal(ds)
			}
			if eff.Sniff.Enabled != tt.enabled || eff.Sniff.OverrideDestination {
				t.Fatalf("sniff = %+v, want enabled = %v and original destination", eff.Sniff, tt.enabled)
			}
			if origin, ok := eff.OriginOf("/sniff/enabled"); !ok || origin.Layer != tt.origin {
				t.Fatalf("origin = %+v, want %s", origin, tt.origin)
			}
			if tt.profile == "" && tt.local == "" && (!slices.Equal(eff.Sniff.Protocols, []string{"http", "tls", "quic"}) ||
				eff.Sniff.TimeoutMS != 300 || eff.Sniff.MaxBytes != 65536 || eff.Sniff.MaxPackets != 8) {
				t.Fatalf("unexpected default budgets or protocols: %+v", eff.Sniff)
			}
		})
	}
}

func TestSniffConfigurationBudgetsAndLocalOverride(t *testing.T) {
	profile := []byte("schema-version: 1\nsniff: {enabled: true, protocols: [tls]}\n")
	eff, ds := Compile(profile, nil, Options{})
	if ds.HasErrors() || !eff.Sniff.Enabled || eff.Sniff.TimeoutMS != 300 || len(eff.Sniff.Protocols) != 1 {
		t.Fatalf("sniff=%+v diagnostics=%v", eff, ds)
	}
	eff, ds = Compile(profile, []byte("sniff: {enabled: false}\n"), Options{})
	if ds.HasErrors() || eff.Sniff.Enabled {
		t.Fatalf("local override: %+v %v", eff, ds)
	}
	if origin, ok := eff.OriginOf("/sniff/enabled"); !ok || origin.Layer != LayerLocal {
		t.Fatalf("origin=%+v", origin)
	}
	for _, bad := range []string{"timeout-ms: -1", "max-bytes: 2000000", "max-packets: 33", "protocols: [tls, tls]", "protocols: [unknown]"} {
		if _, ds := Compile([]byte("schema-version: 1\nsniff: {enabled: true, "+bad+"}\n"), nil, Options{}); !ds.HasErrors() {
			t.Fatalf("accepted %s", bad)
		}
	}
}
