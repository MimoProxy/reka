package compile

import (
	"testing"
)

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
