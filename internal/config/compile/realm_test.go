package compile

import (
	"strings"
	"testing"
)

func TestRealmResolvesMaskedTokenAndRejectsAmbiguousRates(t *testing.T) {
	secrets := store(t)
	if err := secrets.Set("realm/token", "resolved-token"); err != nil {
		t.Fatal(err)
	}
	input := `schema-version: 1
outbounds: [{id: node, type: hysteria2, password: node-secret, tls: {server-name: proxy.test}, protocol: {up-bps: 62500, realm: {enabled: true, server-url: 'https://control.test', token: 'secret://realm/token', realm-id: room, stun-servers: [stun.test]}}}]
`
	eff, ds := Compile([]byte(input), nil, Options{Secrets: secrets})
	if ds.HasErrors() {
		t.Fatal(ds)
	}
	if eff.Outbounds[0].Protocol.Realm.Token != "resolved-token" {
		t.Fatal("Realm secret unresolved")
	}
	if err := secrets.Set("realm/token", "rotated-token"); err != nil {
		t.Fatal(err)
	}
	rotated, ds := Compile([]byte(input), nil, Options{Secrets: secrets})
	if ds.HasErrors() || rotated.Outbounds[0].Fingerprint == eff.Outbounds[0].Fingerprint {
		t.Fatal("resolved Realm token did not replace transport", ds)
	}
	for _, rate := range []string{"up-bps: 62500, up-mbps: 1", "up-mbps: 9223372036854775807"} {
		_, ds = Compile([]byte(strings.Replace(input, "up-bps: 62500", rate, 1)), nil, Options{Secrets: secrets})
		if !ds.HasErrors() {
			t.Fatal("ambiguous/overflowing rate accepted", rate)
		}
	}
}
