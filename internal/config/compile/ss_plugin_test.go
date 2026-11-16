package compile

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestPluginSecretsReplaceOnlyTheirOwningTransport(t *testing.T) {
	secrets := store(t)
	secrets.Set("plugin/password", "outer-private-one")
	input := `schema-version: 1
outbounds:
 - {id: node, name: first, type: shadowsocks, server: proxy.test, port: 443, method: aes-128-gcm, password: test, plugin: {type: shadow-tls, host: camouflage.test, version: 3, password: 'secret://plugin/password'}}
 - {id: unrelated, type: direct}
`
	first, ds := Compile([]byte(input), nil, Options{Secrets: secrets})
	if ds.HasErrors() {
		t.Fatal(ds)
	}
	if first.Outbounds[0].Plugin.Password != "outer-private-one" {
		t.Fatal("plugin secret unresolved")
	}
	data, _ := json.Marshal(first)
	if strings.Contains(string(data), "outer-private") {
		t.Fatal("plugin secret exposed in effective state")
	}
	renamed, ds := Compile([]byte(strings.Replace(input, "name: first", "name: second", 1)), nil, Options{Secrets: secrets})
	if ds.HasErrors() || renamed.Outbounds[0].Fingerprint != first.Outbounds[0].Fingerprint {
		t.Fatal("display edit replaced plugin transport", ds)
	}
	secrets.Set("plugin/password", "outer-private-two")
	second, ds := Compile([]byte(input), nil, Options{Secrets: secrets})
	if ds.HasErrors() {
		t.Fatal(ds)
	}
	if first.Outbounds[0].Fingerprint == second.Outbounds[0].Fingerprint || first.Outbounds[1].Fingerprint != second.Outbounds[1].Fingerprint {
		t.Fatal("plugin credential rotation replaced the wrong transports")
	}
}
