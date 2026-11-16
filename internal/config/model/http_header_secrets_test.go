package model

import (
	"strings"
	"testing"
)

func TestHTTPHeaderSecretsKeepIdentity(t *testing.T) {
	for name, input := range map[string]string{
		DocProfile: "schema-version: 1\noutbounds: [{id: http, type: http, server: node.test, port: 80, headers: [{name: Authorization, value: private-header-token}]}]",
		DocSources: "sources: [{id: remote, outbounds: [{id: http, type: http, server: node.test, port: 80, headers: [{name: Authorization, value: private-header-token}]}]}]",
		DocOverlay: "patches: [{op: set, path: /outbounds/http/headers, value: [{name: Authorization, value: private-header-token}]}]",
	} {
		base, ds := LoadDoc(name, []byte(input))
		if ds.HasErrors() {
			t.Fatal(ds)
		}
		masked, ds := LoadDoc(name, []byte(input))
		if ds.HasErrors() {
			t.Fatal(ds)
		}
		if masked.MaskSecrets() == 0 || strings.Contains(string(masked.Bytes()), "private-header-token") {
			t.Fatal("HTTP header leaked", name)
		}
		changed, ds := LoadDoc(name, []byte(strings.ReplaceAll(string(masked.Bytes()), "Authorization", "X-Other")))
		if ds.HasErrors() {
			t.Fatal(ds)
		}
		if e := changed.UnmaskSecrets(base); e == nil {
			t.Fatal("credential moved to a different header", name)
		}
		if e := masked.UnmaskSecrets(base); e != nil {
			t.Fatal(name, e)
		}
	}
}
