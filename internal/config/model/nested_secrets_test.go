package model

import (
	"strings"
	"testing"
)

func TestNestedSecretsRoundTrip(t *testing.T) {
	original := `schema-version: 1
outbounds:
 - id: node
   type: snell
   password: node-secret
   protocol: {version: 6, user-key: user-secret, obfs: {type: salamander, password: obfs-secret}}
   transport: {type: ws, headers: [{name: Authorization, value: header-secret}]}
dns: {nameserver: ['https://dns.test/query?key=dns-secret']}
`
	base, ds := LoadDoc(DocProfile, []byte(original))
	if ds.HasErrors() {
		t.Fatal(ds)
	}
	masked, _ := LoadDoc(DocProfile, []byte(original))
	if n := masked.MaskSecrets(); n < 5 {
		t.Fatal(n)
	}
	for _, secret := range []string{"node-secret", "user-secret", "obfs-secret", "header-secret", "dns-secret"} {
		if strings.Contains(string(masked.Bytes()), secret) {
			t.Fatal("nested credential leaked")
		}
	}
	if e := masked.UnmaskSecrets(base); e != nil {
		t.Fatal(e)
	}
	for _, secret := range []string{"user-secret", "obfs-secret", "header-secret", "dns-secret"} {
		if !strings.Contains(string(masked.Bytes()), secret) {
			t.Fatal("masked value not restored")
		}
	}
}

func TestHealthURLSecretsInSourcesAndOverlay(t *testing.T) {
	for name, data := range map[string]string{
		DocSources: "sources: [{id: remote, groups: [{id: health, type: url-test, url: 'https://health.test/?key=private-token', members: [direct]}]}]",
		DocOverlay: "patches: [{op: set, path: /groups/health/url, value: 'https://health.test/?key=private-token'}, {op: set, path: /dns, value: {nameserver: ['https://dns.test/?key=dns-token']}}]",
	} {
		base, ds := LoadDoc(name, []byte(data))
		if ds.HasErrors() {
			t.Fatal(ds)
		}
		doc, _ := LoadDoc(name, []byte(data))
		if doc.MaskSecrets() == 0 || strings.Contains(string(doc.Bytes()), "-token") {
			t.Fatal("URL token leaked", name)
		}
		if e := doc.UnmaskSecrets(base); e != nil {
			t.Fatal(e)
		}
		if !strings.Contains(string(doc.Bytes()), "private-token") {
			t.Fatal("URL not restored")
		}
	}
}
