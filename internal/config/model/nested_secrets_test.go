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
	if err := masked.UnmaskSecrets(base); err != nil {
		t.Fatal(err)
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
		if err := doc.UnmaskSecrets(base); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(doc.Bytes()), "private-token") {
			t.Fatal("URL not restored")
		}
	}
}

// TestCredentialURLs pins which DNS and health-check URLs count as
// credentials: user info, a query, or a DoH path that is not a standard
// endpoint. Other DNS fields are never masked.
func TestCredentialURLs(t *testing.T) {
	for v, want := range map[string]bool{
		"https://dns.test/dns-query":          false,
		"https://1.1.1.1/dns-query#proxy":     false,
		"https://dns.test/resolve":            false,
		"https://dns.test":                    false,
		"tls://1.1.1.1":                       false,
		"tls://dns.test:853#direct":           false,
		"223.5.5.5":                           false,
		"[2400:3200::1]:53":                   false,
		"system":                              false,
		"dhcp://en0":                          false,
		"https://dns.test/dns-query?key=x":    true,
		"https://dns.nextdns.io/abc123":       true,
		"https://dns.test/dns-query/token123": true,
		"https://user:pw@dns.test/dns-query":  true,
		"tls://user@dns.test":                 true,
	} {
		if got := credentialURL(v, true); got != want {
			t.Errorf("DNS %q: masked=%v, want %v", v, got, want)
		}
	}
	for v, want := range map[string]bool{
		"https://www.gstatic.com/generate_204":     false,
		"http://cp.cloudflare.com/":                false,
		"https://health.test/check?key=token":      true,
		"https://user:pw@health.test/generate_204": true,
	} {
		if got := credentialURL(v, false); got != want {
			t.Errorf("health %q: masked=%v, want %v", v, got, want)
		}
	}
	doc, _ := LoadDoc(DocProfile, []byte(`schema-version: 1
dns:
  listen: 127.0.0.1:1053
  nameserver: ['https://dns.test/dns-query', 'https://dns.nextdns.io/abc123']
  nameserver-policy: [{id: corp, pattern: '+.corp.test', servers: ['https://u:p@corp.test/dns-query']}]
  fake-ip-filter: ['*.lan', 'stun.?.test', 'a@b.test']
  hosts: [{id: 'x@y.test', addresses: [192.0.2.1]}]
`))
	if n := doc.MaskSecrets(); n != 2 {
		t.Fatalf("masked %d values, want 2:\n%s", n, doc.Bytes())
	}
	out := string(doc.Bytes())
	for _, keep := range []string{"stun.?.test", "a@b.test", "x@y.test", "https://dns.test/dns-query"} {
		if !strings.Contains(out, keep) {
			t.Errorf("%q was masked:\n%s", keep, out)
		}
	}
}

func TestRealmTokenMaskAndRestore(t *testing.T) {
	const source = "schema-version: 1\noutbounds: [{id: realm, type: hysteria2, protocol: {realm: {enabled: true, token: private-realm-token}}}]\n"
	doc, ds := LoadDoc(DocProfile, []byte(source))
	if ds.HasErrors() {
		t.Fatal(ds)
	}
	masked, _ := LoadDoc(DocProfile, []byte(source))
	if masked.MaskSecrets() != 1 || strings.Contains(string(masked.Bytes()), "private-realm-token") {
		t.Fatal("Realm token leaked")
	}
	if err := masked.UnmaskSecrets(doc); err != nil || !strings.Contains(string(masked.Bytes()), "private-realm-token") {
		t.Fatal("Realm token retention failed", err)
	}
}

func TestPluginNestedSecretsAcrossDocuments(t *testing.T) {
	for _, tc := range []struct{ kind, input string }{
		{DocProfile, `schema-version: 1
outbounds: [{id: node, type: shadowsocks, plugin: {password: plugin-private, headers: [{name: Authorization, value: header-private}], tls: {certificate: certificate-private, private-key: key-private}}}]
`},
		{DocSources, `schema-version: 1
sources: [{id: source, outbounds: [{id: node, type: shadowsocks, plugin: {password: plugin-private, headers: [{name: Authorization, value: header-private}], tls: {certificate: certificate-private, private-key: key-private}}}]}]
`},
		{DocOverlay, `schema-version: 1
patches: [{op: set, path: /outbounds/node/plugin, value: {password: plugin-private, headers: [{name: Authorization, value: header-private}], tls: {certificate: certificate-private, private-key: key-private}}}]
`},
	} {
		original, ds := LoadDoc(tc.kind, []byte(tc.input))
		if ds.HasErrors() {
			t.Fatal(ds)
		}
		masked, _ := LoadDoc(tc.kind, []byte(tc.input))
		if n := masked.MaskSecrets(); n != 4 {
			t.Fatal("plugin secrets not masked", tc.kind, n)
		}
		if strings.Contains(string(masked.Bytes()), "-private") {
			t.Fatal("plugin credential leaked", tc.kind)
		}
		if err := masked.UnmaskSecrets(original); err != nil || !strings.Contains(string(masked.Bytes()), "plugin-private") {
			t.Fatal("masked plugin values were not retained", err)
		}
	}
}

func TestLegacyPluginCredentialMaskingAndRetention(t *testing.T) {
	for name, data := range map[string]string{
		DocProfile: "outbounds: [{id: a, type: shadowsocks, plugin: {type: jls, username: private-user, password: private-password}},{id: b, type: shadowsocks, plugin: {type: kcptun, kcp: {key: private-key}}}]",
		DocSources: "sources: [{id: remote, outbounds: [{id: a, type: shadowsocks, plugin: {type: jls, username: private-user, password: private-password}},{id: b, type: shadowsocks, plugin: {type: kcptun, kcp: {key: private-key}}}]}]",
		DocOverlay: "patches: [{op: set, path: /outbounds/a/plugin/username, value: private-user},{op: set, path: /outbounds/a/plugin/password, value: private-password},{op: set, path: /outbounds/b/plugin/kcp/key, value: private-key}]",
	} {
		base, ds := LoadDoc(name, []byte(data))
		if ds.HasErrors() {
			t.Fatal(ds)
		}
		masked, _ := LoadDoc(name, []byte(data))
		if masked.MaskSecrets() != 3 || strings.Contains(string(masked.Bytes()), "private-") {
			t.Fatal("credential leaked", name)
		}
		if err := masked.UnmaskSecrets(base); err != nil {
			t.Fatal(err)
		}
		for _, secret := range []string{"private-user", "private-password", "private-key"} {
			if !strings.Contains(string(masked.Bytes()), secret) {
				t.Fatal("masked credential was lost", name, secret)
			}
		}
	}
}

func TestResourceDownloadURLsMaskAndRestore(t *testing.T) {
	original := "schema-version: 1\ngeodata: [{id: geosite, format: dat, hash: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa, download: {url: 'https://cdn.test/site?token=private-resource-token', interval: 86400, automatic: true}}]\n"
	base, ds := LoadDoc(DocProfile, []byte(original))
	if ds.HasErrors() {
		t.Fatal(ds)
	}
	masked, _ := LoadDoc(DocProfile, []byte(original))
	if masked.MaskSecrets() == 0 || strings.Contains(string(masked.Bytes()), "private-resource-token") {
		t.Fatal("resource URL credential leaked")
	}
	if err := masked.UnmaskSecrets(base); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(masked.Bytes()), "private-resource-token") {
		t.Fatal("masked download URL not restored")
	}
}
