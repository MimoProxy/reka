package compile

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/MimoProxy/reka/internal/config/model"
)

const ssrProfile = `schema-version: 1
outbounds:
  - id: proxy
    type: ssr
    server: proxy.test
    port: 8388
    method: AES-256-CFB
    password: test-password
`

func TestSSRConfiguration(t *testing.T) {
	e, ds := Compile([]byte(ssrProfile), nil, Options{})
	if ds.HasErrors() {
		t.Fatal(ds)
	}
	o := e.Outbounds[0]
	if o.Method != "aes-256-cfb" || !o.UDP || o.Protocol.SSRProtocol != "origin" || o.Protocol.Obfs.Type != "plain" {
		t.Fatal("unexpected SSR defaults")
	}
	input := ssrProfile + `    udp: false
    dialer: {proxy: direct}
    protocol: {obfs: {type: tls1.2_ticket_auth, param: cdn.test}, protocol: auth_aes128_md5, protocol-param: '64:key'}
`
	for _, method := range []string{"none", "dummy", "chacha20-ietf"} {
		e, ds = Compile([]byte(strings.Replace(input, "AES-256-CFB", method, 1)), nil, Options{})
		if ds.HasErrors() {
			t.Fatal(ds)
		}
		o = e.Outbounds[0]
		p := o.Protocol
		if o.Method != method || o.Password != "test-password" || o.UDP || o.Dialer.Proxy != "direct" ||
			p.Obfs.Type != "tls1.2_ticket_auth" || p.Obfs.Param != "cdn.test" || p.SSRProtocol != "auth_aes128_md5" || p.SSRProtocolParam != "64:key" {
			t.Fatal("configured SSR options did not survive compilation")
		}
	}
}

func TestSSRSecretReferences(t *testing.T) {
	const password = "test-password"
	const param = "64:private-param"
	input := strings.Replace(ssrProfile, password, "secret://ssr/password", 1) + "    protocol: {protocol: auth_chain_a, protocol-param: secret://ssr/param}\n"
	secrets := store(t)
	compile := func(password, param string) Outbound {
		t.Helper()
		for name, value := range map[string]string{"ssr/password": password, "ssr/param": param} {
			if err := secrets.Set(name, value); err != nil {
				t.Fatal(err)
			}
		}
		e, ds := Compile([]byte(input), nil, Options{Secrets: secrets})
		if ds.HasErrors() {
			t.Fatal(ds)
		}
		o := e.Outbounds[0]
		if o.Password != password || o.Protocol.SSRProtocolParam != param {
			t.Fatal("SSR secret references were not resolved")
		}
		data, err := json.Marshal(o)
		if err != nil || strings.Contains(string(data), password) || strings.Contains(string(data), param) {
			t.Fatal("effective SSR outbound exposed a credential", err)
		}
		return o
	}
	base := compile(password, param)
	if compile(password, "64:rotated-param").Fingerprint == base.Fingerprint || compile("rotated-password", param).Fingerprint == base.Fingerprint {
		t.Fatal("rotating an SSR credential kept the outbound fingerprint")
	}
}

func TestSSRValidation(t *testing.T) {
	replace := func(old, new string) string { return strings.Replace(ssrProfile, old, new, 1) }
	field := func(s string) string { return ssrProfile + "    " + s + "\n" }
	protocol := func(s string) string { return field("protocol: {" + s + "}") }
	for _, tc := range []struct{ name, input, path, message string }{
		{"missing password with dummy", strings.Replace(replace("    password: test-password\n", ""), "AES-256-CFB", "dummy", 1), "password", "required"},
		{"missing method", replace("    method: AES-256-CFB\n", ""), "method", "aes-256-cfb"},
		{"unknown cipher", replace("AES-256-CFB", "blowfish"), "method", "aes-256-cfb"},
		{"AEAD", replace("AES-256-CFB", "aes-256-gcm"), "method", "stream cipher"},
		{"invalid protocol", protocol("protocol: unknown"), "protocol/protocol", "origin"},
		{"empty protocol", protocol("protocol: ''"), "protocol/protocol", "origin"},
		{"missing obfs type", protocol("obfs: {param: cdn.test}"), "protocol/obfs/type", "plain"},
		{"invalid obfs type", protocol("obfs: {type: unknown}"), "protocol/obfs/type", "plain"},
		{"obfs host", protocol("obfs: {type: plain, host: ''}"), "protocol/obfs/host", "does not apply"},
		{"obfs password", protocol("obfs: {type: plain, password: ''}"), "protocol/obfs/password", "does not apply"},
		{"obfs size", protocol("obfs: {type: plain, min-packet-size: 0}"), "protocol/obfs/min-packet-size", "does not apply"},
		{"foreign protocol option", protocol("version: 5"), "protocol/version", "does not apply"},
		{"TLS", field("tls: {}"), "tls", "SSR does not accept"},
		{"transport", field("transport: {type: ws}"), "transport", "SSR does not accept"},
		{"multiplex", field("multiplex: {enabled: false}"), "multiplex", "SSR does not accept"},
		{"plugin", field("plugin: {type: obfs}"), "plugin", "does not apply"},
		{"realm", protocol("realm: {}"), "protocol/realm", "does not apply"},
		{"TFO", field("dialer: {tfo: true}"), "dialer/tfo", "TCP Fast Open"},
		{"missing secret store", protocol("protocol-param: secret://ssr/param"), "protocol/protocol-param", "no secret store"},
		{"protocol on other outbound", replace("type: ssr", "type: snell") + "    protocol: {version: 5, protocol: origin}\n", "protocol/protocol", "does not apply"},
		{"protocol param on other outbound", replace("type: ssr", "type: snell") + "    protocol: {version: 5, protocol-param: ''}\n", "protocol/protocol-param", "does not apply"},
		{"obfs param on other outbound", replace("type: ssr", "type: snell") + "    protocol: {version: 5, obfs: {type: http, param: ''}}\n", "protocol/obfs/param", "does not apply"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, ds := Compile([]byte(tc.input), nil, Options{})
			if e != nil || !slices.ContainsFunc(ds.Errors(), func(d model.Diagnostic) bool {
				return d.Path == "/outbounds/proxy/"+tc.path && strings.Contains(d.Message, tc.message)
			}) {
				t.Fatalf("expected %q at %s, got %v", tc.message, tc.path, ds)
			}
		})
	}
}
