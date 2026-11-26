package compile

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/MimoProxy/reka/internal/config/model"
)

const anyTLSProfile = `schema-version: 1
outbounds:
  - id: node
    type: anytls
    server: proxy.test
    port: 443
    password: test-password
    tls: {}
`

func TestAnyTLSCompileRejectsInvalidOptions(t *testing.T) {
	replace := func(old, new string) string { return strings.Replace(anyTLSProfile, old, new, 1) }
	protocol := func(option string) string { return anyTLSProfile + "    protocol: {" + option + "}\n" }
	for _, tc := range []struct {
		name, input, path, message string
	}{
		{"missing password", replace("    password: test-password\n", ""), "password", "password is required"},
		{"missing TLS", replace("    tls: {}\n", ""), "tls", "this protocol requires TLS"},
		{"REALITY", replace("tls: {}", "tls: {reality: {}}"), "tls/reality", "only supported on vless"},
		{"multiplex", anyTLSProfile + "    multiplex: {enabled: true}\n", "multiplex", "does not accept multiplex"},
		{"disabled multiplex", anyTLSProfile + "    multiplex: {enabled: false}\n", "multiplex", "does not accept multiplex"},
		{"transport", anyTLSProfile + "    transport: {type: ws}\n", "transport", "does not apply"},
		{"TCP Fast Open", anyTLSProfile + "    dialer: {tfo: true}\n", "dialer/tfo", "TCP Fast Open"},
		{"negative check interval", protocol("idle-session-check-interval-seconds: -1"), "protocol/idle-session-check-interval-seconds", "between 0 and 86400"},
		{"long check interval", protocol("idle-session-check-interval-seconds: 86401"), "protocol/idle-session-check-interval-seconds", "between 0 and 86400"},
		{"negative timeout", protocol("idle-session-timeout-seconds: -1"), "protocol/idle-session-timeout-seconds", "between 0 and 86400"},
		{"long timeout", protocol("idle-session-timeout-seconds: 86401"), "protocol/idle-session-timeout-seconds", "between 0 and 86400"},
		{"negative idle sessions", protocol("min-idle-session: -1"), "protocol/min-idle-session", "between 0 and 64"},
		{"too many idle sessions", protocol("min-idle-session: 65"), "protocol/min-idle-session", "between 0 and 64"},
		{"fractional timeout", protocol("idle-session-timeout-seconds: 6.5"), "protocol/idle-session-timeout-seconds", "expected an integer"},
		{"foreign protocol field", protocol("version: 5"), "protocol/version", "option does not apply"},
		{"unknown protocol field", protocol("unknown: true"), "protocol/unknown", "unknown field"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			eff, ds := Compile([]byte(tc.input), nil, Options{})
			if eff != nil {
				t.Fatal("invalid configuration compiled")
			}
			for _, d := range ds.Errors() {
				if d.Path == "/outbounds/node/"+tc.path && strings.Contains(d.Message, tc.message) {
					return
				}
			}
			t.Fatalf("missing diagnostic for %s containing %q: %v", tc.path, tc.message, ds)
		})
	}
}

func TestAnyTLSCompileOptionsAndPassword(t *testing.T) {
	base, ds := Compile([]byte(anyTLSProfile), nil, Options{})
	if ds.HasErrors() {
		t.Fatal(ds)
	}
	node, _ := base.Outbound("node")
	if !node.UDP || node.TLS == nil || node.TLS.ServerName != "proxy.test" {
		t.Fatal("unexpected UDP or TLS defaults")
	}

	inline, ds := model.LoadDoc(model.DocProfile, []byte(anyTLSProfile))
	if ds.HasErrors() || inline.MaskSecrets() != 1 || inline.Get("/outbounds/node/password").Value != model.Mask {
		t.Fatal("inline password was not masked", ds)
	}

	const ref = "outbounds/node/password"
	input := strings.Replace(anyTLSProfile, "password: test-password", "password: secret://"+ref, 1)
	input = strings.Replace(input, "tls: {}", "tls: {server-name: handshake.test, fingerprint: chrome, alpn: [h2], insecure: true, carrier: {type: shadow-tls, version: 3, password: carrier-password}}", 1)
	input += `    udp: false
    dialer: {tfo: false}
    protocol:
      idle-session-check-interval-seconds: 86400
      idle-session-timeout-seconds: 0
      min-idle-session: 64
      client-metadata: Test Client
`
	secrets := store(t)
	build := func(password string) Outbound {
		t.Helper()
		if err := secrets.Set(ref, password); err != nil {
			t.Fatal(err)
		}
		eff, ds := Compile([]byte(input), nil, Options{Secrets: secrets})
		if ds.HasErrors() {
			t.Fatal(ds)
		}
		node, _ := eff.Outbound("node")
		if node.Password != password {
			t.Fatal("password reference was not resolved")
		}
		data, err := json.Marshal(node)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(data), password) {
			t.Fatal("resolved password leaked in JSON")
		}
		return node
	}
	configured := build("resolved-password")
	if configured.UDP || configured.TLS == nil || configured.TLS.ServerName != "handshake.test" || configured.TLS.Fingerprint != "chrome" || configured.TLS.Carrier == nil || configured.TLS.Carrier.Type != "shadow-tls" {
		t.Fatal("UDP or TLS options were lost")
	}
	if p := configured.Protocol; p == nil || p.IdleSessionCheckIntervalSeconds != 86400 || p.IdleSessionTimeoutSeconds != 0 || p.MinIdleSession != 64 || p.ClientMetadata != "Test Client" {
		t.Fatal("AnyTLS protocol options were lost")
	}
	if updated := build("rotated-password"); configured.Fingerprint == updated.Fingerprint {
		t.Fatal("password rotation was not fingerprinted")
	}
}
