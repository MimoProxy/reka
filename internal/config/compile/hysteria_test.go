package compile

import (
	"bytes"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/MimoProxy/reka/internal/config/model"
)

const hysteriaProfile = `schema-version: 1
outbounds:
  - id: node
    type: hysteria
    server: proxy.test
    port: 443
    tls: {}
    protocol:
      up-bps: 16384
      down-mbps: 1
`

func TestHysteriaCompileOptions(t *testing.T) {
	build := func(input string) Outbound {
		t.Helper()
		eff, ds := Compile([]byte(input), nil, Options{})
		if ds.HasErrors() {
			t.Fatal(ds)
		}
		node, _ := eff.Outbound("node")
		return node
	}
	node := build(hysteriaProfile)
	if !node.UDP || node.Password != "" || node.TLS == nil || node.TLS.ServerName != "proxy.test" ||
		len(node.TLS.ALPN) != 0 || node.Protocol.HopInterval != 0 || node.Protocol.StreamReceiveWindow != 0 ||
		node.Protocol.ConnectionReceiveWindow != 0 || node.Protocol.DisableMTUDiscovery {
		t.Fatal("unexpected Hysteria defaults")
	}

	input := strings.Replace(hysteriaProfile, "port: 443", "port: 0\n    udp: false\n    dialer: {ip-version: ipv4}", 1)
	input += `      auth-base64: /wAB
      stream-receive-window: 2097152
      connection-receive-window: 12582912
      disable-mtu-discovery: true
      server-ports: ["443:445", "8443:8443"]
      hop-interval-seconds: 5
      obfs: {type: xplus, password: obfs-secret}
`
	node = build(input)
	p := node.Protocol
	if node.Port != 0 || node.UDP || node.Dialer == nil || node.Dialer.IPVersion != "ipv4" ||
		p.AuthBase64 != "/wAB" || p.UpBPS == nil || *p.UpBPS != 16384 || p.DownMbps != 1 ||
		p.StreamReceiveWindow != 2097152 || p.ConnectionReceiveWindow != 12582912 || !p.DisableMTUDiscovery ||
		!slices.Equal(p.ServerPorts, []string{"443:445", "8443:8443"}) || p.HopInterval != 5 ||
		p.Obfs == nil || p.Obfs.Type != "xplus" || p.Obfs.Password != "obfs-secret" {
		t.Fatal("configured Hysteria options were lost")
	}
}

func TestHysteriaCompileValidation(t *testing.T) {
	replace := func(old, new string) string { return strings.Replace(hysteriaProfile, old, new, 1) }
	option := func(value string) string { return hysteriaProfile + "      " + value + "\n" }
	top := func(value string) string { return hysteriaProfile + "    " + value + "\n" }
	for _, tc := range []struct{ name, input, path, message string }{
		{"missing TLS", replace("    tls: {}\n", ""), "tls", "requires TLS"},
		{"uTLS", replace("tls: {}", "tls: {fingerprint: chrome}"), "tls/fingerprint", "QUIC"},
		{"REALITY", replace("tls: {}", "tls: {reality: {}}"), "tls/reality", "vless"},
		{"TLS carrier", replace("tls: {}", "tls: {carrier: {type: shadow-tls, password: hide}}"), "tls/carrier/type", "security carriers"},
		{"multiplex", top("multiplex: {enabled: true}"), "multiplex", "does not accept"},
		{"disabled multiplex", top("multiplex: {enabled: false}"), "multiplex", "does not accept"},
		{"transport", top("transport: {type: ws}"), "transport", "does not apply"},
		{"no port", replace("port: 443", "port: 0"), "port", "port must"},
		{"missing rates", strings.Split(hysteriaProfile, "    protocol:")[0], "protocol", "upload and download"},
		{"missing up", replace("      up-bps: 16384\n", ""), "protocol/up-bps", "requires"},
		{"missing down", replace("      down-mbps: 1\n", ""), "protocol/down-bps", "requires"},
		{"zero rate", replace("up-bps: 16384", "up-bps: 0"), "protocol/up-bps", "16384"},
		{"slow download", replace("down-mbps: 1", "down-bps: 16383"), "protocol/down-bps", "16384"},
		{"mixed rates", option("up-mbps: 1"), "protocol", "choose bytes/s"},
		{"overflowing Mbps", replace("down-mbps: 1", "down-mbps: 9223372036854775807"), "protocol", "overflows"},
		{"overflowing bytes", replace("up-bps: 16384", "up-bps: 18446744073709551616"), "protocol/up-bps", ""},
		{"conflicting auth", option("auth-base64: YQ==\n    password: text"), "protocol/auth-base64", "mutually exclusive"},
		{"conflicting empty password", option("auth-base64: YQ==\n    password: ''"), "protocol/auth-base64", "mutually exclusive"},
		{"malformed auth", option("auth-base64: _w=="), "protocol/auth-base64", "standard base64"},
		{"wrong obfs", option("obfs: {type: salamander, password: hide}"), "protocol/obfs/type", "xplus"},
		{"missing obfs password", option("obfs: {type: xplus}"), "protocol/obfs/password", "password"},
		{"obfs packet size", option("obfs: {type: xplus, password: hide, min-packet-size: 0}"), "protocol/obfs/min-packet-size", "XPlus"},
		{"obfs host", option("obfs: {type: xplus, password: hide, host: example.org}"), "protocol/obfs/host", "XPlus"},
		{"short hop", option("hop-interval-seconds: 4"), "protocol/hop-interval-seconds", "5 seconds"},
		{"zero hop", option("hop-interval-seconds: 0"), "protocol/hop-interval-seconds", "5 seconds"},
		{"hop range", option("hop-interval-max-seconds: 30"), "protocol/hop-interval-max-seconds", "does not apply"},
		{"bad ports", option("server-ports: ['443:0']"), "protocol/server-ports", "port range"},
		{"realm", option("realm: {enabled: false}"), "protocol/realm", "does not apply"},
		{"zero stream window", option("stream-receive-window: 0"), "protocol/stream-receive-window", "positive"},
		{"negative stream window", option("stream-receive-window: -1"), "protocol/stream-receive-window", "unsigned"},
		{"zero connection window", option("connection-receive-window: 0"), "protocol/connection-receive-window", "positive"},
		{"noninteger window", option("connection-receive-window: 1.5"), "protocol/connection-receive-window", "unsigned"},
		{"nonboolean MTU", option("disable-mtu-discovery: 1"), "protocol/disable-mtu-discovery", "true or false"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			eff, ds := Compile([]byte(tc.input), nil, Options{})
			if eff != nil || !slices.ContainsFunc(ds.Errors(), func(d model.Diagnostic) bool {
				return d.Path == "/outbounds/node/"+tc.path && strings.Contains(d.Message, tc.message)
			}) {
				t.Fatalf("expected an error at %s containing %q, got %v", tc.path, tc.message, ds)
			}
		})
	}
}

func TestHysteriaSecretReferences(t *testing.T) {
	secrets := store(t)
	set := func(name, value string) {
		t.Helper()
		if err := secrets.Set("hysteria/"+name, value); err != nil {
			t.Fatal(err)
		}
	}
	build := func(auth string) Outbound {
		t.Helper()
		input := hysteriaProfile + "      obfs: {type: xplus, password: secret://hysteria/obfs}\n" + auth
		eff, ds := Compile([]byte(input), nil, Options{Secrets: secrets})
		if ds.HasErrors() {
			t.Fatal(ds)
		}
		node, _ := eff.Outbound("node")
		data, err := json.Marshal(node)
		if err != nil {
			t.Fatal(err)
		}
		for _, value := range []string{node.Password, node.Protocol.AuthBase64, node.Protocol.Obfs.Password} {
			if value != "" && bytes.Contains(data, []byte(value)) {
				t.Fatal("effective outbound exposed a credential")
			}
		}
		return node
	}
	set("password", "text-secret")
	set("auth", "/wAB")
	set("obfs", "obfs-secret")
	const encoded = "      auth-base64: secret://hysteria/auth\n"
	node := build(encoded)
	if node.Protocol.AuthBase64 != "/wAB" || node.Protocol.Obfs.Password != "obfs-secret" {
		t.Fatal("encoded authentication or obfs password was not resolved")
	}
	set("auth", "AQID")
	rotated := build(encoded)
	if rotated.Fingerprint == node.Fingerprint {
		t.Fatal("auth rotation must change the outbound fingerprint")
	}
	set("obfs", "changed-password")
	if build(encoded).Fingerprint == rotated.Fingerprint {
		t.Fatal("obfs rotation must change the outbound fingerprint")
	}
	if plain := build("    password: secret://hysteria/password\n"); plain.Password != "text-secret" || plain.Protocol.AuthBase64 != "" {
		t.Fatal("authentication string was not resolved")
	}
}

func TestHysteriaCredentialsMaskAndRestore(t *testing.T) {
	const node = "{id: node, type: hysteria, protocol: {auth-base64: /wAB, obfs: {type: xplus, password: obfs-secret}}}"
	for kind, input := range map[string]string{
		model.DocProfile: "outbounds: [" + node + "]",
		model.DocSources: "sources: [{id: feed, outbounds: [" + node + "]}]",
		model.DocOverlay: "patches: [{op: set, path: /outbounds/node/protocol/auth-base64, value: /wAB}, {op: set, path: /outbounds/node/protocol/obfs/password, value: obfs-secret}]",
	} {
		original, ds := model.LoadDoc(kind, []byte(input))
		if ds.HasErrors() {
			t.Fatal(ds)
		}
		masked, _ := model.LoadDoc(kind, []byte(input))
		if masked.MaskSecrets() != 2 || bytes.Contains(masked.Bytes(), []byte("/wAB")) || bytes.Contains(masked.Bytes(), []byte("obfs-secret")) {
			t.Fatal("incorrect credential masking", kind)
		}
		if err := masked.UnmaskSecrets(original); err != nil || !bytes.Equal(masked.Bytes(), original.Bytes()) {
			t.Fatal("credentials were not restored", kind, err)
		}
	}
}
