package compile

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/MimoProxy/reka/internal/config/model"
	"github.com/enfein/mieru/v3/apis/trafficpattern"
	"github.com/enfein/mieru/v3/pkg/appctl/appctlpb"
	"google.golang.org/protobuf/proto"
)

const mieruProfile = `schema-version: 1
outbounds:
  - id: node
    type: mieru
    server: proxy.test
    port: 443
    username: test-user
    password: test-password
    protocol:
      transport: TCP
`

func TestMieruCompileOptions(t *testing.T) {
	build := func(input string) Outbound {
		t.Helper()
		eff, ds := Compile([]byte(input), nil, Options{})
		if ds.HasErrors() {
			t.Fatal(ds)
		}
		node, _ := eff.Outbound("node")
		return node
	}
	node := build(mieruProfile)
	if !node.UDP || node.Server != "proxy.test" || node.Port != 443 || node.Protocol.Transport != "TCP" ||
		node.Protocol.Multiplexing != "" || node.Protocol.HandshakeMode != "" || node.Protocol.TrafficPattern != "" {
		t.Fatal("unexpected Mieru defaults")
	}
	pattern := trafficpattern.Encode(&appctlpb.TrafficPattern{Seed: proto.Int32(123)})
	for _, ports := range []string{"1-65535", "1:65535", "65535-65535"} {
		input := strings.Replace(mieruProfile, "port: 443", "udp: false\n    dialer: {interface-name: en0, ip-version: ipv4}", 1)
		input = strings.Replace(input, "transport: TCP", "transport: UDP", 1)
		input += "      multiplexing: MULTIPLEXING_HIGH\n      handshake-mode: HANDSHAKE_NO_WAIT\n      traffic-pattern: " + pattern + "\n      server-ports: ['" + ports + "']\n"
		node := build(input)
		p := node.Protocol
		if node.Port != 0 || node.UDP || p.Transport != "UDP" ||
			p.Multiplexing != "MULTIPLEXING_HIGH" || p.HandshakeMode != "HANDSHAKE_NO_WAIT" || p.TrafficPattern != pattern ||
			!slices.Equal(p.ServerPorts, []string{strings.Replace(ports, ":", "-", 1)}) ||
			node.Dialer == nil || node.Dialer.Interface != "en0" || node.Dialer.IPVersion != "ipv4" {
			t.Fatal("configured Mieru options were lost")
		}
	}
}

func TestMieruCompileValidation(t *testing.T) {
	change := func(old, new string) string { return strings.Replace(mieruProfile, old, new, 1) }
	protocol := func(option string) string { return mieruProfile + "      " + option + "\n" }
	ports := func(list string) string {
		return change("    port: 443\n", "") + "      server-ports: " + list + "\n"
	}
	invalidPattern := trafficpattern.Encode(&appctlpb.TrafficPattern{
		TcpFragment: &appctlpb.TCPFragment{MaxSleepMs: proto.Int32(101)},
	})
	for _, tc := range []struct{ name, input, field, message string }{
		{"missing server", change("    server: proxy.test\n", ""), "server", "required"},
		{"missing username", change("    username: test-user\n", ""), "username", "required"},
		{"missing password", change("    password: test-password\n", ""), "password", "required"},
		{"long username", change("test-user", strings.Repeat("a", 65)), "username", "64 bytes"},
		{"long password", change("test-password", strings.Repeat("a", 65)), "password", "64 bytes"},
		{"no protocol", strings.Split(mieruProfile, "    protocol:")[0], "protocol/transport", "TCP or UDP"},
		{"invalid transport", change("transport: TCP", "transport: tcp"), "protocol/transport", "TCP or UDP"},
		{"missing port", change("    port: 443\n", ""), "port", "port or protocol/server-ports"},
		{"zero port", change("port: 443", "port: 0"), "port", "between 1 and 65535"},
		{"high port", change("port: 443", "port: 65536"), "port", "between 1 and 65535"},
		{"conflicting ports", protocol("server-ports: ['2000-2010']"), "protocol/server-ports", "mutually exclusive"},
		{"explicit zero and range", strings.Replace(protocol("server-ports: ['1-2']"), "port: 443", "port: 0", 1), "protocol/server-ports", "mutually exclusive"},
		{"empty ranges", ports("[]"), "protocol/server-ports", "exactly one"},
		{"multiple ranges", ports("['1-2', '5-6']"), "protocol/server-ports", "exactly one"},
		{"missing bound", ports("['2000']"), "protocol/server-ports", "start and an end"},
		{"zero bound", ports("['0-2']"), "protocol/server-ports", "between 1 and 65535"},
		{"high bound", ports("['1-65536']"), "protocol/server-ports", "between 1 and 65535"},
		{"malformed bound", ports("['1-2x']"), "protocol/server-ports", "integers"},
		{"reversed range", ports("['2-1']"), "protocol/server-ports", "less than or equal"},
		{"multiplexing level", protocol("multiplexing: HIGH"), "protocol/multiplexing", "multiplexing level"},
		{"handshake mode", protocol("handshake-mode: NO_WAIT"), "protocol/handshake-mode", "handshake mode"},
		{"malformed pattern", protocol("traffic-pattern: '%%%%'"), "protocol/traffic-pattern", "decode"},
		{"invalid pattern", protocol("traffic-pattern: " + invalidPattern), "protocol/traffic-pattern", "maxSleepMs"},
		{"TLS", mieruProfile + "    tls: {}\n", "tls", "does not apply"},
		{"multiplex", mieruProfile + "    multiplex: {enabled: true}\n", "multiplex", "protocol/multiplexing"},
		{"disabled multiplex", mieruProfile + "    multiplex: {enabled: false}\n", "multiplex", "protocol/multiplexing"},
		{"generic transport", mieruProfile + "    transport: {type: ws}\n", "transport", "does not apply"},
		{"TCP Fast Open", mieruProfile + "    dialer: {tfo: true}\n", "dialer/tfo", "TCP Fast Open"},
		{"multipath TCP", mieruProfile + "    dialer: {mptcp: true}\n", "dialer/mptcp", "multipath TCP"},
		{"other protocol option", protocol("version: 5"), "protocol/version", "does not apply"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			eff, ds := Compile([]byte(tc.input), nil, Options{})
			if eff != nil || !slices.ContainsFunc(ds.Errors(), func(d model.Diagnostic) bool {
				return d.Path == "/outbounds/node/"+tc.field && strings.Contains(d.Message, tc.message)
			}) {
				t.Fatalf("expected error at %s containing %q, got %v", tc.field, tc.message, ds)
			}
		})
	}
}

func TestMieruSecretReferences(t *testing.T) {
	const ref = "outbounds/node/password"
	input := strings.Replace(mieruProfile, "test-password", "secret://"+ref, 1)
	doc, ds := model.LoadDoc(model.DocProfile, []byte(input))
	if ds.HasErrors() {
		t.Fatal(ds)
	}
	doc.MaskSecrets()
	if doc.Get("/outbounds/node/password").Value != "secret://"+ref {
		t.Fatal("password reference was masked")
	}
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
		data, err := json.Marshal(node)
		if err != nil || node.Password != password || strings.Contains(string(data), password) {
			t.Fatal("password resolution or redaction failed", err)
		}
		return node
	}
	if build("resolved-password").Fingerprint == build("rotated-password").Fingerprint {
		t.Fatal("password rotation must change the outbound fingerprint")
	}
}
