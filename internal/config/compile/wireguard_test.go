package compile

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/MimoProxy/reka/internal/config/model"
)

const wireGuardProfile = `schema-version: 1
outbounds:
  - id: tunnel
    type: wireguard
    server: peer.example
    port: 51820
    protocol:
      private-key: AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=
      public-key: Hx4dHBsaGRgXFhUUExIREA8ODQwLCgkIBwYFBAMCAQA=
      address: [192.0.2.1/24, '2001:db8::1/64']
`

func TestWireGuardConfig(t *testing.T) {
	e, ds := Compile([]byte(wireGuardProfile), nil, Options{})
	if ds.HasErrors() {
		t.Fatal(ds)
	}
	o := e.Outbounds[0]
	p := o.Protocol
	if o.Type != model.OutboundWireGuard || !o.UDP || o.Port != 51820 || o.Server != "peer.example" ||
		!slices.Equal(p.Address, []string{"192.0.2.1/24", "2001:db8::1/64"}) ||
		!slices.Equal(p.AllowedIPs, []string{"0.0.0.0/0", "::/0"}) ||
		p.PreSharedKey != "" || p.MTU != 0 || len(p.Reserved) != 0 || p.PersistentKeepalive != 0 {
		t.Fatal("unexpected WireGuard defaults")
	}
	input := strings.Replace(wireGuardProfile, "    protocol:", "    udp: false\n    protocol:", 1) +
		"      allowed-ips: ['2001:db8::/48']\n      mtu: 65535\n      reserved: [0, 128, 255]\n      persistent-keepalive: 65535\n"
	e, ds = Compile([]byte(input), nil, Options{})
	if ds.HasErrors() {
		t.Fatal(ds)
	}
	o = e.Outbounds[0]
	p = o.Protocol
	if o.UDP || !slices.Equal(p.AllowedIPs, []string{"2001:db8::/48"}) ||
		p.MTU != 65535 || !bytes.Equal(p.Reserved, []byte{0, 128, 255}) || p.PersistentKeepalive != 65535 {
		t.Fatal("WireGuard options did not survive compilation")
	}
}

func TestWireGuardKeyReferences(t *testing.T) {
	secrets := store(t)
	key := func(b byte) string { return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{b}, 32)) }
	storeKey := func(name string, b byte) {
		t.Helper()
		if err := secrets.Set(name, key(b)); err != nil {
			t.Fatal(err)
		}
	}
	input := strings.Replace(wireGuardProfile, "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=", "secret://wg/private", 1) +
		"      pre-shared-key: secret://wg/shared\n"
	compile := func() Outbound {
		t.Helper()
		e, ds := Compile([]byte(input), nil, Options{Secrets: secrets})
		if ds.HasErrors() {
			t.Fatal(ds)
		}
		return e.Outbounds[0]
	}
	storeKey("wg/private", 1)
	storeKey("wg/shared", 2)
	o := compile()
	if o.Protocol.PrivateKey != key(1) || o.Protocol.PreSharedKey != key(2) {
		t.Fatal("WireGuard secret references were not resolved")
	}
	report, err := json.Marshal(o)
	if err != nil || bytes.Contains(report, []byte(key(1))) || bytes.Contains(report, []byte(key(2))) {
		t.Fatal("effective WireGuard outbound exposed keys", err)
	}
	for i, name := range []string{"wg/private", "wg/shared"} {
		storeKey(name, byte(i+3))
		rotated := compile()
		if rotated.Fingerprint == o.Fingerprint {
			t.Fatalf("rotating %s kept the outbound fingerprint", name)
		}
		o = rotated
	}
}

func TestWireGuardValidation(t *testing.T) {
	const private = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
	const public = "Hx4dHBsaGRgXFhUUExIREA8ODQwLCgkIBwYFBAMCAQA="
	const addresses = "[192.0.2.1/24, '2001:db8::1/64']"
	for _, tc := range []struct {
		name, replace, with, path string
	}{
		{"missing server", "    server: peer.example\n", "", "server"},
		{"missing port", "    port: 51820\n", "", "port"},
		{"missing private key", "      private-key: " + private + "\n", "", "protocol/private-key"},
		{"missing public key", "      public-key: " + public + "\n", "", "protocol/public-key"},
		{"invalid private key", private, "invalid%", "protocol/private-key"},
		{"short private key", private, "AQID", "protocol/private-key"},
		{"invalid public key", public, "invalid%", "protocol/public-key"},
		{"short public key", public, "AQID", "protocol/public-key"},
		{"empty shared key", "", "pre-shared-key: ''", "protocol/pre-shared-key"},
		{"invalid shared key", "", "pre-shared-key: invalid%", "protocol/pre-shared-key"},
		{"short shared key", "", "pre-shared-key: AQID", "protocol/pre-shared-key"},
		{"missing address", "      address: " + addresses + "\n", "", "protocol/address"},
		{"empty address", addresses, "[]", "protocol/address"},
		{"invalid address", addresses, "['192.0.2.1/32', bad]", "protocol/address/#1"},
		{"duplicate address", addresses, "['192.0.2.1/32', '192.0.2.1/24']", "protocol/address/#1"},
		{"broadcast address", addresses, "['255.255.255.255/32']", "protocol/address/#0"},
		{"invalid allowed prefix", "", "allowed-ips: ['192.0.2.1/65']", "protocol/allowed-ips/#0"},
		{"empty allowed prefixes", "", "allowed-ips: []", "protocol/allowed-ips"},
		{"negative keepalive", "", "persistent-keepalive: -1", "protocol/persistent-keepalive"},
		{"large keepalive", "", "persistent-keepalive: 65536", "protocol/persistent-keepalive"},
		{"short reserved", "", "reserved: [1, 2]", "protocol/reserved"},
		{"long reserved", "", "reserved: [1, 2, 3, 4]", "protocol/reserved"},
		{"large reserved byte", "", "reserved: [0, 0, 256]", "protocol/reserved/#2"},
		{"negative reserved byte", "", "reserved: [-1, 0, 0]", "protocol/reserved/#0"},
		{"low MTU", "", "mtu: 575", "protocol/mtu"},
		{"high MTU", "", "mtu: 65536", "protocol/mtu"},
		{"foreign option", "", "security: auto", "protocol/security"},
		{"peer list", "", "peers: []", "protocol/peers"},
		{"TLS", "    protocol:", "    tls: {}\n    protocol:", "tls"},
		{"transport", "    protocol:", "    transport: {type: ws}\n    protocol:", "transport"},
		{"multiplex", "    protocol:", "    multiplex: {enabled: false}\n    protocol:", "multiplex"},
		{"detour", "    protocol:", "    dialer: {proxy: direct}\n    protocol:", "dialer/proxy"},
		{"key on other protocol", "type: wireguard", "type: vmess", "protocol/private-key"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := wireGuardProfile
			if tc.replace != "" {
				input = strings.Replace(input, tc.replace, tc.with, 1)
			} else {
				input += "      " + tc.with + "\n"
			}
			e, ds := Compile([]byte(input), nil, Options{})
			want := "/outbounds/tunnel/" + tc.path
			if e != nil || !slices.ContainsFunc(ds, func(d model.Diagnostic) bool {
				return d.Severity == model.SeverityError && d.Path == want
			}) {
				t.Fatalf("expected an error at %s, got %v", want, ds)
			}
		})
	}
}
