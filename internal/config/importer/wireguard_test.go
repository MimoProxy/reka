package importer

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/MimoProxy/reka/internal/config/model"
)

func wireGuardTestKey(b byte) string {
	return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{b}, 32))
}

func TestClashWireGuard(t *testing.T) {
	private, public, shared := wireGuardTestKey(1), wireGuardTestKey(2), wireGuardTestKey(3)
	const input = `proxies:
 - name: tunnel
   type: wireguard
   server: peer.example
   port: "51820"
   ip: 192.0.2.5
   ipv6: 2001:db8::5/64
   private-key: %s
   public-key: %s
   pre-shared-key: %s
   allowed-ips: [0.0.0.0/0, "::/0"]
   reserved: %s
   mtu: 1408
   persistent-keepalive: 25
   udp: true
`
	for _, reserved := range []string{"[1, 2, 255]", "AQL/", "'1, 2, 255'"} {
		r := Import(request(fmt.Sprintf(input, private, public, shared, reserved)))
		if !r.Report.CanApply || r.Report.Partial {
			t.Fatal(r.Report)
		}
		ob := compileImport(t, r).Outbounds[0]
		if ob.Type != model.OutboundWireGuard || ob.Server != "peer.example" || ob.Port != 51820 || !ob.UDP {
			t.Fatal("WireGuard endpoint or UDP mapping lost")
		}
		p := ob.Protocol
		if p.PrivateKey != private || p.PublicKey != public || p.PreSharedKey != shared || p.MTU != 1408 || p.PersistentKeepalive != 25 {
			t.Fatal("WireGuard protocol options changed during import")
		}
		if !slices.Equal(p.Reserved, []byte{1, 2, 255}) || !slices.Equal(p.Address, []string{"192.0.2.5/32", "2001:db8::5/64"}) || !slices.Equal(p.AllowedIPs, []string{"0.0.0.0/0", "::/0"}) {
			t.Fatal("WireGuard reserved bytes or prefixes changed during import")
		}
		masked := r.Preview(false).Sources
		if strings.Contains(masked, private) || strings.Contains(masked, shared) || !strings.Contains(masked, public) {
			t.Fatal("WireGuard key masking mismatch")
		}
	}
}

func TestClashWireGuardSinglePeer(t *testing.T) {
	key := wireGuardTestKey(1)
	input := fmt.Sprintf(`proxies:
 - name: tunnel
   type: wireguard
   ipv6: 2001:db8::5
   private-key: %s
   reserved: [2, 3, 4]
   persistent-keepalive: 10
   peers:
    - server: peer.example
      port: 443
      public-key: %s
      pre-shared-key: %s
      allowed-ips: ["2001:db8::/64"]
`, key, key, key)
	for _, tc := range []struct {
		extra string
		want  []byte
	}{
		{"", []byte{2, 3, 4}},
		{"      reserved: AQID\n", []byte{1, 2, 3}},
	} {
		r := Import(request(input + tc.extra))
		if !r.Report.CanApply {
			t.Fatal(r.Report)
		}
		ob := compileImport(t, r).Outbounds[0]
		p := ob.Protocol
		if ob.Server != "peer.example" || ob.Port != 443 || ob.UDP || p.PersistentKeepalive != 10 || p.PublicKey != key || p.PreSharedKey != key || !slices.Equal(p.Address, []string{"2001:db8::5/128"}) || !slices.Equal(p.AllowedIPs, []string{"2001:db8::/64"}) || !slices.Equal(p.Reserved, tc.want) {
			t.Fatal("single-peer mapping did not preserve the tunnel settings")
		}
	}
}

func TestClashWireGuardSkippedAndIgnoredOptions(t *testing.T) {
	input := fmt.Sprintf(`proxies:
 - {name: fallback, type: direct}
 - name: tunnel
   type: wireguard
   server: peer.example
   port: 51820
   ip: 192.0.2.5/32
   private-key: %s
   public-key: %s
`, wireGuardTestKey(1), wireGuardTestKey(2))
	for _, tc := range []struct{ option, path string }{
		{"peers: [{}, {}]", "peers"}, {"peers: [{}]", "peers/#0/port"},
		{"peers: invalid", "peers"}, {"peers: [false]", "peers"},
		{"peers: [{unknown: true}]", "peers/#0/unknown"},
		{"amnezia-wg-option: {}", "amnezia-wg-option"}, {"amnezia-wg-option: null", "amnezia-wg-option"},
		{"reserved: '1,2,256'", "reserved"}, {"reserved: [1, 2]", "reserved"},
		{"reserved: '!'", "reserved"}, {"reserved: [1, -1, 2]", "reserved"},
		{"ipv6: 192.0.2.5/32", "ipv6"}, {"dialer-proxy: DIRECT", "dialer-proxy"}, {"smux: {enabled: false}", "smux"},
	} {
		req := request(input + "   " + tc.option + "\n")
		req.AllowPartial = true
		r := Import(req)
		if !r.Report.CanApply || !r.Report.Partial || r.Report.Nodes.Unavailable != 1 || len(snapshot(t, r).Outbounds) != 1 {
			t.Fatal(tc.option, r.Report)
		}
		if !slices.ContainsFunc(r.Report.Diagnostics, func(d model.Diagnostic) bool {
			return d.Severity == model.SeverityWarning && d.Path == "/proxies/#1/"+tc.path
		}) {
			t.Fatal("missing field warning", tc.option, r.Report.Diagnostics)
		}
	}
	r := Import(request(input + "   remote-dns-resolve: true\n   dns: [192.0.2.53]\n   refresh-server-ip-interval: 60\n   workers: 2\n   ip-stack: {mode: gvisor}\n"))
	if !r.Report.CanApply || r.Report.Partial || r.Report.Nodes.Imported != 2 {
		t.Fatal(r.Report)
	}
	p := compileImport(t, r).Outbounds[1].Protocol
	if p == nil || !slices.Equal(p.AllowedIPs, []string{"0.0.0.0/0", "::/0"}) {
		t.Fatal("default peer routes were lost when importing the source")
	}
	for _, field := range []string{"remote-dns-resolve", "dns", "refresh-server-ip-interval", "workers", "ip-stack"} {
		path := "/proxies/#1/" + field
		if !slices.Contains(r.Report.Ignored, path) || !slices.ContainsFunc(r.Report.Diagnostics, func(d model.Diagnostic) bool {
			return d.Path == path && d.Severity == model.SeverityWarning && d.Code == "import.ignored-field"
		}) {
			t.Fatal("missing ignored field warning", field, r.Report)
		}
	}
}
