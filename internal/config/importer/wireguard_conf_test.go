package importer

import (
	"encoding/base64"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/MimoProxy/reka/internal/config/model"
)

func TestWireGuardConfHome(t *testing.T) {
	private, public, shared := wireGuardTestKey(1), wireGuardTestKey(2), wireGuardTestKey(3)
	data := fmt.Sprintf(`# name = Home WireGuard
; exported configuration

 [iNtErFaCe] # local tunnel
  pRiVaTeKeY = %s
  Address = 192.0.2.5/24, 2001:db8::5
  address = 192.0.2.6 # additional address
  MTU = 1408

 [pEeR]
  PublicKey = %s
  presharedKEY = %s
  AllowedIPs = 10.0.0.0/24, 2001:db8:1::/64
  ENDPOINT = home.example.com:51820 # hostname
  PersistentKeepalive = 25
`, private, public, shared)
	r := Import(request("\ufeff" + strings.ReplaceAll(data, "\n", "\r\n")))
	if !r.Report.CanApply || r.Report.Partial || r.Report.Format != "wireguard" || r.Report.Nodes != (Count{Total: 1, Imported: 1}) {
		t.Fatal(r.Report)
	}
	ob := compileImport(t, r).Outbounds[0]
	id := StableID("p", "Home WireGuard")
	if ob.ID != "airport/"+id || ob.Name != "Home WireGuard" || ob.Type != model.OutboundWireGuard || ob.Server != "home.example.com" || ob.Port != 51820 || !ob.UDP {
		t.Fatal("WireGuard identity, endpoint or UDP behavior changed")
	}
	p := ob.Protocol
	if p.PrivateKey != private || p.PublicKey != public || p.PreSharedKey != shared || p.MTU != 1408 || p.PersistentKeepalive != 25 {
		t.Fatal("WireGuard protocol options changed during import")
	}
	if !slices.Equal(p.Address, []string{"192.0.2.5/24", "2001:db8::5/128", "192.0.2.6/32"}) || !slices.Equal(p.AllowedIPs, []string{"10.0.0.0/24", "2001:db8:1::/64"}) {
		t.Fatal("WireGuard addresses or allowed prefixes changed")
	}
	if b := r.Report.Bindings; len(b) != 1 || b[0] != (Binding{Kind: "outbound", Name: "Home WireGuard", ID: id, Available: true}) {
		t.Fatal(b)
	}
	masked := r.Preview(false).Sources
	if strings.Contains(masked, private) || strings.Contains(masked, shared) || !strings.Contains(masked, public) {
		t.Fatal("WireGuard key masking mismatch")
	}
}

func TestWireGuardConfWARP(t *testing.T) {
	data := fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = 192.0.2.2/32, 2001:db8::2/128
DNS = 192.0.2.53, 2001:db8::53
MTU = 1280
[Peer]
PublicKey = %s
AllowedIPs = 0.0.0.0/0
AllowedIPs = ::/0
Endpoint = peer.example.com:2408
PersistentKeepalive = off
`, wireGuardTestKey(1), wireGuardTestKey(2))
	for _, tc := range []struct{ endpoint, server string }{
		{"warp.example.com", "warp.example.com"},
		{"192.0.2.1", "192.0.2.1"},
		{"[2001:db8::1]", "2001:db8::1"},
	} {
		t.Run(tc.endpoint, func(t *testing.T) {
			req := request(strings.Replace(data, "peer.example.com", tc.endpoint, 1))
			req.Format = "wireguard"
			r := ImportBundle(req, nil, nil)
			if !r.Report.CanApply || r.Report.Partial || r.Report.Format != "wireguard" {
				t.Fatal(r.Report)
			}
			ob := compileImport(t, r).Outbounds[0]
			if ob.Name != "WireGuard" || ob.ID != "airport/"+StableID("p", "WireGuard") || ob.Server != tc.server || ob.Port != 2408 || ob.Protocol.MTU != 1280 || ob.Protocol.PersistentKeepalive != 0 {
				t.Fatal("WireGuard endpoint or defaults changed during import")
			}
			if !slices.Equal(ob.Protocol.Address, []string{"192.0.2.2/32", "2001:db8::2/128"}) || !slices.Equal(ob.Protocol.AllowedIPs, []string{"0.0.0.0/0", "::/0"}) {
				t.Fatal("WireGuard address families changed during import")
			}
		})
	}
}

func TestWireGuardConfIgnoredFields(t *testing.T) {
	data := fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = 192.0.2.2/32
DNS = 192.0.2.53, 2001:db8::53
ListenPort = 51820
Table = auto
FwMark = 123
SaveConfig = true
PreUp = example-hook
PostUp = example-hook
PreDown = example-hook
PostDown = example-hook
[Peer]
PublicKey = %s
Endpoint = home.example.com:51820
`, wireGuardTestKey(1), wireGuardTestKey(2))
	r := Import(request(data))
	if !r.Report.CanApply || r.Report.Partial || len(r.Report.Ignored) != 9 || len(r.Report.Diagnostics) != 9 {
		t.Fatal(r.Report)
	}
	for i, key := range []string{"dns", "listenport", "table", "fwmark", "saveconfig", "preup", "postup", "predown", "postdown"} {
		d := r.Report.Diagnostics[i]
		path := "/wireguard/#0/" + key
		if d.Code != "import.ignored-field" || d.Severity != model.SeverityWarning || d.Document != "wireguard" || d.Line != i+4 || d.Path != path || r.Report.Ignored[i] != path {
			t.Fatal(d, r.Report.Ignored)
		}
		if i >= 5 && !strings.Contains(d.Message, "will not be executed") {
			t.Fatal(d)
		}
	}
	if strings.Contains(r.Preview(false).Sources, "example-hook") {
		t.Fatal("ignored scripts reached the source snapshot")
	}
	p := compileImport(t, r).Outbounds[0].Protocol
	if !slices.Equal(p.AllowedIPs, []string{"0.0.0.0/0", "::/0"}) {
		t.Fatal("native allowed IP defaults changed during import")
	}
}

func TestWireGuardConfErrors(t *testing.T) {
	input := fmt.Sprintf(`# sample configuration
[Interface]
PrivateKey = %s
Address = 192.0.2.2
Address = 2001:db8::2
[Peer]
PublicKey = %s
AllowedIPs = 10.0.0.0/24
Endpoint = home.example.com:51820
`, wireGuardTestKey(1), wireGuardTestKey(2))
	for _, tc := range []struct {
		name, data, code string
		line             int
	}{
		{"multiple peers", input + "[Peer]\n", "import.wireguard.peers", 10},
		{"missing peer", strings.Split(input, "[Peer]")[0], "import.wireguard.peers", 2},
		{"missing endpoint", strings.Split(input, "Endpoint")[0], "import.wireguard.endpoint", 6},
		{"malformed endpoint", strings.Replace(input, "home.example.com:51820", "2001:db8::1:51820", 1), "import.wireguard.endpoint", 9},
		{"invalid port", strings.Replace(input, ":51820", ":65536", 1), "import.port", 9},
		{"unknown section", strings.Replace(input, "[Peer]", "[Other]", 1), "import.wireguard.section", 6},
		{"unknown interface field", strings.Replace(input, "Address =", "Unknown =", 1), "import.unsupported-field", 4},
		{"unknown peer field", strings.Replace(input, "AllowedIPs =", "Unknown =", 1), "import.unsupported-field", 8},
		{"invalid private key", strings.Replace(input, wireGuardTestKey(1), "invalid-key", 1), "import.outbound.wireguard", 3},
		{"invalid public key", strings.Replace(input, wireGuardTestKey(2), "invalid-key", 1), "import.outbound.wireguard", 7},
		{"invalid second address", strings.Replace(input, "2001:db8::2", "invalid-address", 1), "import.outbound.wireguard", 5},
		{"invalid allowed IP", strings.Replace(input, "10.0.0.0/24", "invalid-prefix", 1), "import.outbound.wireguard", 8},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := request(tc.data)
			req.AllowPartial = true
			r := Import(req)
			if r.Report.CanApply || r.Report.Format != "wireguard" || r.Report.Nodes != (Count{Total: 1, Unavailable: 1}) || len(r.Source) != 0 {
				t.Fatal(r.Report)
			}
			if !slices.ContainsFunc(r.Report.Diagnostics, func(d model.Diagnostic) bool {
				return d.Code == tc.code && d.Severity == model.SeverityError && d.Document == "wireguard" && d.Line == tc.line
			}) {
				t.Fatal(r.Report.Diagnostics)
			}
		})
	}
	t.Run("multiple invalid fields", func(t *testing.T) {
		data := strings.NewReplacer(
			wireGuardTestKey(1), "invalid-key",
			"2001:db8::2", "invalid-address",
			"10.0.0.0/24", "invalid-prefix",
		).Replace(input)
		r := Import(request(data))
		if r.Report.CanApply || len(r.Report.Diagnostics) != 3 {
			t.Fatal(r.Report)
		}
		for _, line := range []int{3, 5, 8} {
			if !slices.ContainsFunc(r.Report.Diagnostics, func(d model.Diagnostic) bool {
				return d.Code == "import.outbound.wireguard" && d.Severity == model.SeverityError && d.Line == line
			}) {
				t.Fatal(r.Report.Diagnostics)
			}
		}
	})
}

func TestDetectWireGuardConf(t *testing.T) {
	const link = "ss://YWVzLTEyOC1nY206cGFzcw@192.0.2.1:8388#example"
	for _, tc := range []struct{ data, want string }{
		{"\n# comment\n ; comment\n[iNtErFaCe] # comment\n", "wireguard"},
		{"proxies: [{name: example, type: direct}]", "clash"},
		{"# comment\n" + link, "links"},
		{base64.StdEncoding.EncodeToString([]byte(link)), "links"},
		{"; comment\n" + link, "clash"},
	} {
		if got := detectFormat(tc.data); got != tc.want {
			t.Errorf("detectFormat(%q) = %s, want %s", tc.data, got, tc.want)
		}
	}
}
