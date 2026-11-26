package importer

import (
	"slices"
	"strings"
	"testing"

	"github.com/MimoProxy/reka/internal/config/model"
)

// This traffic pattern and the share links below come from mihomo's converter tests.
const mieruTrafficPattern = "CCoQARoECAEQCiIYCAMQASoIMDAwMTAyMDMqCDA0MDUwNjA3"

func TestMieruClashNode(t *testing.T) {
	r := Import(request(`proxies:
 - name: Mieru example
   type: mieru
   server: 192.0.2.8
   port: "443"
   transport: TCP
   username: test-user
   password: test-password
   udp: true
   multiplexing: MULTIPLEXING_HIGH
   handshake-mode: HANDSHAKE_NO_WAIT
   traffic-pattern: ` + mieruTrafficPattern + `
   interface-name: test-interface
   routing-mark: 42
   ip-version: ipv6-prefer
   dialer-proxy: DIRECT
   tfo: false
   mptcp: false
`))
	if !r.Report.CanApply || r.Report.Partial {
		t.Fatal(r.Report)
	}
	out := compileImport(t, r).Outbounds[0]
	if out.Name != "Mieru example" || out.Type != model.OutboundMieru || out.Server != "192.0.2.8" ||
		out.Port != 443 || out.Username != "test-user" || out.Password != "test-password" || !out.UDP {
		t.Fatal("Mieru endpoint or credentials changed during import")
	}
	if p := out.Protocol; p == nil || p.Transport != "TCP" || p.Multiplexing != "MULTIPLEXING_HIGH" ||
		p.HandshakeMode != "HANDSHAKE_NO_WAIT" || p.TrafficPattern != mieruTrafficPattern || len(p.ServerPorts) != 0 {
		t.Fatal("Mieru protocol options changed during import")
	}
	if d := out.Dialer; d == nil || d.Interface != "test-interface" || d.RoutingMark != 42 || d.IPVersion != "ipv6-prefer" || d.Proxy != "direct" {
		t.Fatal("Mieru dialer options changed during import")
	}
	if preview := r.Preview(false); preview.Masked != 2 || strings.Contains(preview.Sources, "test-password") || strings.Contains(preview.Sources, "test-user") {
		t.Fatal("Mieru preview exposed a credential")
	}

	r = Import(request(`proxies: [{name: range, type: mieru, server: example.com, port-range: 2000-2010, transport: UDP, username: user, password: test-password}]`))
	if !r.Report.CanApply {
		t.Fatal(r.Report)
	}
	out = compileImport(t, r).Outbounds[0]
	if out.UDP || out.Port != 0 || out.Protocol.Transport != "UDP" || !slices.Equal(out.Protocol.ServerPorts, []string{"2000-2010"}) {
		t.Fatal("Mieru port range or default UDP forwarding changed")
	}
}

func TestMieruClashDiagnostics(t *testing.T) {
	const node = `proxies: [{name: node, type: mieru, server: 192.0.2.2, username: user, password: pass, transport: TCP, `
	for _, tc := range []struct{ options, field, code string }{
		{"port: 443, tfo: True", "tfo", "import.unsupported-field"},
		{"port: 443, mptcp: true", "mptcp", "import.unsupported-field"},
		{"port: 443, smux: {enabled: false}", "smux", "import.unsupported-field"},
		{"port: 443, network: ws", "network", "import.unsupported-field"},
		{"port: 443, tls: true", "tls", "import.unsupported-field"},
		{"port: 443, port-range: 2000-2010", "port-range", ""},
		{"port-range: 2010-2000", "port-range", ""},
		{"port-range: '2000:2010'", "port-range", ""},
		{"port-range: 2000-2001, traffic-pattern: bad", "traffic-pattern", ""},
	} {
		t.Run(tc.options, func(t *testing.T) {
			r := Import(request(node + tc.options + "}]"))
			if r.Report.CanApply || r.Report.Nodes.Unavailable != 1 || !slices.ContainsFunc(r.Report.Diagnostics, func(d model.Diagnostic) bool {
				return d.Line == 1 && d.Path == "/proxies/#0/"+tc.field && (tc.code == "" || d.Code == tc.code)
			}) {
				t.Fatal(r.Report)
			}
		})
	}
}

func TestMieruShareLinkPortPairs(t *testing.T) {
	const link = "mierus://user:pass@1.2.3.4?handshake-mode=HANDSHAKE_NO_WAIT&mtu=1400&multiplexing=MULTIPLEXING_HIGH&port=6666&port=9998-9999&port=6489&port=4896&profile=default&protocol=TCP&protocol=TCP&protocol=UDP&protocol=UDP&traffic-pattern=" + mieruTrafficPattern
	r := Import(request(link))
	if !r.Report.CanApply || r.Report.Partial || r.Report.Nodes.Total != 4 || r.Report.Nodes.Imported != 4 {
		t.Fatal(r.Report)
	}
	nodes := snapshot(t, r).Outbounds
	for i, tc := range []struct {
		name, transport string
		port            int
		ranges          []string
	}{
		{"default:6666/TCP", "TCP", 6666, nil},
		{"default:9998-9999/TCP", "TCP", 0, []string{"9998-9999"}},
		{"default:6489/UDP", "UDP", 6489, nil},
		{"default:4896/UDP", "UDP", 4896, nil},
	} {
		out := nodes[i]
		if out.Name != tc.name || out.Type != model.OutboundMieru || out.Port != tc.port || out.Server != "1.2.3.4" ||
			out.Username != "user" || out.Password != "pass" || out.UDP == nil || !*out.UDP {
			t.Fatal("incorrect Mieru endpoint for", tc.name)
		}
		if p := out.Protocol; p == nil || p.Transport != tc.transport || p.Multiplexing != "MULTIPLEXING_HIGH" ||
			p.HandshakeMode != "HANDSHAKE_NO_WAIT" || p.TrafficPattern != mieruTrafficPattern || !slices.Equal(p.ServerPorts, tc.ranges) {
			t.Fatal("incorrect Mieru protocol options for", tc.name)
		}
	}
	compileImport(t, r)
}

func TestMieruShareLinkNamesAndSkippedPorts(t *testing.T) {
	const host = "mierus://user:pass@example.com"
	r := Import(request(strings.Join([]string{
		host + "?port=443&protocol=TCP&profile=simple",
		host + "?port=443&protocol=TCP&profile=default#myproxy",
		host + "?port=80&protocol=TCP&port=80&protocol=TCP",
		host + "?port=80&protocol=TCP",
		host + "?protocol=UDP",
		host + "?port=81&port=82&protocol=UDP",
		host + "?port=bad&port=83&protocol=UDP&protocol=TCP",
	}, "\n")))
	want := []string{"simple:443/TCP", "myproxy:443/TCP", "example.com:80/TCP", "example.com:80/TCP-01", "example.com:80/TCP-02", "example.com:83/TCP"}
	if !r.Report.CanApply || r.Report.Partial || r.Report.Nodes.Total != len(want) || r.Report.Nodes.Imported != len(want) {
		t.Fatal(r.Report)
	}
	for i, out := range snapshot(t, r).Outbounds {
		if out.Name != want[i] || out.ID != StableID("p", want[i]) {
			t.Errorf("got name %q and ID %q, want an ID derived from %q", out.Name, out.ID, want[i])
		}
	}
}
