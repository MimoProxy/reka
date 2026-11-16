package importer

import "testing"

func TestClashVLESSPacketSelection(t *testing.T) {
	for _, tc := range []struct{ fields, want string }{
		{"", "xudp"}, {", xudp: false", "xudp"}, {", packet-addr: true", "packetaddr"},
		{", packet-addr: true, xudp: true", "xudp"},
		{", packet-encoding: packetaddr, xudp: true", "packetaddr"},
		{", packet-encoding: packet", "packetaddr"},
	} {
		r := Import(request("proxies: [{name: node, type: vless, server: node.test, port: 443, uuid: b831381d-6324-4d53-ad4f-8cda48b30811, udp: true" + tc.fields + "}]"))
		if !r.Report.CanApply {
			t.Fatal(tc, r.Report)
		}
		if got := snapshot(t, r).Outbounds[0].PacketEncoding; got != tc.want {
			t.Fatal(tc, got)
		}
		compileImport(t, r)
	}
}
