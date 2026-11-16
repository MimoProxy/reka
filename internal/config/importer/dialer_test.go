package importer

import "testing"

func TestCommonNodeDialerOptions(t *testing.T) {
	for _, typ := range []string{"direct", "socks5", "http", "ss", "vmess", "vless", "trojan", "hysteria2", "tuic", "snell"} {
		extras := ", server: node.test, port: 443"
		switch typ {
		case "direct":
			extras = ""
		case "ss":
			extras += ", cipher: aes-128-gcm, password: test"
		case "vmess", "vless":
			extras += ", uuid: b831381d-6324-4d53-ad4f-8cda48b30811"
		case "tuic":
			extras += ", uuid: b831381d-6324-4d53-ad4f-8cda48b30811, password: test"
		case "trojan", "hysteria2":
			extras += ", password: test"
		case "snell":
			extras += ", psk: test, version: 5"
		}
		r := Import(request("proxies: [{name: node, type: " + typ + extras + ", interface-name: test-interface, routing-mark: 42, ip-version: ipv6-prefer, tfo: true, mptcp: true}]"))
		if !r.Report.CanApply {
			t.Fatal(typ, r.Report)
		}
		d := snapshot(t, r).Outbounds[0].Dialer
		if d == nil || d.Interface != "test-interface" || d.RoutingMark != 42 || d.IPVersion != "ipv6-prefer" || !d.TFO || !d.MPTCP {
			t.Fatal(typ, d)
		}
		compileImport(t, r)
	}
	for _, option := range []string{"routing-mark: -1", "routing-mark: 4294967296", "ip-version: invalid", "tfo: yes", "mptcp: 'true'"} {
		if r := Import(request("proxies: [{name: node, type: direct, " + option + "}]")); r.Report.CanApply {
			t.Fatal("invalid dialer option accepted", option)
		}
	}
}
