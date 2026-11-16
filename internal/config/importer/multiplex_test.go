package importer

import (
	"strings"
	"testing"
)

func TestClashMultiplexAllDialingProtocolsAndUDPOverride(t *testing.T) {
	for _, tc := range []struct{ typ, extra string }{
		{"ss", ", cipher: aes-128-gcm, password: test"}, {"http", ""}, {"socks5", ""}, {"vmess", ", uuid: b831381d-6324-4d53-ad4f-8cda48b30811"}, {"trojan", ", password: test"}, {"hysteria2", ", password: test"}, {"tuic", ", uuid: b831381d-6324-4d53-ad4f-8cda48b30811, password: test"}, {"snell", ", version: 5, psk: test-password"},
	} {
		input := "proxies: [{name: node, type: " + tc.typ + ", server: node.test, port: 443, smux: {enabled: true, protocol: yamux, padding: true, statistic: true, brutal-opts: {enabled: true, up: '10 Mbps', down: '2MBps'}}" + tc.extra + "}]"
		r := Import(request(input))
		if !r.Report.CanApply {
			t.Fatal(tc.typ, r.Report)
		}
		eff := compileImport(t, r)
		out := eff.Outbounds[0]
		if !out.UDP || out.Multiplex == nil || out.Multiplex.Brutal.UpBPS != 1250000 || out.Multiplex.Brutal.DownBPS != 2000000 {
			t.Fatal("multiplex options or UDP override lost", tc.typ)
		}
		changed := Import(request(strings.Replace(input, "statistic: true", "statistic: false", 1)))
		if compileImport(t, changed).Outbounds[0].Fingerprint != out.Fingerprint {
			t.Fatal("accounting metadata rebuilt transport")
		}
		if tc.typ == "http" {
			onlyTCP := Import(request(strings.Replace(input, "padding: true", "only-tcp: true, padding: true", 1)))
			if !onlyTCP.Report.CanApply || compileImport(t, onlyTCP).Outbounds[0].UDP {
				t.Fatal("only-tcp enabled native HTTP UDP")
			}
		}
	}
}
