package importer

import (
	"strings"
	"testing"
)

func TestClashCertificatePinAndVerificationName(t *testing.T) {
	pin := strings.Repeat("12", 32)
	for _, typ := range []string{"http", "socks5", "vless", "vmess", "trojan", "hysteria2", "tuic"} {
		extra := ""
		if typ == "vless" || typ == "vmess" || typ == "tuic" {
			extra += ", uuid: b831381d-6324-4d53-ad4f-8cda48b30811"
		}
		if typ == "trojan" || typ == "hysteria2" || typ == "tuic" {
			extra += ", password: test"
		}
		r := Import(request("proxies: [{name: node, type: " + typ + ", server: node.test, port: 443, tls: true, fingerprint: '" + pin + "', name-cert-verify: cert.test" + extra + "}]"))
		if !r.Report.CanApply {
			t.Fatal(typ, r.Report)
		}
		out := snapshot(t, r).Outbounds[0]
		if out.TLS.CertificatePin != pin || out.TLS.VerifyName != "cert.test" {
			t.Fatal("TLS certificate options dropped")
		}
		compileImport(t, r)
	}
}
