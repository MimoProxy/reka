package importer

import (
	"strings"
	"testing"
)

func TestClashHTTPAndH2Transports(t *testing.T) {
	for _, typ := range []string{"vmess", "vless"} {
		for _, network := range []string{"http", "h2"} {
			suffix := ", http-opts: {method: POST, path: [/one, /two], headers: {Host: [front.test], X-Token: [secret-one, secret-two]}}"
			if network == "h2" {
				suffix = ", h2-opts: {host: [front.test, other.test], path: /tunnel}"
			}
			r := Import(request("proxies: [{name: node, type: " + typ + ", server: node.test, port: 443, uuid: b831381d-6324-4d53-ad4f-8cda48b30811, network: " + network + suffix + "}]"))
			if !r.Report.CanApply {
				t.Fatal(typ, network, r.Report)
			}
			out := snapshot(t, r).Outbounds[0]
			if out.Transport.Type != network || network == "h2" && out.TLS == nil {
				t.Fatal(out)
			}
			if strings.Contains(r.Preview(false).Sources, "secret-one") {
				t.Fatal("transport header leaked")
			}
			compileImport(t, r)
		}
	}
	r := Import(request("proxies: [{name: node, type: socks5, server: node.test, port: 443, tls: true, sni: front.test, skip-cert-verify: true}]"))
	if !r.Report.CanApply || snapshot(t, r).Outbounds[0].TLS.ServerName != "front.test" {
		t.Fatal(r.Report)
	}
	compileImport(t, r)
}
