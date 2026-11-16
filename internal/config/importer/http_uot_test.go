package importer

import (
	"strings"
	"testing"
)

func TestClashHTTPHeadersAndSSUOT(t *testing.T) {
	r := Import(request("proxies: [{name: node, type: http, server: node.test, port: 80, headers: {X-Test: private-http-token, Host: front.test}}]"))
	if !r.Report.CanApply {
		t.Fatal(r.Report)
	}
	if strings.Contains(r.Preview(false).Sources, "private-http-token") {
		t.Fatal("HTTP header leaked")
	}
	if len(snapshot(t, r).Outbounds[0].Headers) != 2 {
		t.Fatal(snapshot(t, r).Outbounds)
	}
	compileImport(t, r)
	for _, suffix := range []string{"", ", udp-over-tcp-version: 1", ", udp-over-tcp-version: 2"} {
		r := Import(request("proxies: [{name: node, type: ss, server: node.test, port: 443, cipher: aes-128-gcm, password: test, udp: true, udp-over-tcp: true" + suffix + "}]"))
		if !r.Report.CanApply {
			t.Fatal(r.Report)
		}
		if !snapshot(t, r).Outbounds[0].UDPOverTCP {
			t.Fatal("UoT dropped")
		}
		compileImport(t, r)
	}
	r = Import(request("proxies: [{name: node, type: ss, server: node.test, port: 443, cipher: aes-128-gcm, password: test, udp-over-tcp: true, udp-over-tcp-version: 3}]"))
	if r.Report.CanApply {
		t.Fatal("unknown UoT version accepted")
	}
}
