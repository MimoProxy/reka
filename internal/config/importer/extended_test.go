package importer

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestProviderHealthAndIncludeAllFilter(t *testing.T) {
	data := `proxies: [{name: root, type: direct}]
proxy-providers:
 remote:
  type: inline
  payload: [{name: HK-fast, type: direct},{name: US-slow, type: direct}]
  health-check: {enable: true, url: 'https://health.test/', interval: 30, lazy: false}
proxy-groups:
 - {name: Root, type: select, include-all-proxies: true}
 - {name: HK, type: url-test, include-all-providers: true, filter: '^HK-', lazy: false}
rules: ['MATCH,HK']
`
	req := request(data)
	r := Import(req)
	if !r.Report.CanApply {
		t.Fatal(r.Report)
	}
	src := snapshot(t, r)
	if len(src.Groups) != 3 {
		t.Fatal(src.Groups)
	}
	for _, g := range src.Groups {
		if g.Name == "Root" && (len(g.Members) != 1 || g.Members[0] != StableID("p", "root")) {
			t.Fatal("provider nodes leaked into root-only expansion", g)
		}
		if g.Name == "HK" && (len(g.Members) != 1 || g.Members[0] != StableID("p", "remote/HK-fast")) {
			t.Fatal("provider identity filter mismatch", g)
		}
	}
	compileImport(t, r)
}
func TestNewShareLinksAndStrictOptions(t *testing.T) {
	vmess := `{"v":"2","ps":"VM","add":"node.test","port":"443","id":"b831381d-6324-4d53-ad4f-8cda48b30811","aid":"0","scy":"auto","net":"ws","path":"/test","tls":"tls","sni":"node.test"}`
	links := []string{"vmess://" + base64.StdEncoding.EncodeToString([]byte(vmess)), "trojan://private-password@node.test:443?type=grpc&serviceName=reka&sni=node.test#TR", "hy2://private-password@node.test:443?sni=node.test#HY", "tuic://b831381d-6324-4d53-ad4f-8cda48b30811:private-password@node.test:443?alpn=h3#TU"}
	for _, link := range links {
		r := Import(request(link))
		if !r.Report.CanApply {
			t.Fatal(r.Report)
		}
		if strings.Contains(r.Preview(false).Sources, "private-password") {
			t.Fatal("share credential leaked")
		}
		compileImport(t, r)
	}
	for _, bad := range []string{"trojan://password@node.test:443?security=none", "hy2://password@node.test:443?unknown=x", "tuic://no-password@node.test:443"} {
		if r := Import(request(bad)); r.Report.CanApply {
			t.Fatal("invalid link accepted")
		}
	}
}

func TestClashDNSDefaultsAndHosts(t *testing.T) {
	data := "dns: {enable: true, nameserver: [1.1.1.1], enhanced-mode: fake-ip}\nhosts: {example.test: 192.0.2.1}\n"
	r := Import(request(data))
	if !r.Report.CanApply {
		t.Fatal(r.Report)
	}
	d := snapshot(t, r).DNS
	if d == nil || !d.UseHosts || !d.SystemHosts || d.TTL != 1 || len(d.FakeFilter) != 3 || len(d.Hosts) != 1 {
		t.Fatal(d)
	}
	for _, ignored := range r.Report.Ignored {
		if ignored == "/hosts" {
			t.Fatal("imported hosts reported as ignored")
		}
	}
	compileImport(t, r)
	if r = Import(request("proxies: [{name: n, type: direct}]\ndns: {nameserver: [1.1.1.1]}")); !r.Report.CanApply || snapshot(t, r).DNS != nil {
		t.Fatal("absent enable must leave DNS disabled", r.Report)
	}
	for _, suffix := range []string{", fallback: [8.8.8.8]", ", fake-ip-ttl: 0"} {
		r = Import(request("dns: {enable: true, nameserver: [1.1.1.1]" + suffix + "}"))
		if r.Report.CanApply {
			t.Fatal("missing locked GeoIP or zero TTL accepted", r.Report)
		}
	}
	r = Import(request("dns: {enable: true, nameserver: [1.1.1.1], fallback: [8.8.8.8], fallback-filter: {geoip: false}}"))
	if !r.Report.CanApply {
		t.Fatal(r.Report)
	}
}
