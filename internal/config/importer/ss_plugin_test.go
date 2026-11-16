package importer

import (
	"encoding/base64"
	"net/url"
	"strings"
	"testing"
)

func TestClashSSPluginDefaultsAndMasking(t *testing.T) {
	for _, tc := range []struct{ kind, options string }{
		{"restls", "host: target.test, password: plugin-secret, version-hint: tls13, restls-script: '100~30'"}, {"jls", "host: target.test, username: plugin-user, password: plugin-secret, alpn: []"}, {"kcptun", "key: plugin-secret, crypt: aes, conn: 2, mode: fast2, nocomp: true, smuxver: 2"},
		{"obfs", "mode: http"}, {"obfs", "mode: tls"}, {"v2ray-plugin", "mode: websocket, tls: true, headers: {Host: override.test, Authorization: header-secret}, v2ray-http-upgrade: true, v2ray-http-upgrade-fast-open: true"}, {"gost-plugin", "mode: websocket, mux: false"}, {"shadow-tls", "version: 3, host: target.test, password: plugin-secret"},
	} {
		input := "proxies: [{name: node, type: ss, server: node.test, port: 443, cipher: aes-128-gcm, password: test, plugin: " + tc.kind + ", plugin-opts: {" + tc.options + "}}]"
		r := Import(request(input))
		if !r.Report.CanApply {
			t.Fatal(tc.kind, r.Report)
		}
		eff := compileImport(t, r)
		p := eff.Outbounds[0].Plugin
		if p == nil || p.Type != tc.kind {
			t.Fatal("plugin dropped", tc.kind)
		}
		if tc.kind == "v2ray-plugin" && (p.Mux == nil || !*p.Mux || p.TLS.ServerName != "override.test" || !p.FastOpen) {
			t.Fatal("websocket defaults or Host SNI precedence lost")
		}
		if tc.kind == "kcptun" && (!eff.Outbounds[0].UDPOverTCP || eff.Outbounds[0].UDPOverTCPVersion != 1 || p.KCP.Conn != 2 || p.KCP.Interval != 20) {
			t.Fatal("kcptun defaults or required UoT lost")
		}
		if tc.kind == "shadow-tls" && (p.Version != 3 || p.Password != "plugin-secret") {
			t.Fatal("ShadowTLS options lost")
		}
		preview := r.Preview(false).Sources
		if strings.Contains(preview, "plugin-secret") || strings.Contains(preview, "header-secret") {
			t.Fatal("plugin secret leaked")
		}
		changed := Import(request(strings.Replace(input, tc.options, tc.options+", unknown: true", 1)))
		if changed.Report.CanApply {
			t.Fatal("unknown plugin option accepted")
		}
	}
}

func TestSIP003SSLinkPluginOptionsAndEscapes(t *testing.T) {
	for _, tc := range []struct{ plugin, kind string }{
		{"restls;host=front.test;password=outer-secret;version-hint=tls13", "restls"}, {"jls;host=front.test;username=outer-user;password=outer-secret;alpn=h2,http/1.1", "jls"}, {"kcptun;key=outer-secret;smuxver=2;nocomp;mode=fast3", "kcptun"}, {"shadow-tls;host=front.test;password=outer-secret;version=3", "shadow-tls"}, {"gost-plugin;mode=websocket;host=front.test;tls;mux=false", "gost-plugin"},
		{"obfs-local;obfs=http;obfs-host=front.test", "obfs"}, {"simple-obfs;obfs=tls;obfs-host=front.test", "obfs"},
		{`v2ray-plugin;mode=websocket;host=front.test;path=/a\;b\=c;tls;mux=0`, "v2ray-plugin"},
	} {
		link := "ss://" + base64.RawURLEncoding.EncodeToString([]byte("aes-128-gcm:secret")) + "@node.test:443/?plugin=" + url.QueryEscape(tc.plugin) + "&uot=1&udp-over-tcp=false#node"
		r := Import(request(link))
		if !r.Report.CanApply {
			t.Fatal(r.Report)
		}
		p := compileImport(t, r).Outbounds[0]
		if p.Plugin == nil || p.Plugin.Type != tc.kind || !p.UDPOverTCP {
			t.Fatal("link plugin/UoT lost")
		}
		if tc.kind == "v2ray-plugin" && (p.Plugin.Path != "/a;b=c" || *p.Plugin.Mux || p.Plugin.TLS == nil) {
			t.Fatal("SIP003 flags or escapes lost")
		}
	}
	for _, value := range []string{"obfs-local;obfs=tls;unknown=x", "v2ray-plugin;mode=websocket;mode=quic", "v2ray-plugin;mode=websocket;mux=not-a-number", `v2ray-plugin;mode=websocket;path=bad\`} {
		if _, _, err := ssLinkPlugin(value); err == nil {
			t.Fatal("invalid SIP003 options accepted", value)
		}
	}
}

func TestGroupDotNetFilterPriorityAndExpectedStatus(t *testing.T) {
	input := `proxies: [{name: alpha-one, type: direct},{name: beta-two, type: direct},{name: alpha-skip, type: direct}]
proxy-groups: [{name: auto, type: url-test, proxies: [alpha-one, beta-two, alpha-skip], filter: '(?<=beta-)two` + "`" + `(?<=alpha-)one', exclude-filter: 'skip$', expected-status: '204/300-399'}]
rules: ['MATCH,auto']`
	r := Import(request(input))
	if !r.Report.CanApply {
		t.Fatal(r.Report)
	}
	eff := compileImport(t, r)
	if len(eff.AutoGroups) != 1 || eff.AutoGroups[0].ExpectedStatus != "204/300-399" {
		t.Fatal("health status lost")
	}
	src := snapshot(t, r)
	if len(src.Groups[0].Members) != 2 || src.Groups[0].Members[0] != src.Outbounds[1].ID {
		t.Fatal(".NET filter priority lost")
	}
	for _, status := range []string{"65536", "bad", "204-"} {
		bad := Import(request(strings.Replace(input, "204/300-399", status, 1)))
		if bad.Report.CanApply {
			t.Fatal("invalid health range accepted", status)
		}
	}
}
func TestProviderExpectedStatus(t *testing.T) {
	input := `proxy-providers: {one: {type: inline, payload: [{name: node, type: direct}], health-check: {enable: true, url: 'http://example.test/', interval: 30, expected-status: '204,300-399'}}}
proxy-groups: [{name: pick, type: select, use: [one]}]
rules: ['MATCH,pick']`
	req := request(input)
	defs, err := Providers(req)
	if err != nil {
		t.Fatal(err)
	}
	r := ImportProviders(req, map[string][]byte{defs[0].ID: defs[0].Inline})
	if !r.Report.CanApply {
		t.Fatal(r.Report)
	}
	eff := compileImport(t, r)
	if len(eff.AutoGroups) != 1 || eff.AutoGroups[0].ExpectedStatus != "204,300-399" {
		t.Fatal("provider status range lost", eff.AutoGroups)
	}
}
