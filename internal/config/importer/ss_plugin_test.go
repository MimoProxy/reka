package importer

import (
	"encoding/base64"
	"net/url"
	"strings"
	"testing"
)

func TestClashSSPluginDefaultsAndMasking(t *testing.T) {
	for _, tc := range []struct{ kind, options string }{
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
