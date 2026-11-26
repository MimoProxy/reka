package importer

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestSSRClashNode(t *testing.T) {
	result := Import(request(`proxies:
  - name: example
    type: ssr
    server: ssr.example
    port: "8388"
    cipher: aes-256-cfb
    password: test-password
    obfs: tls1.2_ticket_auth
    obfs-param: cover.example
    protocol: auth_aes128_md5
    protocol-param: "64:test-key"
    udp: true
    tfo: false
    mptcp: true
    interface-name: test-interface
    routing-mark: 42
    ip-version: ipv6-prefer
    dialer-proxy: DIRECT
`))
	if !result.Report.CanApply || result.Report.Partial {
		t.Fatal(result.Report)
	}
	out := compileImport(t, result).Outbounds[0]
	if out.Type != "ssr" || out.Name != "example" || out.Server != "ssr.example" || out.Port != 8388 || out.Method != "aes-256-cfb" || out.Password != "test-password" || !out.UDP {
		t.Fatal("SSR endpoint or credentials changed during import")
	}
	p := out.Protocol
	if p == nil || p.Obfs == nil || p.Obfs.Type != "tls1.2_ticket_auth" || p.Obfs.Param != "cover.example" || p.SSRProtocol != "auth_aes128_md5" || p.SSRProtocolParam != "64:test-key" {
		t.Fatal("SSR obfuscation or protocol changed during import")
	}
	if d := out.Dialer; d == nil || d.TFO || !d.MPTCP || d.Interface != "test-interface" || d.RoutingMark != 42 || d.IPVersion != "ipv6-prefer" || d.Proxy != "direct" {
		t.Fatal("SSR dialer options changed during import")
	}
	preview := result.Preview(false)
	if preview.Masked != 2 || strings.Contains(preview.Sources, "test-password") || strings.Contains(preview.Sources, "test-key") {
		t.Fatal("SSR preview did not mask both credentials")
	}

	result = Import(request(`proxies: [{name: minimal, type: ssr, server: '2001:db8::1', port: 8388, cipher: none, password: test-password, obfs: plain, protocol: origin}]`))
	if !result.Report.CanApply || result.Report.Partial {
		t.Fatal(result.Report)
	}
	out = compileImport(t, result).Outbounds[0]
	if out.Server != "2001:db8::1" || out.UDP || out.Protocol.SSRProtocolParam != "" || out.Protocol.Obfs.Param != "" {
		t.Fatal("unexpected SSR defaults")
	}
}

func TestSSRClashRejectsUnsupportedOptions(t *testing.T) {
	const node = `proxies: [{name: example, type: ssr, server: ssr.example, port: 8388, cipher: none, password: test-password, obfs: plain, protocol: origin}]`
	for _, tc := range []struct{ from, to, key string }{
		{", cipher: none", "", "cipher"}, {", password: test-password", "", "password"},
		{", obfs: plain", "", "obfs"}, {", protocol: origin", "", "protocol"},
		{"cipher: none", "cipher: aes-256-gcm", "cipher"}, {"obfs: plain", "obfs: unsupported", "obfs"},
		{"protocol: origin", "protocol: unsupported", "protocol"}, {"}]", ", smux: {enabled: false}}]", "smux"},
		{"}]", ", tfo: True}]", "tfo"}, {"}]", ", plugin: obfs}]", "plugin"},
	} {
		t.Run(tc.key+tc.to, func(t *testing.T) {
			r := Import(request(strings.Replace(node, tc.from, tc.to, 1)))
			if r.Report.CanApply || r.Report.Nodes.Unavailable != 1 {
				t.Fatal("unsupported SSR option was accepted")
			}
			for _, d := range r.Report.Diagnostics {
				if strings.HasSuffix(d.Path, "/"+tc.key) && d.Line > 0 {
					return
				}
			}
			t.Fatal(r.Report.Diagnostics)
		})
	}
}

func ssrTestLink(body string) string {
	return "ssr://" + base64.RawURLEncoding.EncodeToString([]byte(body))
}

func TestSSRShareLinks(t *testing.T) {
	const authority = "ssr.example:8388:auth_chain_a:rc4-md5:http_simple:dGVzdC1wYXNzd29yZA"
	r := Import(request(ssrTestLink(authority + "/?remarks=5rWL6K+V&remarks=ignored&obfsparam=Y292ZXIuZXhhbXBsZQ&protoparam=NjQ6dGVzdC1rZXk&group=Z3JvdXA&uot=1&udpport=443")))
	if !r.Report.CanApply || r.Report.Partial {
		t.Fatal(r.Report)
	}
	out := compileImport(t, r).Outbounds[0]
	if out.Type != "ssr" || out.Name != "测试" || out.Server != "ssr.example" || out.Port != 8388 || !out.UDP || out.Method != "rc4-md5" || out.Password != "test-password" || out.UDPOverTCP {
		t.Fatal("SSR link endpoint or credentials changed during import")
	}
	if p := out.Protocol; p == nil || p.SSRProtocol != "auth_chain_a" || p.SSRProtocolParam != "64:test-key" || p.Obfs == nil || p.Obfs.Type != "http_simple" || p.Obfs.Param != "cover.example" {
		t.Fatal("SSR link protocol parameters changed during import")
	}
	if preview := r.Preview(false); preview.Masked != 2 || strings.Contains(preview.Sources, "test-key") || strings.Contains(preview.Sources, "test-password") {
		t.Fatal("SSR link preview did not mask both credentials")
	}
	r = Import(request(ssrTestLink(authority + "/?")))
	if !r.Report.CanApply {
		t.Fatal(r.Report)
	}
	out = compileImport(t, r).Outbounds[0]
	if out.Name != "ssr@ssr.example:8388" || !out.UDP || out.Protocol.SSRProtocolParam != "" || out.Protocol.Obfs.Param != "" {
		t.Fatal("unexpected SSR link defaults")
	}

	for _, link := range []string{
		"ssr://%%%", ssrTestLink(authority), ssrTestLink("ssr.example:8388:origin:none:cGFzcw/?"),
		ssrTestLink("2001:db8::1:8388:origin:none:plain:cGFzcw/?"),
		ssrTestLink("[2001:db8::1]:8388:origin:none:plain:cGFzcw/?"),
		ssrTestLink("ssr.example:8388:origin:none:plain:*/?"),
		ssrTestLink("ssr.example:8388:origin:none:plain:/?"),
		ssrTestLink(authority + "/?remarks=%zz"), ssrTestLink(authority + "/?protoparam=*"),
	} {
		if r := Import(request(link)); r.Report.CanApply || r.Report.Nodes.Unavailable != 1 {
			t.Fatal("invalid SSR link was accepted")
		}
	}
}
