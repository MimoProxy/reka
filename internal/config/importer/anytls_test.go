package importer

import (
	"slices"
	"strings"
	"testing"
)

func TestAnyTLSClashNode(t *testing.T) {
	pin := strings.Repeat("42", 32)
	r := Import(request(`proxies:
 - name: AnyTLS example
   type: anytls
   server: 192.0.2.8
   port: 443
   password: test-password
   udp: true
   sni: cover.test
   alpn: [h2, http/1.1]
   skip-cert-verify: true
   name-cert-verify: cert.test
   fingerprint: '` + pin + `'
   client-fingerprint: chrome
   ech-opts: {enable: true, query-server-name: ech.test}
   client-metadata: test-client
   idle-session-check-interval: 45
   idle-session-timeout: 120
   min-idle-session: 2
   disable-reuse: false
   tfo: false
   mptcp: true
   interface-name: test-interface
   routing-mark: 42
   ip-version: ipv6-prefer
   dialer-proxy: DIRECT
`))
	if !r.Report.CanApply || r.Report.Partial {
		t.Fatal(r.Report)
	}
	out := compileImport(t, r).Outbounds[0]
	if out.Type != "anytls" || out.Name != "AnyTLS example" || out.Server != "192.0.2.8" || out.Port != 443 || out.Password != "test-password" || !out.UDP {
		t.Fatal("AnyTLS endpoint or credentials changed during conversion")
	}
	if p := out.Protocol; p == nil || p.IdleSessionCheckIntervalSeconds != 45 || p.IdleSessionTimeoutSeconds != 120 || p.MinIdleSession != 2 || p.ClientMetadata != "test-client" {
		t.Fatal("AnyTLS protocol options changed during conversion")
	}
	tls := out.TLS
	if tls == nil || tls.ServerName != "cover.test" || !tls.Insecure || tls.VerifyName != "cert.test" || tls.CertificatePin != pin || tls.Fingerprint != "chrome" || !slices.Equal(tls.ALPN, []string{"h2", "http/1.1"}) {
		t.Fatal("AnyTLS TLS options changed during conversion")
	}
	if ech := tls.ECH; ech == nil || !ech.Enabled || ech.QueryServerName != "ech.test" {
		t.Fatal("AnyTLS ECH options changed during conversion")
	}
	if d := out.Dialer; d == nil || d.TFO || !d.MPTCP || d.Interface != "test-interface" || d.RoutingMark != 42 || d.IPVersion != "ipv6-prefer" || d.Proxy != "direct" {
		t.Fatal("AnyTLS dialer options changed during conversion")
	}
	if preview := r.Preview(false); preview.Masked != 1 || strings.Contains(preview.Sources, "test-password") {
		t.Fatal("AnyTLS password was exposed in preview")
	}

	r = Import(request(`proxies: [{name: defaults, type: anytls, server: 192.0.2.8, port: 443, password: test-password}]`))
	if !r.Report.CanApply {
		t.Fatal(r.Report)
	}
	out = compileImport(t, r).Outbounds[0]
	if out.UDP || out.TLS == nil || out.TLS.ServerName != out.Server || out.TLS.Insecure || (out.Protocol != nil && out.Protocol.ClientMetadata != "") {
		t.Fatal("AnyTLS defaults do not match mihomo")
	}
}

func TestAnyTLSClashRejectsUnsupportedOptions(t *testing.T) {
	const node = `proxies: [{name: node, type: anytls, server: node.test, port: 443, password: test-password`
	for _, tc := range []struct {
		key, option string
	}{
		{"disable-reuse", "TRUE"},
		{"smux", "{enabled: false}"},
		{"smux", "null"},
		{"tfo", "True"},
		{"network", "tcp"},
		{"reality-opts", "{}"},
		{"tls", "false"},
		{"unknown", "true"},
	} {
		t.Run(tc.key+"="+tc.option, func(t *testing.T) {
			r := Import(request(node + ", " + tc.key + ": " + tc.option + "}]"))
			if r.Report.CanApply || r.Report.Nodes.Unavailable != 1 {
				t.Fatal("unsupported AnyTLS option was accepted")
			}
			matches := 0
			for _, d := range r.Report.Diagnostics {
				if d.Code == "import.unsupported-field" && strings.HasSuffix(d.Path, "/"+tc.key) {
					matches++
				}
			}
			if matches != 1 {
				t.Fatal(r.Report.Diagnostics)
			}
		})
	}
}

func TestAnyTLSShareLinks(t *testing.T) {
	pin := strings.Repeat("42", 32)
	for _, tc := range []struct {
		link, name, password, sni, pin string
		insecure                       bool
	}{
		{"anytls://test%3Apassword@node.test:443?sni=cover.test&insecure=1&hpkp=" + pin + "#AnyTLS%20example", "AnyTLS example", "test:password", "cover.test", pin, true},
		{"anytls://unused:test-password@node.test:443?insecure=true", "node.test:443", "test-password", "node.test", "", false},
	} {
		r := Import(request(tc.link))
		if !r.Report.CanApply {
			t.Fatal(r.Report)
		}
		out := compileImport(t, r).Outbounds[0]
		if out.Type != "anytls" || out.Name != tc.name || out.Server != "node.test" || out.Port != 443 || !out.UDP || out.Password != tc.password {
			t.Fatal("AnyTLS link endpoint or credentials changed during conversion")
		}
		if tls := out.TLS; tls == nil || tls.ServerName != tc.sni || tls.Insecure != tc.insecure || tls.CertificatePin != tc.pin {
			t.Fatal("AnyTLS link TLS options changed during conversion")
		}
		if preview := r.Preview(false); preview.Masked != 1 || strings.Contains(preview.Sources, tc.password) {
			t.Fatal("AnyTLS link password was exposed in preview")
		}
	}
	for _, link := range []string{
		"anytls://test-password@node.test:443?unknown=true",
		"anytls://test-password@node.test:443?sni=one.test&sni=two.test",
		"anytls://test-password@node.test:443?hpkp=invalid",
		"anytls://test-password@node.test",
		"anytls://node.test:443",
		"anytls://@node.test:443",
	} {
		if r := Import(request(link)); r.Report.CanApply || r.Report.Nodes.Unavailable != 1 {
			t.Fatal("invalid AnyTLS link was accepted")
		}
	}
}
