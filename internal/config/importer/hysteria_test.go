package importer

import (
	"slices"
	"strings"
	"testing"
)

func TestHysteriaClashNode(t *testing.T) {
	pin := strings.Repeat("42", 32)
	r := Import(request(`proxies:
 - name: Hysteria example
   type: hysteria
   server: 192.0.2.8
   ports: '443, 9002-9000'
   hop_interval: 7
   up: 1234567 Bps
   down: 1500 Kbps
   auth: '/wAB'
   auth_str: discarded-auth
   obfs: xplus-password
   protocol: wechat-video
   obfs_protocol: udp
   udp: false
   fast_open: false
   recv_window: 7654321
   recv_window_conn: 2345678
   disable_mtu_discovery: true
   sni: cover.test
   skip_cert_verify: true
   name_cert_verify: cert.test
   fingerprint: '` + pin + `'
   alpn: [custom, hysteria]
   ech_opts: {enable: true, query_server_name: ech.test}
   ca: unused-file
   ca-str: unused-ca
   interface_name: test-interface
   dialer_proxy: DIRECT
`))
	if !r.Report.CanApply || r.Report.Partial {
		t.Fatal(r.Report)
	}
	out := compileImport(t, r).Outbounds[0]
	if out.Type != "hysteria" || out.Name != "Hysteria example" || out.Server != "192.0.2.8" || out.Port != 0 || out.Password != "" || out.UDP {
		t.Fatal("Hysteria endpoint or authentication changed during conversion")
	}
	p := out.Protocol
	if p == nil || p.AuthBase64 != "/wAB" || p.UpBPS == nil || *p.UpBPS != 1234567 || p.DownBPS == nil || *p.DownBPS != 187500 {
		t.Fatal("Hysteria binary auth or exact bandwidth changed during conversion")
	}
	if p.Obfs == nil || p.Obfs.Type != "xplus" || p.Obfs.Password != "xplus-password" || p.StreamReceiveWindow != 2345678 || p.ConnectionReceiveWindow != 7654321 || !p.DisableMTUDiscovery {
		t.Fatal("Hysteria obfuscation, window or MTU settings changed during conversion")
	}
	if !slices.Equal(p.ServerPorts, []string{"443:443", "9000:9002"}) || p.HopInterval != 7 || p.HopIntervalMax != 0 {
		t.Fatal("Hysteria hop ports or interval changed during conversion")
	}
	if tls := out.TLS; tls == nil || tls.ServerName != "cover.test" || !tls.Insecure || tls.VerifyName != "cert.test" || tls.CertificatePin != pin || tls.Fingerprint != "" ||
		!slices.Equal(tls.ALPN, []string{"custom", "hysteria"}) || tls.ECH == nil || !tls.ECH.Enabled || tls.ECH.QueryServerName != "ech.test" {
		t.Fatal("Hysteria TLS options changed during conversion")
	}
	if d := out.Dialer; d == nil || d.Interface != "test-interface" || d.Proxy != "direct" {
		t.Fatal("Hysteria dialer options changed during conversion")
	}
	for _, key := range []string{"auth-str", "ca", "ca-str", "protocol"} {
		if !slices.Contains(r.Report.Ignored, "/proxies/#0/"+key) {
			t.Fatalf("ignored field %s missing from %v", key, r.Report.Ignored)
		}
	}
	if preview := r.Preview(false); preview.Masked != 2 || strings.Contains(preview.Sources, "/wAB") || strings.Contains(preview.Sources, "xplus-password") || strings.Contains(preview.Sources, "discarded-auth") {
		t.Fatal("Hysteria import preview exposed credentials")
	}
}

func TestHysteriaClashDefaultsAndOverrides(t *testing.T) {
	node := "proxies: [{name: node, type: hysteria, server: node.test, port: 443, up: 1, down: 17 KBps"
	for _, extra := range []string{"", ", recv-window: 0"} {
		r := Import(request(node + ", auth-str: test-password, recv-window-conn: 128000, hop-interval: 9, fast-open: true, tls: false" + extra + "}]"))
		if !r.Report.CanApply {
			t.Fatal(r.Report)
		}
		out := compileImport(t, r).Outbounds[0]
		p := out.Protocol
		if !out.UDP || out.Password != "test-password" || out.TLS == nil || out.TLS.ServerName != out.Server || out.TLS.Insecure || len(out.TLS.ALPN) != 0 {
			t.Fatal("incorrect imported Hysteria defaults")
		}
		if p.AuthBase64 != "" || p.ConnectionReceiveWindow != 0 || p.StreamReceiveWindow != 0 || p.HopInterval != 0 || *p.UpBPS != 125000 || *p.DownBPS != 17000 {
			t.Fatal("Hysteria window or rate defaults changed")
		}
		for _, key := range []string{"recv-window-conn", "hop-interval"} {
			if !slices.Contains(r.Report.Ignored, "/proxies/#0/"+key) {
				t.Fatalf("ignored field %s missing from %v", key, r.Report.Ignored)
			}
		}
	}
	for _, extra := range []string{"", ", hop-interval: 0"} {
		r := Import(request(node + ", ports: 8443, up-speed: 2, down-speed: 3" + extra + "}]"))
		if !r.Report.CanApply {
			t.Fatal(r.Report)
		}
		out := compileImport(t, r).Outbounds[0]
		if p := out.Protocol; p.HopInterval != 10 || !slices.Equal(p.ServerPorts, []string{"8443:8443"}) || *p.UpBPS != 250000 || *p.DownBPS != 375000 || out.Password != "" || p.AuthBase64 != "" {
			t.Fatal("Hysteria hop default, anonymous auth or speed overrides changed")
		}
	}
}

func TestHysteriaClashRejectsInvalidOptions(t *testing.T) {
	node := "proxies: [{name: node, type: hysteria, server: node.test, port: 443, "
	for _, tc := range []struct{ fields, field, code string }{
		{"up: 1", "down", "import.bandwidth"},
		{"down: 1, up-speed: 1", "up", "import.bandwidth"},
		{"up: 1, down: bad, down-speed: 2", "down", "import.bandwidth"},
		{"up: 16383 Bps, down: 1", "up", "import.bandwidth"},
		{"up: 1, down: 1, up-speed: -1", "up-speed", "import.bandwidth"},
		{"up: 1, down: 1, auth: '__8='", "auth", "import.hysteria.auth"},
		{"up: 1, down: 1, protocol: faketcp", "protocol", "import.unsupported-field"},
		{"up: 1, down: 1, protocol: wechat-video", "protocol", "import.unsupported-field"},
		{"up: 1, down: 1, protocol: udp, obfs_protocol: unknown", "obfs-protocol", "import.unsupported-field"},
		{"up: 1, down: 1, ports: 65536", "ports", "import.ports"},
		{"up: 1, down: 1, ports: 8443, hop-interval: 5-10", "hop-interval", "import.type"},
		{"up: 1, down: 1, ports: 8443, hop-interval: null", "hop-interval", "import.type"},
		{"up: 1, down: 1, fast-open: wrong", "fast-open", "import.type"},
		{"up: 1, down: 1, fast-open: null", "fast-open", "import.type"},
		{"up: 1, down: 1, disable-mtu-discovery: wrong", "disable-mtu-discovery", "import.type"},
		{"up: 1, down: 1, disable-mtu-discovery: null", "disable-mtu-discovery", "import.type"},
		{"up: 1, down: 1, auth-str: plain, auth_str: other", "auth_str", "import.duplicate-key"},
		{"up: 1, down: 1, ech-opts: {query_server_name: public.test, query-server-name: example.test}", "query-server-name", "import.duplicate-key"},
		{"up: 1, down: 1, smux: {enabled: false}", "smux", "import.unsupported-field"},
		{"up: 1, down: 1, other: 1", "other", "import.unsupported-field"},
	} {
		t.Run(tc.fields, func(t *testing.T) {
			r := Import(request(node + tc.fields + "}]"))
			if r.Report.CanApply {
				t.Fatal("invalid Hysteria option imported")
			}
			for _, d := range r.Report.Diagnostics {
				if strings.HasSuffix(d.Path, "/"+tc.field) && d.Code == tc.code {
					if (tc.field == "protocol" || tc.field == "obfs-protocol") && !strings.Contains(d.Message, "only supports udp") {
						t.Fatal(d)
					}
					return
				}
			}
			t.Fatal(r.Report.Diagnostics)
		})
	}
	other := Import(request("proxies: [{name: other, type: anytls, server: node.test, port: 443, password: test-password, skip_cert_verify: true}]"))
	if other.Report.CanApply {
		t.Fatal("underscore option aliases must be scoped to Hysteria")
	}
}

func TestHysteriaShareLinks(t *testing.T) {
	for _, tc := range []struct {
		rates, insecure string
		up, down        uint64
		wantInsecure    bool
	}{
		{"upmbps=2&downmbps=3", "TRUE", 250000, 375000, true},
		{"up=17654+Bps&upmbps=2&down=44+KBps&downmbps=3", "0", 17654, 44000, false},
	} {
		r := Import(request("hysteria://[2001:db8::1]:444/?peer=cover.test&auth=url%3Apassword&obfs=obfs-secret&protocol=udp&alpn=custom,hysteria&insecure=" + tc.insecure + "&" + tc.rates + "#Hysteria%20example"))
		if !r.Report.CanApply {
			t.Fatal(r.Report)
		}
		out := compileImport(t, r).Outbounds[0]
		if out.Type != "hysteria" || out.Server != "2001:db8::1" || out.Port != 444 || out.Name != "Hysteria example" || out.Password != "url:password" || !out.UDP {
			t.Fatal("Hysteria share-link endpoint or auth changed")
		}
		if tls := out.TLS; tls == nil || tls.ServerName != "cover.test" || tls.Insecure != tc.wantInsecure || !slices.Equal(tls.ALPN, []string{"custom", "hysteria"}) {
			t.Fatal("Hysteria share-link TLS settings changed")
		}
		if p := out.Protocol; p == nil || *p.UpBPS != tc.up || *p.DownBPS != tc.down || p.Obfs == nil || p.Obfs.Type != "xplus" || p.Obfs.Password != "obfs-secret" {
			t.Fatal("Hysteria share-link rates or obfs changed")
		}
	}
	for _, query := range []string{"up=1", "up=1&down=2&unknown=true", "up=1&up=3&down=2"} {
		if r := Import(request("hysteria://node.test:443?" + query + "#test")); r.Report.CanApply {
			t.Fatal("invalid Hysteria share link imported")
		}
	}
}

func TestHysteriaProviderKeepsExactBandwidth(t *testing.T) {
	r := Import(request(`proxy-providers:
 local:
  type: inline
  payload: [{name: node, type: hysteria, server: node.test, port: 443, up: '9007199254740993 Bps', down: 1}]
proxy-groups: [{name: choice, type: select, use: [local]}]
`))
	if !r.Report.CanApply {
		t.Fatal(r.Report)
	}
	if rate := compileImport(t, r).Outbounds[0].Protocol.UpBPS; rate == nil || *rate != 9007199254740993 {
		t.Fatal("provider conversion rounded the exact Hysteria bandwidth")
	}
}

func TestHysteriaProviderOverridesUnderscoreOption(t *testing.T) {
	node := "{name: node, type: hysteria, server: node.test, port: 443, up: 1, down: 1, skip_cert_verify: false}"
	for _, kind := range []string{"inline", "http"} {
		t.Run(kind, func(t *testing.T) {
			provider := "proxy-providers:\n local:\n  type: " + kind + "\n  override: {skip-cert-verify: true}\n"
			if kind == "http" {
				provider += "  url: https://nodes.test/list\n"
			} else {
				provider += "  payload: [" + node + "]\n"
			}
			req := request(provider + "proxy-groups: [{name: choice, type: select, use: [local]}]")
			importNode := func(req Request, node string) Result {
				t.Helper()
				if kind == "inline" {
					return Import(req)
				}
				ps, err := Providers(req)
				if err != nil || len(ps) != 1 {
					t.Fatalf("invalid provider: %v", err)
				}
				return ImportProviders(req, map[string][]byte{ps[0].ID: []byte("proxies: [" + node + "]")})
			}
			r := importNode(req, node)
			if !r.Report.CanApply {
				t.Fatal(r.Report)
			}
			if tls := compileImport(t, r).Outbounds[0].TLS; tls == nil || !tls.Insecure {
				t.Fatal("provider override did not replace the Hysteria option")
			}
			duplicate := strings.Replace(node, "skip_cert_verify: false", "skip_cert_verify: false, skip-cert-verify: false", 1)
			req.Data = strings.Replace(req.Data, node, duplicate, 1)
			if importNode(req, duplicate).Report.CanApply {
				t.Fatal("provider override concealed duplicate Hysteria options in its payload")
			}
		})
	}
}

func TestHysteriaClashIgnoresClientFingerprint(t *testing.T) {
	r := Import(request("proxies: [{name: node, type: hysteria, server: node.test, port: 443, up: 10, down: 50, client-fingerprint: chrome}]"))
	if !r.Report.CanApply {
		t.Fatal(r.Report)
	}
	if out := compileImport(t, r).Outbounds[0]; out.TLS == nil || out.TLS.Fingerprint != "" {
		t.Fatal("client-fingerprint must not reach the QUIC TLS config")
	}
	found := false
	for _, d := range r.Report.Diagnostics {
		found = found || d.Code == "import.ignored-field" && strings.HasSuffix(d.Path, "/client-fingerprint")
	}
	if !found {
		t.Fatal(r.Report.Diagnostics)
	}
}
