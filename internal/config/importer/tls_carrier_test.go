package importer

import (
	"strings"
	"testing"
)

func TestStandaloneSecurityCarriersAndSecrets(t *testing.T) {
	for _, protocol := range []string{"vless", "vmess", "trojan", "anytls"} {
		for _, tc := range []struct{ key, options, kind string }{
			{"shadow-tls-opts", "version: 3, password: outer-private", "shadow-tls"},
			{"restls-opts", "password: outer-private, version-hint: tls13, restls-script: '100~20'", "restls"},
			{"jls-opts", "username: user-private, password: outer-private", "jls"},
		} {
			credentials := "uuid: b831381d-6324-4d53-ad4f-8cda48b30811"
			if protocol == "trojan" || protocol == "anytls" {
				credentials = "password: inner-secret"
			}
			tls := "tls: true, servername: camo.test"
			if protocol == "anytls" {
				tls = "sni: camo.test"
			}
			input := "proxies: [{name: a, type: " + protocol + ", server: node.test, port: 443, " + tls + ", " + credentials + ", " + tc.key + ": {" + tc.options + "}}]"
			r := Import(request(input))
			if !r.Report.CanApply {
				t.Fatal(protocol, tc.kind, r.Report)
			}
			eff := compileImport(t, r)
			carrier := eff.Outbounds[0].TLS.Carrier
			if carrier == nil || carrier.Type != tc.kind || carrier.Password != "outer-private" {
				t.Fatal("carrier or secret lost", protocol, tc.kind)
			}
			if strings.Contains(r.Preview(false).Sources, "outer-private") || strings.Contains(r.Preview(false).Sources, "user-private") {
				t.Fatal("carrier credential leaked")
			}
			wrong := Import(request(strings.Replace(input, tc.options, tc.options+", unknown: true", 1)))
			if wrong.Report.CanApply {
				t.Fatal("unknown security field accepted")
			}
			if protocol != "anytls" {
				if noTLS := Import(request(strings.Replace(input, "tls: true", "tls: false", 1))); noTLS.Report.CanApply {
					t.Fatal("active security mode accepted without TLS", protocol)
				}
			}
		}
	}
}
func TestSecurityModesConflictAndInactiveOptions(t *testing.T) {
	base := `proxies: [{name: a, type: vless, server: node.test, port: 443, uuid: b831381d-6324-4d53-ad4f-8cda48b30811, tls: true, servername: camo.test, shadow-tls-opts: {password: secret, version: 3}, jls-opts: {username: user, password: secret}}]`
	if Import(request(base)).Report.CanApply {
		t.Fatal("conflicting security modes accepted")
	}
	inactive := strings.Replace(base, "tls: true", "tls: false", 1)
	inactive = strings.Replace(inactive, "password: secret, version: 3", "password: '', version: 0", 1)
	inactive = strings.Replace(inactive, "username: user, password: secret", "username: '', password: ''", 1)
	inactive = strings.Replace(inactive, ", servername: camo.test", "", 1)
	if r := Import(request(inactive)); !r.Report.CanApply {
		t.Fatal("inactive modes changed a plaintext node", r.Report)
	}
}

func TestRealityCertificateFlagIsInertAndReported(t *testing.T) {
	input := strings.Replace(sample, "tls: true", "tls: true, skip-cert-verify: true", 1)
	r := Import(request(input))
	if !r.Report.CanApply {
		t.Fatal(r.Report)
	}
	eff := compileImport(t, r)
	for _, out := range eff.Outbounds {
		if out.TLS != nil && out.TLS.Reality != nil && out.TLS.Insecure {
			t.Fatal("certificate flag disabled REALITY authentication")
		}
	}
	found := false
	for _, d := range r.Report.Diagnostics {
		if d.Code == "import.ignored-field" && strings.HasSuffix(d.Path, "/skip-cert-verify") {
			found = true
		}
	}
	if !found {
		t.Fatal("ignored REALITY certificate flag was not reported")
	}
}
