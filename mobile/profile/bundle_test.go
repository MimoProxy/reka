package profile

import (
	"context"
	"fmt"
	"reflect"
	"testing"

	"github.com/MimoProxy/reka/internal/config/compile"
	"github.com/MimoProxy/reka/internal/config/model"
	"github.com/MimoProxy/reka/internal/router"
)

func TestClashProfileControlsUseCompiledRules(t *testing.T) {
	raw := []byte(`
proxies:
  - {name: Node A, type: ss, server: a.example.test, port: 443, cipher: aes-128-gcm, password: example-a}
  - {name: Node B, type: ss, server: b.example.test, port: 443, cipher: aes-128-gcm, password: example-b}
proxy-groups:
  - {name: Main, type: select, proxies: [Node A, Node B]}
  - {name: Services, type: select, proxies: [Main, DIRECT]}
rules:
  - DOMAIN-SUFFIX,local.example.test,DIRECT
  - DOMAIN-SUFFIX,example.test,Services
  - MATCH,Main
`)
	ctx := context.Background()
	bundle, err := prepare(ctx, raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	eff, err := bundle.Compile()
	if err != nil {
		t.Fatal(err)
	}
	summary, ruleSet := bundle.Summary, eff.Router.Rules()
	mainGroup, services := summary.Groups[0], summary.Groups[1]
	updated, err := ApplyControls(eff, summary, Controls{Mode: "rule", Selections: map[string]string{"Main": "Node B"}})
	if err != nil {
		t.Fatal(err)
	}
	if updated.Router.Rules() != ruleSet {
		t.Fatal("selection rebuilt the rule index")
	}
	decision := updated.RoutingRouter().Route(ctx, router.Metadata{Domain: "service.example.test", Network: "tcp"}, nil)
	if decision.Target != services.ID || decision.Outbound != mainGroup.Members[1] {
		t.Fatalf("selection not applied: %#v", decision)
	}
	decision = updated.RoutingRouter().Route(ctx, router.Metadata{Domain: "host.local.example.test", Network: "tcp"}, nil)
	if decision.Outbound != "direct" {
		t.Fatalf("first matching rule lost priority: %#v", decision)
	}
}

func TestControlsBlockQUIC(t *testing.T) {
	raw := []byte(`
proxies:
  - {name: Node A, type: ss, server: a.example.test, port: 443, cipher: aes-128-gcm, password: example-a}
rules:
  - MATCH,Node A
`)
	bundle, err := prepare(context.Background(), raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	eff, err := bundle.Compile()
	if err != nil {
		t.Fatal(err)
	}
	fromProfile := *eff
	fromProfile.Routing.BlockQUIC = "proxy"
	for _, tt := range []struct {
		name    string
		base    *compile.Effective
		control string
		want    string
	}{
		{"default", eff, "", "off"},
		{"profile value kept", &fromProfile, "", "proxy"},
		{"control overrides profile", &fromProfile, "all", "all"},
		{"control turns it off", &fromProfile, "off", "off"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			updated, err := ApplyControls(tt.base, bundle.Summary, Controls{Mode: "rule", BlockQUIC: tt.control})
			if err != nil {
				t.Fatal(err)
			}
			if updated.Routing.BlockQUIC != tt.want {
				t.Fatalf("block-quic = %q, want %q", updated.Routing.BlockQUIC, tt.want)
			}
		})
	}
	if _, err := ApplyControls(eff, bundle.Summary, Controls{Mode: "rule", BlockQUIC: "sometimes"}); err == nil {
		t.Fatal("invalid QUIC blocking mode was accepted")
	}
}

func TestControlsIPVersion(t *testing.T) {
	const input = `
schema-version: 1
outbounds:
  - {id: configured, type: shadowsocks, server: proxy.test, port: 443, method: aes-128-gcm, password: example, dialer: {ip-version: ipv6-prefer, tfo: true}}
  - {id: plain, type: shadowsocks, server: proxy.test, port: 443, method: aes-128-gcm, password: example}
  - {id: detoured, type: direct, dialer: {proxy: plain}}
groups: [{id: main, type: select, members: [configured, plain, detoured], selected: configured}]
routing: {mode: rule, global: main}
rules: [{match: {all: true}, outbound: main}]
dns: {ipv6: %t, nameserver: [192.0.2.53]}
`
	for _, baseIPv6 := range []bool{false, true} {
		t.Run(fmt.Sprintf("profile IPv6 %t", baseIPv6), func(t *testing.T) {
			bundle, err := prepare(t.Context(), []byte(fmt.Sprintf(input, baseIPv6)), nil)
			if err != nil {
				t.Fatal(err)
			}
			base, err := bundle.Compile()
			if err != nil {
				t.Fatal(err)
			}
			original, err := bundle.Compile()
			if err != nil {
				t.Fatal(err)
			}
			for _, tc := range []struct {
				name, control, policy string
				ipv6                  bool
			}{
				{"follow profile", "", "", baseIPv6},
				{"dual", "dual", "", true},
				{"ipv4", "ipv4", "ipv4", false},
				{"ipv6", "ipv6", "ipv6", true},
				{"ipv4-prefer", "ipv4-prefer", "ipv4-prefer", true},
				{"ipv6-prefer", "ipv6-prefer", "ipv6-prefer", true},
			} {
				t.Run(tc.name, func(t *testing.T) {
					updated, err := ApplyControls(base, bundle.Summary, Controls{IPVersion: tc.control})
					if err != nil {
						t.Fatal(err)
					}
					if !reflect.DeepEqual(base, original) {
						t.Fatal("controls modified the base configuration")
					}
					if tc.control == "" {
						if !reflect.DeepEqual(updated, base) {
							t.Fatal("empty override changed the compiled settings")
						}
						return
					}
					if updated.DNS == nil || updated.DNS == base.DNS || updated.DNS.IPv6 != tc.ipv6 {
						t.Fatalf("expected a copy of DNS config with IPv6 set to %t", tc.ipv6)
					}
					if (base.DNSFingerprint != updated.DNSFingerprint) != (baseIPv6 != tc.ipv6) {
						t.Fatal("DNS fingerprint did not track the IPv6 setting")
					}
					want := map[string]*model.Dialer{
						"configured": {IPVersion: tc.policy, TFO: true},
						"detoured":   {Proxy: "plain"},
						"direct":     nil,
						"plain":      nil,
						"reject":     nil,
					}
					if tc.policy != "" {
						want["direct"] = &model.Dialer{IPVersion: tc.policy}
						want["plain"] = &model.Dialer{IPVersion: tc.policy}
					}
					for id, dialer := range want {
						outbound, ok := updated.Outbound(id)
						if !ok || !reflect.DeepEqual(outbound.Dialer, dialer) {
							t.Errorf("outbound %q dialer = %+v, want %+v", id, outbound.Dialer, dialer)
						}
					}
				})
			}
			if _, err := ApplyControls(base, bundle.Summary, Controls{IPVersion: "invalid"}); err == nil || err.Error() != "unknown IP version policy" {
				t.Fatalf("invalid IP version error = %v", err)
			}
		})
	}
}

func TestControlsIPVersionWithoutDNS(t *testing.T) {
	base, diagnostics := compile.Compile([]byte("schema-version: 1\n"), nil, compile.Options{})
	if diagnostics.HasErrors() {
		t.Fatal(diagnostics)
	}
	updated, err := ApplyControls(base, Describe(base), Controls{IPVersion: "ipv4"})
	if err != nil {
		t.Fatal(err)
	}
	if updated.DNS != nil || updated.DNSFingerprint != base.DNSFingerprint {
		t.Fatal("override changed an absent DNS configuration")
	}
}
