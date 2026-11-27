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
  - {name: Main, type: select, proxies: [Node A, Node B], icon: "https://icons.example.test/main.png"}
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
	if mainGroup.Icon != "https://icons.example.test/main.png" || services.Icon != "" {
		t.Fatalf("group icons = %q, %q", mainGroup.Icon, services.Icon)
	}
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

func TestControlsPinURLTestMembers(t *testing.T) {
	base, diagnostics := compile.Compile([]byte(`
schema-version: 1
outbounds:
  - {id: primary, name: Primary Node, type: direct}
  - {id: alternate, name: Alternate Node, type: direct}
groups:
  - {id: automatic, name: Automatic Group, type: url-test, members: [primary, alternate]}
  - {id: configured, type: url-test, members: [primary, alternate], selected: primary}
  - {id: fallback, type: fallback, members: [primary, alternate]}
  - {id: balanced, type: load-balance, members: [primary, alternate]}
  - {id: manual, type: select, members: [primary, alternate], selected: primary}
`), nil, compile.Options{})
	if diagnostics.HasErrors() {
		t.Fatal(diagnostics)
	}
	summary := Describe(base)
	for _, tc := range []struct {
		name       string
		pins       map[string]string
		automatic  string
		configured string
	}{
		{"IDs", map[string]string{"automatic": "alternate", "configured": "alternate"}, "alternate", "alternate"},
		{"display names", map[string]string{"Automatic Group": "Alternate Node"}, "alternate", "primary"},
		{"group ID takes precedence", map[string]string{"automatic": "primary", "Automatic Group": "Alternate Node"}, "primary", "primary"},
		{"unknown member", map[string]string{"automatic": "missing"}, "", "primary"},
		{"member outside group", map[string]string{"configured": "direct"}, "", "primary"},
		{"other group types", map[string]string{"fallback": "alternate", "balanced": "alternate", "manual": "alternate"}, "", "primary"},
		{"cleared", nil, "", "primary"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			eff, err := ApplyControls(base, summary, Controls{Pins: tc.pins})
			if err != nil {
				t.Fatal(err)
			}
			want := map[string]string{
				"automatic": tc.automatic, "configured": tc.configured, "fallback": "", "balanced": "",
			}
			selected := make(map[string]string, len(eff.AutoGroups))
			for _, group := range eff.AutoGroups {
				selected[group.ID] = group.Selected
			}
			if !reflect.DeepEqual(selected, want) {
				t.Errorf("automatic selections = %v, want %v", selected, want)
			}
			for _, group := range eff.Groups {
				if group.ID == "manual" && group.Selected != "primary" {
					t.Errorf("manual selection changed to %q", group.Selected)
				}
			}
			if base.AutoGroups[0].Selected != "" || base.AutoGroups[1].Selected != "primary" {
				t.Fatal("controls modified the base automatic groups")
			}
		})
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
	fromProfile.Routing.UDPFallback = "direct"
	fromProfile.Routing.DNSFailure = "final"
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
		{"control uses per-policy", &fromProfile, "per-policy", "per-policy"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			updated, err := ApplyControls(tt.base, bundle.Summary, Controls{Mode: "rule", BlockQUIC: tt.control})
			if err != nil {
				t.Fatal(err)
			}
			if updated.Routing.BlockQUIC != tt.want {
				t.Fatalf("block-quic = %q, want %q", updated.Routing.BlockQUIC, tt.want)
			}
			// Controls keep the profile's other routing options.
			if got := updated.Routing; got.UDPFallback != tt.base.Routing.UDPFallback || got.DNSFailure != tt.base.Routing.DNSFailure {
				t.Fatalf("routing = %+v, want options from %+v", got, tt.base.Routing)
			}
		})
	}
	if _, err := ApplyControls(eff, bundle.Summary, Controls{Mode: "rule", BlockQUIC: "sometimes"}); err == nil {
		t.Fatal("invalid QUIC blocking mode was accepted")
	}
}

func TestControlsProcessMode(t *testing.T) {
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
	fromProfile.Process.Mode = "off"
	for _, tt := range []struct {
		name    string
		base    *compile.Effective
		control string
		want    string
	}{
		{"default", eff, "", "rule"},
		{"profile value kept", &fromProfile, "", "off"},
		{"control overrides profile", &fromProfile, "always", "always"},
		{"control restores rule", &fromProfile, "rule", "rule"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			updated, err := ApplyControls(tt.base, bundle.Summary, Controls{Mode: "rule", ProcessMode: tt.control})
			if err != nil {
				t.Fatal(err)
			}
			if updated.Process.Mode != tt.want {
				t.Fatalf("process mode = %q, want %q", updated.Process.Mode, tt.want)
			}
		})
	}
	if _, err := ApplyControls(eff, bundle.Summary, Controls{Mode: "rule", ProcessMode: "sometimes"}); err == nil {
		t.Fatal("invalid process mode was accepted")
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
