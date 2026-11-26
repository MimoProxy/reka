package compile

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/MimoProxy/reka/internal/config/model"
	"github.com/MimoProxy/reka/internal/router"
)

const wireGuardLinkProfile = wireGuardProfile + `      allowed-ips: [10.0.0.0/24, '2001:db8:1::/48']
  - {id: fallback, type: direct}
rules:
  - {id: link-wireguard-0, match: {ip-cidr: 10.0.0.0/8, no-resolve: true}, outbound: reject}
  - {id: final, match: {all: true}, outbound: reject}
`

const wireGuardLinkLocal = `link:
  wireguard:
    - outbound: tunnel
`

func TestWireGuardLinkRuleOrderAndModes(t *testing.T) {
	for _, tc := range []struct {
		mode, localOutbound, otherOutbound string
	}{
		{"rule", "tunnel", "reject"},
		{"global", "tunnel", "fallback"},
		{"direct", "direct", "direct"},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			local := wireGuardLinkLocal + fmt.Sprintf("routing: {mode: %s, global: fallback}\n", tc.mode)
			eff, ds := Compile([]byte(wireGuardLinkProfile), []byte(local), Options{})
			if eff == nil || ds.HasErrors() {
				t.Fatal(ds)
			}
			for _, ip := range []string{"10.0.0.10", "2001:db8:1::1"} {
				decision := eff.RoutingRouter().Explain(t.Context(), router.Metadata{Addr: netip.MustParseAddr(ip)}, nil)
				if decision.Outbound != tc.localOutbound {
					t.Fatalf("route for %s = %+v, want %q", ip, decision, tc.localOutbound)
				}
				if tc.mode != "direct" && (decision.RuleIndex != 0 || decision.Rule.Kind != router.KindIPCIDR || !decision.Rule.NoResolve) {
					t.Fatalf("expected the WireGuard IP rule first, got %+v", decision)
				}
			}
			decision := eff.RoutingRouter().Route(t.Context(), router.Metadata{Addr: netip.MustParseAddr("10.1.0.10")}, nil)
			if decision.Outbound != tc.otherOutbound {
				t.Fatalf("route outside the WireGuard prefixes = %+v, want %q", decision, tc.otherOutbound)
			}
			if tc.mode == "rule" && decision.Rule.ID != "link-wireguard-0" {
				t.Fatalf("profile rule lost its ID or order: %+v", decision)
			}
			env := &noRuleLookup{}
			decision = eff.RoutingRouter().Route(t.Context(), router.Metadata{Domain: "host.example.com"}, env)
			if env.calls != 0 || decision.Outbound != tc.otherOutbound {
				t.Fatalf("domain-only route = %+v with %d lookups", decision, env.calls)
			}
		})
	}
}

func TestWireGuardLinkRuleProvenance(t *testing.T) {
	eff, ds := Compile([]byte(wireGuardLinkProfile), []byte(wireGuardLinkLocal), Options{})
	if eff == nil || ds.HasErrors() {
		t.Fatal(ds)
	}
	if len(eff.Rules) != 3 || len(eff.RuleIDs) != 3 || len(eff.RuleDescriptions) != 3 {
		t.Fatalf("unexpected rule metadata: %v %v %v", eff.Rules, eff.RuleIDs, eff.RuleDescriptions)
	}
	generated := eff.Rules[0]
	if generated.ID == "" || generated.ID == eff.Rules[1].ID || generated.ID != eff.RuleIDs[0] {
		t.Fatalf("generated rule ID collided with or diverged from profile metadata: %v", eff.RuleIDs)
	}
	const localPath = "/link/wireguard/#0"
	origin, ok := eff.OriginOf(model.JoinPath("/rules", generated.ID))
	if !ok || origin.Layer != LayerLocal || origin.Document != model.DocLocal || origin.Path != localPath || origin.Line != 3 || origin.Column == 0 {
		t.Fatalf("unexpected generated rule origin: %+v", origin)
	}
	if description := eff.RuleDescriptions[0]; !strings.Contains(description, "local.yaml") || !strings.Contains(description, localPath) {
		t.Fatalf("expected local location in the generated rule description, got %q", description)
	}
	profile := strings.Replace(wireGuardLinkProfile, "id: link-wireguard-0", fmt.Sprintf("id: %q", generated.ID), 1)
	if eff, ds = Compile([]byte(profile), []byte(wireGuardLinkLocal), Options{}); eff != nil || !ds.HasErrors() {
		t.Fatalf("profile rule could claim generated rule ID %q: %v", generated.ID, ds)
	}
}

func TestWireGuardLinkKeepsAnonymousProfileRuleOrigins(t *testing.T) {
	profile := strings.NewReplacer("id: link-wireguard-0, ", "", "id: final, ", "").Replace(wireGuardLinkProfile)
	eff, ds := Compile([]byte(profile), []byte(wireGuardLinkLocal), Options{})
	if eff == nil || ds.HasErrors() {
		t.Fatal(ds)
	}
	for i := range 2 {
		oldPath := fmt.Sprintf("/rules/#%d/outbound", i)
		newPath := fmt.Sprintf("/rules/#%d/outbound", i+1)
		origin, ok := eff.OriginOf(newPath)
		if !ok || origin.Layer != LayerProfile || origin.Document != model.DocProfile || origin.Path != oldPath || origin.Line == 0 {
			t.Fatalf("profile rule at %s lost its origin at %s: %+v", newPath, oldPath, origin)
		}
	}
}

func TestWireGuardLinkRoutesToSourceOutbound(t *testing.T) {
	profile := `schema-version: 1
imports: [{source: peers, outbounds: true}]
`
	sources := `schema-version: 1
sources:
  - id: peers
    outbounds:
`
	for _, line := range strings.SplitAfter(strings.TrimPrefix(wireGuardProfile, "schema-version: 1\noutbounds:\n"), "\n") {
		if line != "" {
			sources += "    " + line
		}
	}
	local := `link:
  wireguard:
    - outbound: peers/tunnel
      routes: [10.0.0.0/24]
`
	eff, ds := Compile([]byte(profile), []byte(local), Options{Sources: []byte(sources)})
	if eff == nil || ds.HasErrors() {
		t.Fatal(ds)
	}
	for _, tc := range []struct{ addr, want string }{
		{"10.0.0.10", "peers/tunnel"},
		{"192.0.2.10", "direct"},
		{"2001:db8::1", "direct"},
	} {
		got := eff.RoutingRouter().Route(t.Context(), router.Metadata{Addr: netip.MustParseAddr(tc.addr)}, nil)
		if got.Outbound != tc.want {
			t.Fatalf("route for %s = %q, want %q", tc.addr, got.Outbound, tc.want)
		}
	}
}

func TestWireGuardLinkMissingOutbound(t *testing.T) {
	local := strings.Replace(wireGuardLinkLocal, "    - outbound: tunnel", "    - outbound: missing\n    - outbound: tunnel", 1)
	eff, ds := Compile([]byte(wireGuardLinkProfile), []byte(local), Options{})
	if eff == nil || ds.HasErrors() {
		t.Fatal(ds)
	}
	if len(ds) != 1 || ds[0].Severity != model.SeverityWarning || ds[0].Document != model.DocLocal || ds[0].Path != "/link/wireguard/#0/outbound" || ds[0].Line != 3 || !strings.Contains(ds[0].Message, "missing") {
		t.Fatalf("expected a warning for the missing outbound: %v", ds)
	}
	if len(eff.Rules) != 3 || eff.Rules[0].Target != "tunnel" {
		t.Fatalf("missing outbound affected valid rules: %v", eff.Rules)
	}
	origin, ok := eff.OriginOf(model.JoinPath("/rules", eff.Rules[0].ID))
	if !ok || origin.Path != "/link/wireguard/#1" || origin.Line != 4 {
		t.Fatalf("skipped entry shifted the generated rule origin: %+v", origin)
	}
}

func TestWireGuardLinkValidation(t *testing.T) {
	for _, tc := range []struct {
		name, entry, path string
	}{
		{"invalid CIDR", "{outbound: tunnel, routes: [10.0.0.1]}", "/#0/routes/#0"},
		{"IPv4 default route", "{outbound: tunnel, routes: [0.0.0.0/0]}", "/#0/routes/#0"},
		{"IPv6 default route", "{outbound: tunnel, routes: ['::/0']}", "/#0/routes/#0"},
		{"IPv4 loopback", "{outbound: tunnel, routes: [127.0.0.0/8]}", "/#0/routes/#0"},
		{"overlapping loopback", "{outbound: tunnel, routes: [126.0.0.0/7]}", "/#0/routes/#0"},
		{"IPv6 loopback", "{outbound: tunnel, routes: ['::1/128']}", "/#0/routes/#0"},
		{"IPv4 link local", "{outbound: tunnel, routes: [169.254.0.0/16]}", "/#0/routes/#0"},
		{"IPv6 link local", "{outbound: tunnel, routes: ['fe80::/10']}", "/#0/routes/#0"},
		{"IPv4 multicast", "{outbound: tunnel, routes: [224.0.0.0/4]}", "/#0/routes/#0"},
		{"IPv6 multicast", "{outbound: tunnel, routes: ['ff00::/8']}", "/#0/routes/#0"},
		{"IPv4-mapped loopback", "{outbound: tunnel, routes: ['::ffff:127.0.0.0/104']}", "/#0/routes/#0"},
		{"outbound required", "{}", "/#0"},
		{"other outbound type", "{outbound: fallback}", "/#0/outbound"},
		{"duplicate outbound", "{outbound: tunnel}\n    - {outbound: tunnel}", "/#1/outbound"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			local := "link:\n  wireguard:\n    - " + tc.entry + "\n"
			eff, ds := Compile([]byte(wireGuardLinkProfile), []byte(local), Options{})
			want := "/link/wireguard" + tc.path
			if eff != nil || !slices.ContainsFunc(ds.Errors(), func(d model.Diagnostic) bool {
				return d.Document == model.DocLocal && d.Path == want && d.Line > 0 && d.Column > 0
			}) {
				t.Fatalf("expected a local error at %s: %v", want, ds)
			}
		})
	}
}

func TestWireGuardLinkRequiresExplicitRoutesForDefaultAllowedIPs(t *testing.T) {
	for _, allowed := range []string{"", "      allowed-ips: [0.0.0.0/0]\n", "      allowed-ips: ['::/0']\n"} {
		profile := wireGuardProfile + allowed
		eff, ds := Compile([]byte(profile), []byte(wireGuardLinkLocal), Options{})
		if eff != nil || !slices.ContainsFunc(ds.Errors(), func(d model.Diagnostic) bool {
			return d.Document == model.DocLocal && strings.HasPrefix(d.Path, "/link/wireguard/#0") && strings.Contains(d.Message, "routes")
		}) {
			t.Fatalf("expected an explicit routes error for allowed-ips %q: %v", allowed, ds)
		}
		local := wireGuardLinkLocal + "      routes: [10.0.0.0/24]\n"
		eff, ds = Compile([]byte(profile), []byte(local), Options{})
		if eff == nil || ds.HasErrors() || len(eff.Rules) != 1 || !slices.Equal(eff.Rules[0].Values, []string{"10.0.0.0/24"}) {
			t.Fatalf("explicit routes did not override allowed-ips %q: %v", allowed, ds)
		}
	}
}

func TestWireGuardLinkEmptyRoutesDoesNotInherit(t *testing.T) {
	for _, routes := range []string{"[]", "null"} {
		local := wireGuardLinkLocal + "      routes: " + routes + "\n"
		eff, ds := Compile([]byte(wireGuardProfile), []byte(local), Options{})
		if eff == nil || ds.HasErrors() || len(eff.Rules) != 0 {
			t.Fatalf("empty routes inherited the defaults for %s: %v", routes, ds)
		}
	}
}

func TestWireGuardLinkLimit(t *testing.T) {
	var local strings.Builder
	local.WriteString("link:\n  wireguard:\n")
	for i := range 64 {
		fmt.Fprintf(&local, "    - outbound: optional-%d\n", i)
	}
	if eff, ds := Compile([]byte(wireGuardLinkProfile), []byte(local.String()), Options{}); eff == nil || ds.HasErrors() {
		t.Fatalf("limit of 64 entries was rejected: %v", ds)
	}
	local.WriteString("    - outbound: tunnel\n")
	eff, ds := Compile([]byte(wireGuardLinkProfile), []byte(local.String()), Options{})
	if eff != nil || !slices.ContainsFunc(ds.Errors(), func(d model.Diagnostic) bool {
		return d.Document == model.DocLocal && d.Path == "/link/wireguard" && strings.Contains(d.Message, "64")
	}) {
		t.Fatalf("expected a local error for exceeding the entry limit: %v", ds)
	}
}

func TestWireGuardLinkRuleFingerprint(t *testing.T) {
	seen := make(map[string]bool)
	for _, local := range []string{
		"",
		wireGuardLinkLocal,
		wireGuardLinkLocal + "      routes: [10.0.0.0/25]\n",
	} {
		eff, ds := Compile([]byte(wireGuardLinkProfile), []byte(local), Options{})
		if eff == nil || ds.HasErrors() {
			t.Fatal(ds)
		}
		if eff.RulesFingerprint == "" || seen[eff.RulesFingerprint] {
			t.Fatalf("link edit kept the rule fingerprint for local settings %q", local)
		}
		seen[eff.RulesFingerprint] = true
	}
}
