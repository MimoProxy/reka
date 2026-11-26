package compile

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/MimoProxy/reka/internal/config/model"
	"github.com/MimoProxy/reka/internal/router"
)

const tailscaleLinkLocal = `link:
  tailscale:
    - id: home
`

func TestTailscaleReferencesAndRouting(t *testing.T) {
	const profile = `schema-version: 1
imports: [{source: feed, outbounds: true, groups: true}]
outbounds: [{id: ts, name: Local tailnet, type: tailscale}]
groups:
  - {id: choice, type: select, members: [ts, feed/imported]}
rules:
  - {match: {domain: named.test}, outbound: ts}
  - {match: {domain: group.test}, outbound: choice}
`
	const sources = `sources:
  - id: feed
    outbounds: [{id: imported, type: tailscale, udp: false}]
    groups: [{id: speed, type: url-test, include-all: true}]
`
	for _, local := range []string{"", tailscaleLinkLocal} {
		eff, ds := Compile([]byte(profile), []byte(local), Options{Sources: []byte(sources)})
		if eff == nil || ds.HasErrors() {
			t.Fatal(ds)
		}
		for id, udp := range map[string]bool{"ts": true, "feed/imported": false} {
			out, ok := eff.Outbound(id)
			if !ok || out.Type != model.OutboundTailscale || out.Tailscale != nil || out.UDP != udp || out.Fingerprint == "" {
				t.Errorf("unexpected reference %q: %+v", id, out)
			}
		}
		if !slices.ContainsFunc(eff.Groups, func(g router.Group) bool {
			return g.ID == "feed/speed" && slices.Equal(g.Members, []string{"feed/imported"})
		}) {
			t.Fatalf("url-test did not include its scoped reference: %+v", eff.Groups)
		}
		for _, host := range []string{"named.test", "group.test"} {
			if got := eff.Router.Route(t.Context(), router.Metadata{Domain: host}, nil); got.Outbound != "ts" {
				t.Fatalf("route for %s = %+v", host, got)
			}
		}
		warnings := map[string]string{}
		for _, d := range ds {
			if d.Code == "outbound.tailscale-unavailable" && d.Severity == model.SeverityWarning {
				warnings[d.Path] = d.Document
			}
		}
		if local == "" {
			if warnings["/sources/feed/outbounds/imported/type"] != model.DocSources || warnings["/outbounds/ts/type"] != model.DocProfile {
				t.Fatalf("missing warnings on the declaring documents: %v", ds)
			}
		} else if len(warnings) != 0 {
			t.Fatalf("configured node produced unavailable warnings: %v", ds)
		}
	}
}

func TestTailscaleReferenceRejectsNodeOptions(t *testing.T) {
	for _, config := range []string{"server: localhost", "port: 1234", "tls: {}", "protocol: {}", "transport: {}", "multiplex: {}", "dialer: {}",
		"password: example", "auth-key: example", "control-url: example", "hostname: example", "state-dir: state", "ephemeral: true",
		"accept-routes: true", "exit-node: auto", "exit-node-allow-lan-access: false"} {
		field, _, _ := strings.Cut(config, ":")
		t.Run(field, func(t *testing.T) {
			profile := "schema-version: 1\noutbounds: [{id: ts, type: tailscale, " + config + "}]\n"
			eff, ds := Compile([]byte(profile), nil, Options{})
			if eff != nil || !slices.ContainsFunc(ds.Errors(), func(d model.Diagnostic) bool {
				return d.Document == model.DocProfile && d.Path == "/outbounds/ts/"+field && d.Line == 2
			}) {
				t.Fatalf("expected an error on %s: %v", field, ds)
			}
		})
	}
}

func TestTailscaleReferenceFingerprints(t *testing.T) {
	const profile = `schema-version: 1
outbounds:
  - {id: ts, type: tailscale}
  - {id: remote, type: socks, server: relay.test, port: 1080, dialer: {proxy: ts}}
`
	compile := func(local string) map[string]string {
		t.Helper()
		eff, ds := Compile([]byte(profile), []byte(local), Options{})
		if ds.HasErrors() {
			t.Fatal(ds)
		}
		fingerprints := map[string]string{}
		for _, out := range eff.Outbounds {
			fingerprints[out.ID] = out.Fingerprint
		}
		return fingerprints
	}
	base := compile(tailscaleLinkLocal)
	preferred := compile(tailscaleLinkLocal + "      accept-routes: false\n      exit-node: gateway\n      exit-node-allow-lan-access: true\n")
	for _, out := range []string{"tailscale/home", "ts", "remote"} {
		if base[out] != preferred[out] {
			t.Errorf("routing preferences changed the %s fingerprint", out)
		}
	}
	for _, local := range []string{"", tailscaleLinkLocal + "      hostname: replacement\n", "link: {tailscale: [{id: renamed}]}"} {
		changed := compile(local)
		for _, out := range []string{"ts", "remote"} {
			if base[out] == changed[out] {
				t.Errorf("node identity change did not update the %s fingerprint", out)
			}
		}
	}
}

func TestTailscaleLinkOptionsAndRuleOrder(t *testing.T) {
	profile := strings.Replace(wireGuardLinkProfile, "rules:\n", `groups:
  - {id: home-access, type: select, members: [tailscale/home, direct]}
rules:
  - {id: named-host, match: {domain: service.test}, outbound: tailscale/home}
  - {id: named-group, match: {domain: group.test}, outbound: home-access}
`, 1)
	local := wireGuardLinkLocal + `  tailscale:
    - id: home
      control-url: https://control.example.test:443
      hostname: local-node
      ephemeral: true
      accept-routes: false
      exit-node: auto
      exit-node-allow-lan-access: true
      routes: [10.0.1.99/23, '2001:db8:2::1/48']
`
	eff, ds := Compile([]byte(profile), []byte(local), Options{})
	if eff == nil || ds.HasErrors() {
		t.Fatal(ds)
	}
	const target = "tailscale/home"
	out, ok := eff.Outbound(target)
	if !ok || out.Type != model.OutboundTailscale || out.Tailscale == nil || !out.UDP || out.Builtin || out.Fingerprint == "" {
		t.Fatal("missing local Tailscale outbound")
	}
	identity := TailscaleIdentity{ID: "home", ControlURL: "https://control.example.test:443", Hostname: "local-node", Ephemeral: true}
	if want := (Tailscale{TailscaleIdentity: identity, ExitNode: "auto", ExitNodeAllowLANAccess: true}); *out.Tailscale != want {
		t.Fatal("Tailscale settings did not survive compilation")
	}
	if want := []string{"tunnel", target, target, target, "home-access", "reject", "reject"}; len(eff.Rules) != len(want) {
		t.Fatalf("unexpected rules: %v", eff.Rules)
	} else {
		for i, target := range want {
			if eff.Rules[i].Target != target {
				t.Fatalf("unexpected rules: %v", eff.Rules)
			}
		}
	}
	for i, want := range [][]string{
		{"100.64.0.0/10", "fd7a:115c:a1e0::/48"},
		{"10.0.0.0/23", "2001:db8:2::/48"},
	} {
		rule := eff.Rules[i+1]
		if rule.Kind != router.KindIPCIDR || !rule.NoResolve || !slices.Equal(rule.Values, want) {
			t.Fatalf("unexpected Tailscale rule: %+v", rule)
		}
		const path = "/link/tailscale/home"
		origin, found := eff.OriginOf(model.JoinPath("/rules", rule.ID))
		if !found || origin.Document != model.DocLocal || origin.Layer != LayerLocal || origin.Path != path || origin.Line != 5 || origin.Column == 0 {
			t.Fatalf("invalid rule origin: %+v", origin)
		}
		if eff.RuleIDs[i+1] != rule.ID || LocalRuleSource(rule.ID) != "local.yaml "+path || !strings.Contains(eff.RuleDescriptions[i+1], path) {
			t.Fatalf("missing rule metadata: %v %v", eff.RuleIDs, eff.RuleDescriptions)
		}
	}
	if eff.Rules[1].ID == eff.Rules[2].ID {
		t.Fatal("Tailscale rules share an ID")
	}
	for _, domain := range []string{"service.test", "group.test"} {
		if decision := eff.RoutingRouter().Route(t.Context(), router.Metadata{Domain: domain}, nil); decision.Outbound != target {
			t.Fatalf("route for %s = %+v", domain, decision)
		}
	}
}

func TestTailscaleLinkRoutingModes(t *testing.T) {
	for _, tc := range []struct {
		mode, wireguard, tailscale, fallback string
	}{
		{"rule", "tunnel", "tailscale/home", "reject"},
		{"global", "tunnel", "tailscale/home", "fallback"},
		{"direct", "direct", "direct", "direct"},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			local := wireGuardLinkLocal + "  tailscale: [{id: home, routes: [10.0.0.0/23]}]\n" +
				fmt.Sprintf("routing: {mode: %s, global: fallback}\n", tc.mode)
			eff, ds := Compile([]byte(wireGuardLinkProfile), []byte(local), Options{})
			if eff == nil || ds.HasErrors() {
				t.Fatal(ds)
			}
			for _, want := range []struct{ addr, target string }{
				{"10.0.0.10", tc.wireguard}, {"10.0.1.10", tc.tailscale}, {"100.64.0.1", tc.tailscale},
				{"fd7a:115c:a1e0::1", tc.tailscale}, {"10.1.0.10", tc.fallback},
			} {
				decision := eff.RoutingRouter().Route(t.Context(), router.Metadata{Addr: netip.MustParseAddr(want.addr)}, nil)
				if decision.Outbound != want.target {
					t.Fatalf("route for %s = %+v, want %q", want.addr, decision, want.target)
				}
			}
			env := &noRuleLookup{}
			if decision := eff.RoutingRouter().Route(t.Context(), router.Metadata{Domain: "unmatched.test"}, env); env.calls != 0 || decision.Outbound != tc.fallback {
				t.Fatalf("domain-only route = %+v with %d lookups", decision, env.calls)
			}
		})
	}
}

func TestTailscaleLinkValidation(t *testing.T) {
	for _, tc := range []struct{ name, entry, path, code string }{
		{"limit", "{id: one}\n    - {id: two}", "", "link.tailscale.limit"},
		{"missing ID", "{}", "/#0", "schema.id"},
		{"scoped ID", "{id: other/home}", "/other~1home/id", "schema.id"},
		{"invalid ID start", "{id: .home}", "/.home/id", "schema.id"},
		{"long ID", "{id: " + strings.Repeat("a", 65) + "}", "/" + strings.Repeat("a", 65) + "/id", "schema.id"},
		{"insecure URL", "{id: home, control-url: http://control.example.test}", "/home/control-url", "link.tailscale.control-url"},
		{"relative URL", "{id: home, control-url: control.example.test}", "/home/control-url", "link.tailscale.control-url"},
		{"malformed URL", "{id: home, control-url: 'https://[bad'}", "/home/control-url", "link.tailscale.control-url"},
		{"missing URL host", "{id: home, control-url: 'https:///path'}", "/home/control-url", "link.tailscale.control-url"},
		{"missing auth key", "{id: home, auth-key: secret://tailscale/auth}", "/home/auth-key", "secret.missing"},
		{"reserved secret", "{id: home, auth-key: secret://mitm/private-key}", "/home/auth-key", "secret.reserved"},
		{"bad secret reference", "{id: home, auth-key: secret://../auth}", "/home/auth-key", "secret.name"},
		{"route limit", "{id: home, routes: [" + strings.Repeat("10.0.0.0/24, ", 64) + "10.0.1.0/24]}", "/home/routes", "link.tailscale.routes"},
		{"custom state directory", "{id: home, state-directory: test}", "/home/state-directory", "schema.unknown-field"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			local := "link:\n  tailscale:\n    - " + tc.entry + "\n"
			assertTailscaleLocalError(t, local, tc.path, tc.code)
		})
	}
	for _, route := range []string{
		"10.0.0.1", "0.0.0.0/0", "::/0", "127.0.0.0/8", "126.0.0.0/7", "::1/128",
		"169.254.0.0/16", "fe80::/10", "224.0.0.0/4", "ff00::/8", "::ffff:127.0.0.0/104",
	} {
		t.Run(route, func(t *testing.T) {
			local := tailscaleLinkLocal + fmt.Sprintf("      routes: [%q]\n", route)
			assertTailscaleLocalError(t, local, "/home/routes/#0", "link.tailscale.routes")
		})
	}
}

func assertTailscaleLocalError(t *testing.T, local, suffix, code string) {
	t.Helper()
	eff, ds := Compile([]byte("schema-version: 1\n"), []byte(local), Options{Secrets: store(t)})
	want := tailscaleLinkPath + suffix
	if eff != nil || !slices.ContainsFunc(ds.Errors(), func(d model.Diagnostic) bool {
		return d.Code == code && d.Document == model.DocLocal && d.Path == want && d.Line > 0 && d.Column > 0
	}) {
		t.Fatalf("expected a local %s diagnostic at %s: %v", code, want, ds)
	}
}

func TestTailscaleLinkMissingTargetAndScopedCollision(t *testing.T) {
	for _, tc := range []struct{ profile, code string }{
		{"rules: [{match: {all: true}, outbound: tailscale/home}]", "rule.outbound"},
		{"groups: [{id: home-access, type: select, members: [tailscale/home]}]", "group.member"},
		{"outbounds: [{id: tailscale/home, type: direct}]", "schema.id"},
	} {
		eff, ds := Compile([]byte("schema-version: 1\n"+tc.profile), nil, Options{})
		if eff != nil || !slices.ContainsFunc(ds.Errors(), func(d model.Diagnostic) bool { return d.Code == tc.code }) {
			t.Fatalf("expected %s for %q: %v", tc.code, tc.profile, ds)
		}
	}
	profile := "schema-version: 1\nimports: [{source: tailscale, outbounds: true}]\n"
	sources := "schema-version: 1\nsources: [{id: tailscale, outbounds: [{id: home, type: direct}]}]\n"
	eff, ds := Compile([]byte(profile), []byte(tailscaleLinkLocal), Options{Sources: []byte(sources)})
	if eff != nil || !slices.ContainsFunc(ds.Errors(), func(d model.Diagnostic) bool {
		return d.Code == "schema.duplicate-id" && d.Document == model.DocLocal && d.Path == "/link/tailscale/home/id"
	}) {
		t.Fatalf("expected a diagnostic on the local link for the scoped ID collision: %v", ds)
	}
}

func TestTailscaleLinkSecretAndFingerprints(t *testing.T) {
	secrets := store(t)
	setKey := func(key string) {
		t.Helper()
		if err := secrets.Set("tailscale/auth", key); err != nil {
			t.Fatal(err)
		}
	}
	compile := func(local string) (*Effective, Outbound) {
		t.Helper()
		eff, ds := Compile([]byte("schema-version: 1\n"), []byte(local), Options{Secrets: secrets})
		if eff == nil || ds.HasErrors() {
			t.Fatal(ds)
		}
		out, ok := eff.Outbound("tailscale/home")
		if !ok || out.Tailscale == nil {
			t.Fatal("missing local Tailscale outbound")
		}
		return eff, out
	}
	const key = "private-auth-key-first"
	setKey(key)
	local := tailscaleLinkLocal + "      auth-key: secret://tailscale/auth\n"
	eff, out := compile(local)
	if !out.Tailscale.AcceptRoutes || out.Tailscale.Ephemeral || out.Tailscale.ControlURL != "" || out.Tailscale.Hostname != "" || out.Tailscale.AuthKey != key || len(eff.Rules) != 1 {
		t.Fatal("unexpected Tailscale defaults or resolved auth key")
	}
	wire, err := json.Marshal(eff)
	if err != nil || strings.Contains(string(wire), key) {
		t.Fatal("effective configuration exposed a Tailscale auth key", err)
	}
	maximum := local + "      routes: [" + strings.Repeat("10.0.0.0/24, ", maxTailscaleRoutes-1) + "10.0.1.0/24]\n"
	routed, unchanged := compile(maximum)
	if routed.RulesFingerprint == eff.RulesFingerprint || unchanged.Fingerprint != out.Fingerprint || len(routed.Rules[1].Values) != maxTailscaleRoutes {
		t.Fatal("adding local routes must change only the rule fingerprint")
	}
	setKey("private-auth-key-second")
	rotated, changed := compile(local)
	if rotated.RulesFingerprint != eff.RulesFingerprint || changed.Fingerprint == out.Fingerprint {
		t.Fatal("rotating the auth key must change only the outbound fingerprint")
	}
}

func TestLinkSecretsStayLocal(t *testing.T) {
	secrets := store(t)
	if err := secrets.Set("link/tailscale/home/auth-key", "private-link-key"); err != nil {
		t.Fatal(err)
	}
	local := tailscaleLinkLocal + "      auth-key: secret://link/tailscale/home/auth-key\n"
	eff, ds := Compile([]byte("schema-version: 1\n"), []byte(local), Options{Secrets: secrets})
	if eff == nil || ds.HasErrors() {
		t.Fatal(ds)
	}
	if out, ok := eff.Outbound("tailscale/home"); !ok || out.Tailscale.AuthKey != "private-link-key" {
		t.Fatal("local link settings could not read their auth key")
	}
	// A profile or subscription node must not send a link credential to its
	// own server as a password.
	profile := "schema-version: 1\noutbounds:\n  - {id: leak, type: trojan, server: example.com, port: 443, password: secret://link/tailscale/home/auth-key, tls: {}}\n"
	_, ds = Compile([]byte(profile), nil, Options{Secrets: secrets})
	found := false
	for _, d := range ds {
		found = found || d.Code == "secret.reserved"
	}
	if !found {
		t.Fatalf("profile reference to a link credential was accepted: %v", ds)
	}
}
