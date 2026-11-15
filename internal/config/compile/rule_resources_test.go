package compile

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"github.com/MimoProxy/reka/internal/resource"
	"github.com/MimoProxy/reka/internal/router"
)

const logicProfile = `rule-sets:
 - id: domains
   entries: [{domain-suffix: example.org}]
 - id: nested
   entries: [{rule-set: domains}, {dst-port: 8443}]
sub-rules:
 - id: tls
   rules:
    - {id: secure, match: {and: [{rule-set: nested}, {dst-port: 443}]}, outbound: reject}
    - {id: other, match: {domain: special.test}, outbound: direct}
rules:
 - {id: call, match: {network: tcp}, call: tls}
 - {id: final, match: {all: true}, outbound: direct}
`

func TestSubRulesNestedSetOrderAndFallthrough(t *testing.T) {
	eff, ds := Compile([]byte("schema-version: 1\n"+logicProfile), nil, Options{})
	if ds.HasErrors() {
		t.Fatal(ds)
	}
	for _, tc := range []struct {
		domain, network, want string
		port                  uint16
	}{{"a.example.org", "tcp", "reject", 443}, {"a.example.org", "udp", "direct", 443}, {"a.example.org", "tcp", "direct", 80}, {"special.test", "tcp", "direct", 443}} {
		d := eff.Router.Route(context.Background(), router.Metadata{Domain: tc.domain, Network: tc.network, Port: tc.port}, nil)
		if d.Outbound != tc.want {
			t.Fatal(tc, d)
		}
	}
	if len(eff.Rules) != 3 || eff.Rules[0].ID != "call/tls/secure" {
		t.Fatal(eff.Rules)
	}
	b, ds := Compile([]byte("schema-version: 1\n"+strings.Replace(logicProfile, "example.org", "other.org", 1)), nil, Options{})
	if ds.HasErrors() || eff.RulesFingerprint == b.RulesFingerprint {
		t.Fatal("nested entries missing from fingerprint", ds)
	}
}
func TestRuleGraphRejectsInvalidUnusedDefinitions(t *testing.T) {
	for _, bad := range []string{
		strings.Replace(logicProfile, "rule-set: domains", "rule-set: nested", 1),
		strings.Replace(logicProfile, "call: tls", "call: missing", 1),
		strings.Replace(logicProfile, "outbound: reject", "call: tls", 1),
		strings.Replace(logicProfile, "outbound: reject", "outbound: missing", 1),
		strings.Replace(logicProfile, "id: nested", "id: domains", 1),
		strings.Replace(logicProfile, "call: tls", "call: tls, outbound: reject", 1),
		strings.Replace(logicProfile, "network: tcp", "not: [{network: tcp}, {network: udp}]", 1),
		logicProfile + "sub-rules: []\n",
	} {
		if eff, ds := Compile([]byte("schema-version: 1\n"+bad), nil, Options{}); eff != nil || !ds.HasErrors() {
			t.Fatal("invalid graph accepted", bad, ds)
		}
	}
	unused := strings.Replace(logicProfile, "call: tls", "outbound: direct", 1)
	unused = strings.Replace(unused, "outbound: reject", "outbound: missing", 1)
	if _, ds := Compile([]byte("schema-version: 1\n"+unused), nil, Options{}); !ds.HasErrors() {
		t.Fatal("invalid unused block accepted")
	}
}
func TestLockedRuleResourceHashAndFingerprint(t *testing.T) {
	a, b := []byte("+.example.org\n"), []byte("+.other.org\n")
	run := func(data []byte) *Effective {
		hash := resource.Hash(data)
		profile := fmt.Sprintf("rule-sets: [{id: list, behavior: domain, format: text, hash: %s}]\nrules: [{id: use, match: {rule-set: list}, outbound: reject}]\n", hash)
		eff, ds := Compile([]byte("schema-version: 1\n"+profile), nil, Options{ReadResource: func(h string) ([]byte, error) {
			if h != hash {
				t.Fatal(h)
			}
			return data, nil
		}})
		if ds.HasErrors() {
			t.Fatal(ds)
		}
		return eff
	}
	first, second := run(a), run(b)
	if first.RulesFingerprint == second.RulesFingerprint {
		t.Fatal("resource update did not change rule fingerprint")
	}
	if got := first.Router.Route(context.Background(), router.Metadata{Domain: "x.example.org"}, nil); got.Outbound != "reject" {
		t.Fatal(got)
	}
	profile := fmt.Sprintf("rule-sets: [{id: list, behavior: domain, format: text, hash: %s}]", resource.Hash(a))
	for _, opts := range []Options{{}, {ReadResource: func(string) ([]byte, error) { return b, nil }}} {
		if _, ds := Compile([]byte("schema-version: 1\n"+profile), nil, opts); !ds.HasErrors() {
			t.Fatal("unavailable/corrupt resource accepted")
		}
	}
}
func TestSourceRuleResourcesNamespacesAndOverlay(t *testing.T) {
	source := "schema-version: 1\nsources:\n - id: airport\n"
	for _, line := range strings.Split(strings.TrimSuffix(logicProfile, "\n"), "\n") {
		source += "   " + line + "\n"
	}
	profile := "rules: [{source: airport}]"
	overlay := `schema-version: 1
patches: [{op: set, path: /rule-sets/airport~1domains/entries, value: [{domain: changed.test}]}]`
	eff, ds := Compile([]byte("schema-version: 1\n"+profile), nil, Options{Sources: []byte(source), Overlay: []byte(overlay)})
	if ds.HasErrors() {
		t.Fatal(ds)
	}
	d := eff.Router.Route(context.Background(), router.Metadata{Domain: "changed.test", Network: "tcp", Port: 443}, nil)
	if d.Outbound != "reject" {
		t.Fatal(d)
	}
	if !strings.Contains(eff.Rules[d.RuleIndex].ID, "airport/tls") {
		t.Fatal("unscoped block", d)
	}
}

func TestSourceNodeImportsDoNotActivateRuleResources(t *testing.T) {
	sources := `sources:
 - id: airport
   outbounds: [{id: node, type: direct}]
   rule-sets: [{id: missing, hash: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa, behavior: domain, format: text}]
   sub-rules: [{id: block, rules: [{id: child, match: {rule-set: missing}, outbound: unimported}]}]
`
	profile := "schema-version: 1\nimports: [{source: airport, outbounds: true}]"
	if _, ds := Compile([]byte(profile), nil, Options{Sources: []byte(sources)}); ds.HasErrors() {
		t.Fatal("unused rules affected node-only import", ds)
	}
}

func TestSubRuleProvenanceIncludesGuardAndChild(t *testing.T) {
	eff, ds := Compile([]byte("schema-version: 1\n"+logicProfile), nil, Options{})
	if ds.HasErrors() {
		t.Fatal(ds)
	}
	prefix := "/rules/call~1tls~1secure"
	for path, want := range map[string]string{prefix + "/match/and/#0/network": "/rules/call/match/network", prefix + "/outbound": "/sub-rules/tls/rules/secure/outbound", prefix + "/match/and/#1/and/#0/rule-set": "/sub-rules/tls/rules/secure/match/and/#0/rule-set"} {
		got, ok := eff.Provenance[path]
		if !ok || got.Path != want || got.Line == 0 {
			t.Fatal(path, got, want)
		}
	}
}

type noRuleLookup struct{ calls int }

func (e *noRuleLookup) Resolve(context.Context, string) ([]netip.Addr, error) {
	e.calls++
	return nil, router.ErrNoLookup
}
func (e *noRuleLookup) Process(context.Context) (string, bool) { return "", false }
func TestSubRuleEmptyBlockStillEvaluatesGuard(t *testing.T) {
	profile := `schema-version: 1
sub-rules: [{id: empty, rules: []}]
rules:
 - {id: guard, match: {ip-cidr: 192.0.2.0/24}, call: empty}
 - {id: final, match: {all: true}, outbound: direct}
`
	eff, ds := Compile([]byte(profile), nil, Options{})
	if ds.HasErrors() {
		t.Fatal(ds)
	}
	env := &noRuleLookup{}
	exp := eff.Router.Explain(context.Background(), router.Metadata{Domain: "x.test"}, env)
	if !exp.Undetermined || env.calls != 1 {
		t.Fatal(exp, env.calls)
	}
	if got := eff.Router.Route(context.Background(), router.Metadata{Addr: netip.MustParseAddr("192.0.2.1")}, nil); got.Outbound != "direct" || got.RuleIndex != 1 {
		t.Fatal(got)
	}
}

func TestReferenceDepthCannotBeBypassedByDefinitionOrder(t *testing.T) {
	var sets, blocks strings.Builder
	sets.WriteString("schema-version: 1\nrule-sets:\n - {id: s0, entries: [{domain: x.test}]}\n")
	blocks.WriteString("schema-version: 1\nsub-rules:\n - {id: s0, rules: [{id: leaf, match: {all: true}, outbound: direct}]}\n")
	for i := 1; i < 40; i++ {
		fmt.Fprintf(&sets, " - {id: s%d, entries: [{rule-set: s%d}]}\n", i, i-1)
		fmt.Fprintf(&blocks, " - {id: s%d, rules: [{id: call, match: {all: true}, call: s%d}]}\n", i, i-1)
	}
	sets.WriteString("rules: [{match: {rule-set: s39}, outbound: reject}]\n")
	blocks.WriteString("rules: [{match: {all: true}, call: s39}]\n")
	for _, profile := range []string{sets.String(), blocks.String()} {
		if _, ds := Compile([]byte(profile), nil, Options{}); !ds.HasErrors() {
			t.Fatal("dependency-first depth limit bypass", profile)
		}
	}
}
