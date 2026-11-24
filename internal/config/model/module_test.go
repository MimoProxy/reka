package model

import (
	"strings"
	"testing"
)

func TestModuleArgumentsDecode(t *testing.T) {
	const prefix = "schema-version: 1\nmodules:\n  - id: filter\n    url: https://example.com/filter.sgmodule\n"
	profile, positions, ds := ParseProfile([]byte(prefix + `    arguments: {策略: "Pick, one", enabled: "true", empty: ""}
`))
	if ds.HasErrors() {
		t.Fatal(ds)
	}
	def := profile.Modules[0]
	if !def.IsEnabled() || def.Arguments["策略"] != "Pick, one" || def.Arguments["enabled"] != "true" || def.Arguments["empty"] != "" || positions["/modules/filter/arguments/策略"].Line != 5 {
		t.Fatalf("module arguments or position missing: %+v, %+v", def, positions)
	}
	for _, tc := range []struct{ field, code string }{
		{"arguments: {heading: one, heading: two}", "yaml.duplicate"},
		{"arguments: {1: one}", "yaml.key"},
		{"arguments: {enabled: true}", "yaml.type"},
		{"arguments: [entry]", "yaml.type"},
		{"unexpected: field", "schema.unknown-field"},
	} {
		_, _, ds := ParseProfile([]byte(prefix + "    " + tc.field))
		if len(ds) != 1 || ds[0].Code != tc.code || ds[0].Line != 5 {
			t.Fatalf("decode %q: %+v", tc.field, ds)
		}
	}
}

func TestModuleURLMaskRoundTrip(t *testing.T) {
	raw := []byte(`schema-version: 1
modules:
  - {id: first, url: 'https://example.com/filter.sgmodule'}
  - {id: second, url: 'secret://modules/second/url'}
`)
	base, ds := LoadDoc(DocProfile, raw)
	if ds.HasErrors() {
		t.Fatal(ds)
	}
	edited, _ := LoadDoc(DocProfile, raw)
	if !IsSensitive("/modules/first/url") || edited.MaskSecrets() != 1 ||
		strings.Contains(string(edited.Bytes()), "https://example.com") ||
		!strings.Contains(string(edited.Bytes()), "secret://modules/second/url") {
		t.Fatalf("unexpected masked document %s", edited.Bytes())
	}
	if err := edited.Apply(Op{Op: "set", Path: "/modules/first/arguments", Value: []byte(`{"策略": "Pick, one"}`)}); err != nil {
		t.Fatal(err)
	}
	if err := edited.UnmaskSecrets(base); err != nil {
		t.Fatal(err)
	}
	p, _, ds := ParseProfile(edited.Bytes())
	if ds.HasErrors() || p.Modules[0].URL != "https://example.com/filter.sgmodule" || p.Modules[0].Arguments["策略"] != "Pick, one" {
		t.Fatalf("wrong edited profile %+v: %v", p, ds)
	}
}
