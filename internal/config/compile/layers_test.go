package compile

import (
	"strings"
	"testing"

	"github.com/MimoProxy/reka/internal/config/model"
)

const layeredProfile = `schema-version: 1
imports:
  - {source: airport, outbounds: true, groups: true}
rules:
  - {id: before, match: {domain: local.test}, outbound: reject}
  - {source: airport}
  - {id: final, match: {all: true}, outbound: airport/proxy}
`
const layeredSources = `schema-version: 1
sources:
  - id: airport
    outbounds:
      - {id: a, type: socks, server: 127.0.0.1, port: 1080, username: user, password: original}
      - {id: b, type: direct}
    groups:
      - {id: proxy, type: select, members: [a, b], selected: a}
    rules:
      - {id: remote, match: {domain: source.test}, outbound: proxy}
`
const layeredOverlay = `schema-version: 1
patches:
  - {op: set, path: /groups/airport~1proxy/selected, value: airport/b}
  - {op: set, path: /outbounds/airport~1a/port, value: 2080}
`

func TestSourceCompositionAndRefresh(t *testing.T) {
	compile := func(sources string) *Effective {
		t.Helper()
		eff, ds := Compile([]byte(layeredProfile), []byte("log: {level: error}\n"), Options{Sources: []byte(sources), Overlay: []byte(layeredOverlay)})
		if ds.HasErrors() {
			t.Fatal(ds)
		}
		return eff
	}
	a := compile(layeredSources)
	b := compile(strings.ReplaceAll(strings.ReplaceAll(layeredSources, "port: 1080", "port: 3080"), "id: a, type:", "id: a, name: renamed, type:"))
	if len(a.Rules) != 3 || a.RuleIDs[1] != "airport/remote" || a.RuleIDs[2] != "final" {
		t.Fatalf("rule expansion: %+v", a.RuleIDs)
	}
	for _, eff := range []*Effective{a, b} {
		out, _, err := eff.Router.Resolve("airport/proxy")
		if err != nil || out != "airport/b" {
			t.Fatalf("selection: %s %v", out, err)
		}
		node, _ := eff.Outbound("airport/a")
		if node.Port != 2080 || node.Password != "original" || eff.LogLevel != "error" {
			t.Fatalf("composed node: %+v", node)
		}
	}
	if a.SourceHashes["airport"] == b.SourceHashes["airport"] {
		t.Fatal("source content is not locked")
	}
	ao, _ := a.Outbound("airport/a")
	bo, _ := b.Outbound("airport/a")
	if ao.Fingerprint != bo.Fingerprint {
		t.Fatal("covered upstream change replaced an identical instance")
	}
	origin, _ := a.OriginOf("/outbounds/airport~1a/port")
	if origin.Layer != LayerOverlay || origin.Document != model.DocOverlay || origin.Overrides == nil || origin.Overrides.Source != "airport" {
		t.Fatalf("overlay origin: %+v", origin)
	}
	origin, _ = a.OriginOf("/outbounds/airport~1a/server")
	if origin.Layer != LayerSource || origin.Source != "airport" || origin.Path != "/sources/airport/outbounds/a/server" || origin.Line != 5 {
		t.Fatalf("source origin: %+v", origin)
	}
}

func TestSourceNamespacesAndBuiltins(t *testing.T) {
	sources := layeredSources + strings.ReplaceAll(strings.TrimPrefix(layeredSources, "schema-version: 1\nsources:\n"), "id: airport", "id: another")
	profile := strings.Replace(layeredProfile, "rules:", "  - {source: another, outbounds: true, groups: true}\nrules:", 1)
	eff, ds := Compile([]byte(profile), nil, Options{Sources: []byte(sources)})
	if ds.HasErrors() {
		t.Fatal(ds)
	}
	for _, id := range []string{"airport/a", "another/a"} {
		if _, ok := eff.Outbound(id); !ok {
			t.Fatal("missing", id)
		}
	}
	// An unknown source-local target must not bind to a profile object.
	bad := strings.Replace(layeredSources, "outbound: proxy", "outbound: local", 1)
	profile = layeredProfile + "outbounds:\n  - {id: local, type: direct}\n"
	_, ds = Compile([]byte(profile), nil, Options{Sources: []byte(bad)})
	if !ds.HasErrors() {
		t.Fatal("source reference escaped its namespace")
	}
}

func TestLayerFailures(t *testing.T) {
	cases := []struct{ name, profile, sources, overlay, code string }{
		{"missing source id", layeredProfile, strings.Replace(layeredSources, "id: airport", "id: \"\"", 1), "", "source.id"},
		{"duplicate marker", strings.Replace(layeredProfile, "{source: airport}", "{id: before, source: airport}", 1), layeredSources, "", "schema.duplicate-id"},
		{"invalid marker ID", strings.Replace(layeredProfile, "{source: airport}", "{id: bad/id, source: airport}", 1), layeredSources, "", "schema.id"},
		{"unknown source", strings.ReplaceAll(layeredProfile, "airport", "missing"), layeredSources, "", "source.missing"},
		{"duplicate import", strings.Replace(layeredProfile, "rules:", "  - {source: airport, groups: true}\nrules:", 1), layeredSources, "", "source.duplicate-import"},
		{"missing overlay target", layeredProfile, strings.ReplaceAll(layeredSources, "id: a,", "id: renamed,"), layeredOverlay, "overlay.path"},
		{"missing selection", layeredProfile, strings.ReplaceAll(layeredSources, "[a, b]", "[a]"), layeredOverlay, "group.selected"},
		{"identity edit", layeredProfile, layeredSources, "patches: [{op: set, path: /outbounds/airport~1a/id, value: other}]", "overlay.path"},
		{"local takeover", layeredProfile, layeredSources, "patches: [{op: set, path: /listeners, value: []}]", "overlay.path"},
		{"anonymous source rule", layeredProfile, strings.ReplaceAll(layeredSources, "id: remote, ", ""), "", "source.id"},
		{"invalid source field", layeredProfile, strings.Replace(layeredSources, "port: 1080", "port: 0", 1), "", "outbound.port"},
		{"invalid overlay type", layeredProfile, layeredSources, "patches: [{op: set, path: /outbounds/airport~1a/port, value: broken}]", "yaml.type"},
		{"duplicate patch value", layeredProfile, layeredSources, "patches: [{op: set, path: /groups/airport~1proxy, value: {id: x, id: y}}]", "yaml.duplicate"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			eff, ds := Compile([]byte(tc.profile), nil, Options{Sources: []byte(tc.sources), Overlay: []byte(tc.overlay)})
			if eff != nil {
				t.Fatal("invalid composition accepted")
			}
			for _, d := range ds {
				if d.Code == tc.code {
					if d.Document == "" || d.Line == 0 {
						t.Fatalf("missing location: %+v", d)
					}
					return
				}
			}
			t.Fatalf("missing %s: %v", tc.code, ds)
		})
	}
}

func TestSourceIDMustBeLiteralScalar(t *testing.T) {
	for _, tc := range []struct{ name, value string }{
		{name: "alias", value: "*source-id"},
		{name: "sequence", value: "[sample]"},
		{name: "mapping", value: "{name: sample}"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sources := "sources:\n  - outbounds: [{id: node, type: direct, name: &source-id sample}]\n    id: " + tc.value + "\n"
			eff, ds := Compile([]byte("schema-version: 1\n"), nil, Options{Sources: []byte(sources)})
			if eff != nil || !ds.HasErrors() {
				t.Fatalf("invalid source ID accepted: %+v", ds)
			}
			for _, d := range ds.Errors() {
				if d.Document == model.DocSources && d.Path == "/sources/#0/id" && d.Line == 3 {
					return
				}
			}
			t.Fatalf("missing diagnostic at the source ID: %+v", ds)
		})
	}
}

func TestOverlayDisableAndInsert(t *testing.T) {
	overlay := `patches:
 - {op: remove, path: /rules/airport~1remote}
 - {op: insert, path: /rules, before: final, value: {id: custom, match: {domain: added.test}, outbound: reject}}
`
	eff, ds := Compile([]byte(layeredProfile), nil, Options{Sources: []byte(layeredSources), Overlay: []byte(overlay)})
	if ds.HasErrors() {
		t.Fatal(ds)
	}
	if strings.Join(eff.RuleIDs, ",") != "before,custom,final" {
		t.Fatalf("order: %+v", eff.RuleIDs)
	}
	// Disabling a referenced node requires repairing its group explicitly.
	overlay = "patches: [{op: remove, path: /outbounds/airport~1a}]"
	if eff, ds := Compile([]byte(layeredProfile), nil, Options{Sources: []byte(layeredSources), Overlay: []byte(overlay)}); eff != nil || !ds.HasErrors() {
		t.Fatal("dangling group accepted")
	}
}

func TestProfileReplacementAndAnonymousRuleOrigins(t *testing.T) {
	profile := layeredProfile + "outbounds:\n - {id: airport/a, type: direct}\n"
	eff, ds := Compile([]byte(profile), nil, Options{Sources: []byte(layeredSources)})
	if ds.HasErrors() {
		t.Fatal(ds)
	}
	o, _ := eff.OriginOf("/outbounds/airport~1a/type")
	if o.Layer != LayerProfile || o.Overrides == nil || o.Overrides.Layer != LayerSource {
		t.Fatalf("replacement origin: %+v", o)
	}
	// Anonymous local rules move when the source expands; provenance must
	// still point to the original profile position, not generated YAML.
	profile = strings.ReplaceAll(layeredProfile, "{id: final, match:", "{match:")
	extra := layeredSources + "      - {id: second, match: {domain: second.test}, outbound: proxy}\n"
	eff, ds = Compile([]byte(profile), nil, Options{Sources: []byte(extra)})
	if ds.HasErrors() {
		t.Fatal(ds)
	}
	o, _ = eff.OriginOf("/rules/#3/outbound")
	if o.Path != "/rules/#2/outbound" || o.Line != 7 {
		t.Fatalf("anonymous origin: %+v", o)
	}
}
