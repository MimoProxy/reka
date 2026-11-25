package compile

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/MimoProxy/reka/internal/config/model"
	"github.com/MimoProxy/reka/internal/httprewrite"
	"github.com/MimoProxy/reka/internal/resource"
)

const moduleLocation = "https://example.com/filter.sgmodule"
const moduleProfile = `schema-version: 1
modules:
  - {id: filter, url: https://example.com/filter.sgmodule}
`

func moduleSnapshot(id, location, body string) string {
	def := model.Module{URL: location}
	return fmt.Sprintf("  - id: %s\n    module: {format: surge, request: %s}\n    lock: {root: %s}\n",
		id, def.RequestHash(), resource.Hash([]byte(body)))
}

func moduleOptions(body string) Options {
	return Options{
		Sources: []byte("sources:\n" + moduleSnapshot("filter", moduleLocation, body)),
		ReadResource: func(hash string) ([]byte, error) {
			if hash == resource.Hash([]byte(body)) {
				return []byte(body), nil
			}
			return nil, resource.ErrCorrupt
		},
	}
}

func compileModule(t *testing.T, profile string, opts Options) *Effective {
	t.Helper()
	eff, ds := Compile([]byte(profile), nil, opts)
	if ds.HasErrors() {
		t.Fatal(ds)
	}
	return eff
}

func TestModuleRulePlacementAndPolicyResolution(t *testing.T) {
	const body = `#!arguments=PROXY:Choice
[Rule]
DOMAIN,module.test,{{{PROXY}}}
DOMAIN-SUFFIX,example.net,remote/node
AND,((DOMAIN-SUFFIX,example.com),(NOT,((DOMAIN,skip.example.com)))),REJECT-DROP
DOMAIN,pass.test,pass
`
	opts := moduleOptions(body)
	const remote = `  - id: remote
    outbounds: [{id: node, name: Remote, type: direct}]
`
	opts.Sources = append(opts.Sources, remote...)
	profile := moduleProfile + `imports: [{source: remote, outbounds: true}]
groups: [{id: choice, name: Choice, type: select, members: [remote/node]}]
rules:
  - {id: first, match: {domain: first.test}, outbound: direct}
  - {id: final, match: {all: true}, outbound: direct}
`
	eff := compileModule(t, profile, opts)
	if len(eff.Rules) != 6 || eff.Rules[0].Target != "choice" || eff.Rules[1].Target != "remote/node" ||
		eff.Rules[2].Target != "reject-drop" || eff.Rules[3].Target != "pass" || eff.RuleIDs[4] != "first" {
		t.Fatalf("unexpected rule order and targets: %v", eff.Rules)
	}
	first := eff.RuleIDs[0]
	if origin, ok := eff.OriginOf(model.JoinPath("/rules", first, "outbound")); !ok ||
		origin.Layer != LayerModule || origin.Document != model.DocSources || origin.Source != "filter" || origin.Line != 3 {
		t.Fatalf("unexpected origin: %+v", origin)
	}
	marked := strings.Replace(profile, "  - {id: final", "  - {id: slot, module: filter}\n  - {id: final", 1)
	eff = compileModule(t, marked, opts)
	if eff.RuleIDs[0] != "first" || eff.RuleIDs[1] != first {
		t.Fatalf("marked rule order: %v", eff.RuleIDs)
	}
	disabled := strings.Replace(marked, "{id: filter, url:", "{id: filter, enabled: false, url:", 1)
	eff = compileModule(t, disabled, Options{Sources: []byte("sources:\n" + remote)})
	if !slices.Equal(eff.RuleIDs, []string{"first", "final"}) || len(eff.Modules) != 0 {
		t.Fatalf("disabled module contributed rules or reports: %v %+v", eff.RuleIDs, eff.Modules)
	}
}

func TestModuleLayerValidation(t *testing.T) {
	const body = "[Rule]\nDOMAIN,example.com,Unavailable"
	const enabledBody = "[Rule]\nDOMAIN,example.com,DIRECT"
	for _, tc := range []struct {
		name, profile, code string
		opts                Options
	}{
		{"missing policy", moduleProfile, "module.rule-policy", moduleOptions(body)},
		{"ambiguous policy", moduleProfile + `outbounds: [{id: a, name: Unavailable, type: direct}, {id: b, name: Unavailable, type: direct}]`, "module.rule-policy", moduleOptions(body)},
		{"no snapshot", moduleProfile, "module.download", Options{}},
		{"changed location", strings.Replace(moduleProfile, "example.com", "example.net", 1), "module.download", moduleOptions(enabledBody)},
		{"changed format", strings.Replace(moduleProfile, "{id: filter,", "{id: filter, format: loon,", 1), "module.download", moduleOptions(enabledBody)},
		{"invalid format", strings.Replace(moduleProfile, "{id: filter,", "{id: filter, format: other,", 1), "module.definition", moduleOptions(enabledBody)},
		{"no resource reader", moduleProfile, "module.resource", Options{Sources: moduleOptions(enabledBody).Sources}},
		{"corrupt root", moduleProfile, "module.resource", Options{Sources: moduleOptions(enabledBody).Sources, ReadResource: func(string) ([]byte, error) { return []byte("other"), nil }}},
		{"unknown marker", moduleProfile + "rules: [{module: unknown}]", "module.missing", moduleOptions(enabledBody)},
		{"duplicate marker", moduleProfile + "rules: [{module: filter}, {module: filter}]", "module.duplicate-marker", moduleOptions(enabledBody)},
		{"mixed marker", moduleProfile + "rules: [{module: filter, outbound: direct}]", "module.marker", moduleOptions(enabledBody)},
		{"mixed source", moduleProfile, "module.snapshot", Options{Sources: append(moduleOptions(enabledBody).Sources, []byte("    groups: []\n")...)}},
		{"imported as source", moduleProfile + "imports: [{source: filter, rewrites: true}]", "module.source", moduleOptions(enabledBody)},
		{"expanded as source", moduleProfile + "rules: [{source: filter}]", "module.source", moduleOptions(enabledBody)},
		{"native source ID conflict", moduleProfile, "module.source-conflict", Options{Sources: []byte("sources: [{id: filter}]")}},
		{"duplicate IDs", moduleProfile + "  - {id: filter, url: 'https://example.net/module'}\n", "module.duplicate", Options{}},
		{"invalid interval", strings.Replace(moduleProfile, "{id: filter,", "{id: filter, interval: 299,", 1), "module.definition", Options{}},
		{"invalid hostname points to module", moduleProfile, "mitm.hostname", moduleOptions("[MITM]\nhostname = %INSERT% example.test:65536")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			eff, ds := Compile([]byte(tc.profile), nil, tc.opts)
			if eff != nil || !ds.HasErrors() {
				t.Fatalf("expected failure, got %+v", ds)
			}
			for _, d := range ds {
				if strings.HasPrefix(d.Code, tc.code) {
					if tc.code == "module.rule-policy" || tc.code == "mitm.hostname" {
						if d.Document != model.DocProfile || d.Path != "/modules/filter" || !strings.Contains(d.Message, "module line 2") {
							t.Fatalf("wrong module diagnostic: %+v", d)
						}
					}
					return
				}
			}
			t.Fatalf("missing diagnostic %q: %v", tc.code, ds)
		})
	}
}

func TestCompileLoonAndStashSnapshots(t *testing.T) {
	const loon = `#!name=Loon filters
[Argument]
Player = input, sample
Enabled = switch, true, false
[Rule]
DOMAIN,example.test,PROXY
[Rewrite]
^https://example\.test/blocked reject-200
[Script]
http-response ^https://example\.test/ script-path=https://example.test/hook.js, argument=[{Player},{Enabled}]
[MITM]
hostname = %APPEND% example.test
`
	const stash = `name: Stash filters
rules:
  - DOMAIN,example.test,DIRECT
http:
  mitm: [example.test]
  url-rewrite:
    - '^https://example\.test/blocked - reject-200'
  script:
    - {match: '^https://example\.test/', name: hook, type: response, argument: sample}
script-providers:
  hook: {url: 'https://example.test/hook.js'}
`
	const location = "https://example.test/module"
	const scriptURL = "https://example.test/hook.js"
	const hook = "$done({})"
	for _, tc := range []struct {
		format, fields, body, argument, argumentType string
		scriptLine                                   int
	}{
		{"loon", ", arguments: {PROXY: direct, Player: override}", loon, "", "object", 10},
		{"stash", ", format: stash", stash, "sample", "", 9},
	} {
		t.Run(tc.format, func(t *testing.T) {
			def := model.Module{URL: location}
			root := resource.Hash([]byte(tc.body))
			scriptRequest := resource.Hash([]byte(scriptURL))
			scriptHash := resource.Hash([]byte(hook))
			sources := fmt.Sprintf(`sources:
  - id: filters
    module: {format: %s, request: %s}
    lock:
      root: %s
      resources:
        - {kind: script, id: %s, request: %s, hash: %s}
`, tc.format, def.RequestHash(), root, scriptRequest[:16], scriptRequest, scriptHash)
			profile := fmt.Sprintf("schema-version: 1\nmodules: [{id: filters, url: %s%s}]\n", location, tc.fields)
			eff := compileModule(t, profile, Options{
				Sources: []byte(sources),
				ReadResource: func(hash string) ([]byte, error) {
					switch hash {
					case root:
						return []byte(tc.body), nil
					case scriptHash:
						return []byte(hook), nil
					}
					return nil, resource.ErrCorrupt
				},
			})
			report := eff.Modules["filters"]
			if report.Format != tc.format || report.Rules.Imported != 1 || report.Rewrites.Imported != 1 || report.Scripts.Imported != 1 {
				t.Fatalf("module report = %+v", report)
			}
			if len(eff.Rules) == 0 || eff.Rules[0].Target != "direct" || !slices.Equal(eff.MITM.Hostnames, []string{"example.test"}) || len(eff.Scripts) != 1 {
				t.Fatalf("unexpected composition: rules = %v, MITM = %+v, scripts = %v", eff.Rules, eff.MITM, eff.Scripts)
			}
			got := eff.Scripts[0]
			if got.Format != tc.format || got.ArgumentType != tc.argumentType || got.Hash != scriptHash || got.Origin.Line != tc.scriptLine {
				t.Fatalf("compiled script = %+v", got)
			}
			if tc.argumentType == "object" {
				var argument map[string]any
				if err := json.Unmarshal([]byte(got.Argument), &argument); err != nil || len(argument) != 2 || argument["Player"] != "override" || argument["Enabled"] != true {
					t.Fatalf("compiled object argument = %q (%v)", got.Argument, err)
				}
			} else if got.Argument != tc.argument {
				t.Fatalf("compiled string argument = %q", got.Argument)
			}
			rewrite := eff.HTTPRewrite.Request(httprewrite.Request{URL: "https://example.test/blocked"})
			if rewrite.Local == nil || rewrite.Local.StatusCode != 200 {
				t.Fatalf("unexpected rewrite = %+v", rewrite)
			}
		})
	}
}

func TestModuleMITMLayersAndOverlay(t *testing.T) {
	const body = `[MITM]
hostname = %INSERT% -insert.example.com:0
hostname = %APPEND% append.example.com
h2 = true
skip-server-cert-verify = true
[URL Rewrite]
^https://example\.com/ - reject-200
`
	const second = `[MITM]
hostname = %INSERT% second.example.com:8443
hostname = %APPEND% after.example.net
h2 = false
skip-server-cert-verify = false
`
	const secondURL = "https://example.net/second.sgmodule"
	opts := moduleOptions(body)
	opts.Sources = append(opts.Sources, []byte(moduleSnapshot("second", secondURL, second))...)
	opts.Sources = append(opts.Sources, []byte(`  - id: native
    mitm: {hostnames: [source.example.net], h2: false, skip-server-cert-verify: true}
    http-rewrites: [{id: native, match: '^https://example\.com/', action: reject, response: gif}]
`)...)
	read := opts.ReadResource
	opts.ReadResource = func(hash string) ([]byte, error) {
		if hash == resource.Hash([]byte(second)) {
			return []byte(second), nil
		}
		return read(hash)
	}
	profile := moduleProfile + `  - {id: second, url: https://example.net/second.sgmodule}
imports: [{source: native, rewrites: true}]
mitm: {hostnames: ['*.example.com'], h2: true}
http-rewrites: [{id: own, match: '^https://example\.com/', action: reject, response: dict}]
`
	eff := compileModule(t, profile, opts)
	want := []string{"-insert.example.com:0", "second.example.com:8443", "*.example.com", "source.example.net", "append.example.com", "after.example.net"}
	if !slices.Equal(eff.MITM.Hostnames, want) || !eff.MITM.H2 || eff.MITM.SkipServerCertVerify {
		t.Fatalf("MITM composition: %+v", eff.MITM)
	}
	o, _ := eff.OriginOf("/mitm/h2")
	if o.Layer != LayerProfile || o.Overrides == nil || o.Overrides.Source != "second" ||
		o.Overrides.Overrides == nil || o.Overrides.Overrides.Source != "filter" ||
		o.Overrides.Overrides.Overrides == nil || o.Overrides.Overrides.Overrides.Source != "native" {
		t.Fatalf("unexpected h2 origin chain: %+v", o)
	}
	var modulePath string
	for path, origin := range eff.Provenance {
		if strings.HasPrefix(path, "/http-rewrites/filter~1u-") && origin.Layer == LayerModule && origin.Line == 7 {
			modulePath = path
		}
	}
	if modulePath == "" || eff.HTTPRewrite == nil {
		t.Fatalf("missing module rewrite: %v", eff.Provenance)
	}
	request := httprewrite.Request{URL: "https://example.com/item"}
	if rewrite := eff.HTTPRewrite.Request(request); rewrite.Local == nil || rewrite.Local.StatusCode != 200 ||
		len(rewrite.MatchedIDs) != 1 || !strings.HasPrefix(rewrite.MatchedIDs[0], "filter/u-") {
		t.Fatalf("module rewrite did not run before imported and profile rewrites: %+v", rewrite)
	}
	opts.Overlay = []byte(fmt.Sprintf(`patches:
  - {op: remove, path: %s}
  - {op: remove, path: '/mitm/hostnames/#0'}
  - {op: set, path: /mitm/h2, value: false}
`, modulePath))
	eff = compileModule(t, profile, opts)
	if !slices.Equal(eff.MITM.Hostnames, want[1:]) || eff.MITM.H2 {
		t.Fatalf("overlaid MITM: %+v", eff.MITM)
	}
	if origin, _ := eff.OriginOf("/mitm/hostnames/#0"); origin.Layer != LayerModule || origin.Source != "second" || origin.Line != 2 {
		t.Fatalf("unexpected shifted origin: %+v", origin)
	}
	if _, ok := eff.Provenance[modulePath]; ok {
		t.Fatalf("removed rewrite retains provenance at %s", modulePath)
	}
	if rewrite := eff.HTTPRewrite.Request(request); !slices.Equal(rewrite.MatchedIDs, []string{"native/native"}) {
		t.Fatalf("imported rewrite did not run before the profile rewrite: %+v", rewrite)
	}
}

func TestModuleDigestsAndCompactReports(t *testing.T) {
	body := "#!arguments=unused:old\n[Rule]\nDOMAIN,example.com,DIRECT\n"
	first := compileModule(t, moduleProfile, moduleOptions(body))
	for _, tc := range []struct{ profile, body string }{
		{moduleProfile, body + "# module note\n"},
		{strings.Replace(moduleProfile, "{id: filter,", "{id: filter, arguments: {unused: new},", 1), body},
		{strings.Replace(moduleProfile, "{id: filter,", "{id: filter, enabled: false,", 1), body},
	} {
		next := compileModule(t, tc.profile, moduleOptions(tc.body))
		if next.SourceHashes["filter"] == first.SourceHashes["filter"] ||
			next.HTTPRewriteFingerprint == first.HTTPRewriteFingerprint {
			t.Fatalf("fingerprints did not reflect a module change: %v", next.SourceHashes)
		}
	}
	opts := moduleOptions(body)
	opts.OmitProvenance = true
	eff := compileModule(t, moduleProfile, opts)
	report := eff.Modules["filter"]
	if !report.CanApply || len(report.Lines) != 0 || report.Rules.Imported != 1 {
		t.Fatalf("unexpected compact report: %+v", report)
	}
}
