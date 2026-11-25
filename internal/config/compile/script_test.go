package compile

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/MimoProxy/reka/internal/config/model"
	"github.com/MimoProxy/reka/internal/resource"
	"go.yaml.in/yaml/v3"
)

const scriptSource = `console.log("script source")`
const scriptPattern = `^https://example\.test/`

func scriptProfile(fields string) []byte {
	return []byte("schema-version: 1\nscripts: [{" + fields + "}]\n")
}

func scriptReader(data string) func(string) ([]byte, error) {
	return func(hash string) ([]byte, error) {
		if hash != resource.Hash([]byte(data)) {
			return nil, resource.ErrCorrupt
		}
		return []byte(data), nil
	}
}

func TestScriptDefaultsAndLimits(t *testing.T) {
	hash := resource.Hash([]byte(scriptSource))
	fields := fmt.Sprintf("id: sample, type: http-request, pattern: '%s', hash: %s", scriptPattern, hash)
	opts := Options{ReadResource: scriptReader(scriptSource)}
	for _, tc := range []struct {
		name, fields string
		maxSize      int64
		timeout      int
		engine       string
		format       string
	}{
		{"defaults", "", ScriptDefaultMaxSize, model.DefaultScriptTimeout, "auto", "surge"},
		{"unbounded negative", ", max-size: -1", ScriptMaxBodySize, model.DefaultScriptTimeout, "auto", "surge"},
		{"unbounded zero", ", max-size: 0", ScriptMaxBodySize, model.DefaultScriptTimeout, "auto", "surge"},
		{"positive", ", max-size: 1024, timeout: 1, engine: jsc, format: loon", 1024, 1, "jsc", "loon"},
		{"capped", ", max-size: 4294967296, timeout: 3600, engine: webview, format: stash", ScriptMaxBodySize, 3600, "webview", "stash"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			eff, ds := Compile(scriptProfile(fields+tc.fields), nil, opts)
			if ds.HasErrors() || len(eff.Scripts) != 1 || eff.ScriptFingerprint == "" {
				t.Fatalf("script compile: %v", ds)
			}
			got := eff.Scripts[0]
			if !got.Supported || got.Type != "http-request" || got.Pattern != scriptPattern || got.Hash != hash || got.Path != "sample" ||
				got.MaxSize != tc.maxSize || got.Timeout != tc.timeout || got.Engine != tc.engine || got.Format != tc.format ||
				got.RequiresBody || got.BinaryBodyMode || got.Origin.Layer != LayerProfile || got.Origin.Path != "/scripts/sample" {
				t.Fatalf("script = %+v", got)
			}
		})
	}

	t.Run("explicit settings", func(t *testing.T) {
		fields := strings.Replace(fields, "http-request", "http-response", 1)
		fields += `, name: Sample, requires-body: true, binary-body-mode: true, argument: ' a=1,b=2 ', download: {url: 'secret://script-url'}`
		eff, ds := Compile(scriptProfile(fields), nil, opts)
		if ds.HasErrors() {
			t.Fatal(ds)
		}
		got := eff.Scripts[0]
		if !got.Supported || got.Type != "http-response" || got.Name != "Sample" || !got.RequiresBody || !got.BinaryBodyMode || got.Argument != " a=1,b=2 " || got.Path != "secret://script-url" {
			t.Fatalf("script = %+v", got)
		}
		serialized, err := json.Marshal(eff)
		if err != nil || !strings.Contains(string(serialized), `"scripts":[{"id":"sample"`) ||
			strings.Contains(string(serialized), "script source") || strings.Contains(string(serialized), "secret://script-url") {
			t.Fatalf("effective JSON = %s, err = %v", serialized, err)
		}
	})

	t.Run("absolute file", func(t *testing.T) {
		// Compilation validates the path without reading the original file.
		file := filepath.Join(t.TempDir(), "script.js")
		path, err := json.Marshal(file)
		if err != nil {
			t.Fatal(err)
		}
		eff, ds := Compile(scriptProfile(fields+", file: "+string(path)), nil, opts)
		if ds.HasErrors() {
			t.Fatal(ds)
		}
		if eff.Scripts[0].Path != file {
			t.Fatalf("path = %q", eff.Scripts[0].Path)
		}
	})
}

func TestScriptSourceUsesLockedReader(t *testing.T) {
	data := []byte(scriptSource)
	hash := resource.Hash(data)
	fields := fmt.Sprintf("id: sample, type: http-request, pattern: '%s', hash: %s", scriptPattern, hash)
	var reads int
	eff, ds := Compile(scriptProfile(fields), nil, Options{ReadResource: func(string) ([]byte, error) {
		reads++
		return data, nil
	}})
	if ds.HasErrors() || reads != 1 {
		t.Fatalf("compile = %v, reads = %d", ds, reads)
	}
	if !keepScriptReader {
		if _, err := eff.ScriptSource(hash); err == nil || reads != 1 {
			t.Fatalf("source err = %v, reads = %d", err, reads)
		}
		return
	}
	got, err := eff.ScriptSource(hash)
	if err != nil || string(got) != scriptSource || reads != 2 {
		t.Fatalf("source = %q, err = %v, reads = %d", got, err, reads)
	}
	data = []byte("changed")
	if _, err := eff.ScriptSource(hash); err == nil {
		t.Fatal("loaded a script whose content no longer matches its locked hash")
	}
}

func TestScriptFieldValidation(t *testing.T) {
	hash := resource.Hash([]byte(scriptSource))
	reader := scriptReader(scriptSource)
	defaultFields := "id: sample, type: http-response, pattern: '^https://example\\.test/', hash: " + hash
	for _, tc := range []struct {
		name, fields, code, path string
		reader                   func(string) ([]byte, error)
	}{
		{"missing id", strings.TrimPrefix(defaultFields, "id: sample, "), "schema.id", "/scripts/#0/id", reader},
		{"invalid id", strings.Replace(defaultFields, "id: sample", "id: bad/id", 1), "schema.id", "/scripts/bad~1id/id", reader},
		{"missing type", strings.Replace(defaultFields, "type: http-response, ", "", 1), "script.type", "/scripts/sample/type", reader},
		{"unknown type", strings.Replace(defaultFields, "http-response", "unknown", 1), "script.type", "/scripts/sample/type", reader},
		{"missing pattern", "id: sample, type: http-request, hash: " + hash, "script.pattern", "/scripts/sample/pattern", reader},
		{"empty pattern", "id: sample, type: http-request, pattern: '', hash: " + hash, "script.pattern", "/scripts/sample/pattern", reader},
		{"lookahead pattern", strings.Replace(defaultFields, scriptPattern, `(?=bad)`, 1), "script.pattern", "/scripts/sample/pattern", reader},
		{"negative limit", defaultFields + ", max-size: -2", "script.max-size", "/scripts/sample/max-size", reader},
		{"zero timeout", defaultFields + ", timeout: 0", "script.timeout", "/scripts/sample/timeout", reader},
		{"too long timeout", defaultFields + ", timeout: 3601", "script.timeout", "/scripts/sample/timeout", reader},
		{"invalid engine", defaultFields + ", engine: other", "script.engine", "/scripts/sample/engine", reader},
		{"invalid format", defaultFields + ", format: other", "script.format", "/scripts/sample/format", reader},
		{"missing hash", strings.TrimSuffix(defaultFields, ", hash: "+hash), "script.resource", "/scripts/sample/hash", reader},
		{"invalid hash", strings.Replace(defaultFields, hash, "wrong", 1), "script.resource", "/scripts/sample/hash", reader},
		{"missing reader", defaultFields, "script.resource", "/scripts/sample/hash", nil},
		{"missing blob", defaultFields, "script.resource", "/scripts/sample/hash", scriptReader("different")},
		{"corrupt blob", defaultFields, "script.resource", "/scripts/sample/hash", func(string) ([]byte, error) { return []byte("different"), nil }},
		{"empty blob", defaultFields, "script.resource", "/scripts/sample/hash", func(string) ([]byte, error) { return nil, nil }},
		{"oversized blob", defaultFields, "script.resource", "/scripts/sample/hash", func(string) ([]byte, error) { return make([]byte, model.MaxScriptSize+1), nil }},
		{"invalid download", defaultFields + `, download: {url: 'ftp://example.test/test.js'}`, "resource.download", "/scripts/sample/download", reader},
		{"invalid interval", defaultFields + `, download: {url: 'https://example.test/test.js', interval: 299}`, "resource.download", "/scripts/sample/download", reader},
		{"relative file", defaultFields + `, file: script.js`, "script.file", "/scripts/sample/file", reader},
		{"file with NUL", defaultFields + `, file: "script.js\0"`, "script.file", "/scripts/sample/file", reader},
		{"both sources", defaultFields + `, file: script.js, download: {url: 'https://example.test/test.js'}`, "script.source", "/scripts/sample/file", reader},
	} {
		t.Run(tc.name, func(t *testing.T) {
			eff, ds := Compile(scriptProfile(tc.fields), nil, Options{ReadResource: tc.reader})
			if eff != nil || !slices.ContainsFunc(ds, func(d model.Diagnostic) bool {
				return d.Code == tc.code && d.Path == tc.path && d.Severity == model.SeverityError
			}) {
				t.Fatalf("expected %s at %s: %v", tc.code, tc.path, ds)
			}
		})
	}
}

func TestUnsupportedScriptTypes(t *testing.T) {
	for _, typ := range []string{"cron", "generic", "event", "dns", "rule"} {
		t.Run(typ, func(t *testing.T) {
			eff, ds := Compile(scriptProfile("id: sample, type: "+typ+`, pattern: '(?=ignored)', requires-body: true`), nil, Options{})
			if ds.HasErrors() || len(eff.Scripts) != 1 || eff.Scripts[0].Supported || eff.Scripts[0].Type != typ {
				t.Fatalf("unsupported script: %v", ds)
			}
			if len(ds) != 1 || ds[0].Severity != model.SeverityWarning || ds[0].Code != "script.unsupported-type" || ds[0].Path != "/scripts/sample/type" {
				t.Fatalf("unsupported script diagnostics: %v", ds)
			}
		})
	}
}

func TestScriptsComposeWithModuleSourceAndOverlay(t *testing.T) {
	const location = "https://example.test/script.js"
	const moduleText = `[Map Local]
^https://example\.test/local$, data=` + location + `
[Script]
Module Script = type=http-response,pattern="` + scriptPattern + `",script-path=` + location + `
`
	moduleHash := resource.Hash([]byte(moduleText))
	request := resource.Hash([]byte(location))
	scriptHash := resource.Hash([]byte(scriptSource))
	mapHash := resource.Hash([]byte("substitute"))
	sources := fmt.Sprintf(`sources:
  - id: filter
    module: {format: surge, request: %s}
    lock:
      root: %s
      resources:
        - {id: %s, kind: map-local, request: %s, hash: %s}
        - {id: %s, kind: script, request: %s, hash: %s}
  - id: native
    scripts: [{id: imported, type: http-request, pattern: '%s', hash: %s}]
`, (model.Module{URL: moduleLocation}).RequestHash(), moduleHash, request[:24], request, mapHash, request[:24], request, scriptHash, scriptPattern, scriptHash)
	profile := moduleProfile + fmt.Sprintf(`imports: [{source: native, rewrites: true}]
scripts: [{id: own, type: http-response, pattern: '%s', hash: %s}]
`, scriptPattern, scriptHash)
	opts := Options{Sources: []byte(sources), ReadResource: func(hash string) ([]byte, error) {
		switch hash {
		case moduleHash:
			return []byte(moduleText), nil
		case scriptHash:
			return []byte(scriptSource), nil
		case mapHash:
			return []byte("substitute"), nil
		default:
			return nil, resource.ErrCorrupt
		}
	}}
	eff := compileModule(t, profile, opts)
	if len(eff.Scripts) != 3 || eff.HTTPRewrite == nil || eff.Modules["filter"].Scripts.Imported != 1 {
		t.Fatalf("module, source and profile script composition = %+v", eff.Scripts)
	}
	mod, src, own := eff.Scripts[0], eff.Scripts[1], eff.Scripts[2]
	if !strings.HasPrefix(mod.ID, "filter/s-") || mod.Name != "Module Script" || mod.Hash != scriptHash || mod.Module != "filter" ||
		mod.Origin.Layer != LayerModule || mod.Origin.Line != 4 || mod.Origin.Source != "filter" {
		t.Errorf("module script = %+v", mod)
	}
	if src.ID != "native/imported" || src.Module != "" || src.Origin.Layer != LayerSource || src.Origin.Path != "/sources/native/scripts/imported" {
		t.Errorf("source script = %+v", src)
	}
	if own.ID != "own" || own.Module != "" || own.Origin.Layer != LayerProfile {
		t.Errorf("profile script = %+v", own)
	}
	path := model.JoinPath("/scripts", mod.ID)
	opts.Overlay = []byte(fmt.Sprintf(`patches:
  - {op: remove, path: '%s'}
  - {op: set, path: /scripts/native~1imported/timeout, value: 10}
`, path))
	patched := compileModule(t, profile, opts)
	if len(patched.Scripts) != 2 || patched.Scripts[0].ID != src.ID || patched.Scripts[0].Timeout != 10 || patched.Scripts[1].ID != own.ID ||
		patched.ScriptFingerprint == eff.ScriptFingerprint {
		t.Fatalf("overlay scripts = %+v", patched.Scripts)
	}
	origin, ok := patched.OriginOf("/scripts/native~1imported/timeout")
	if !ok || origin.Layer != LayerOverlay || origin.Overrides == nil || origin.Overrides.Layer != LayerSource {
		t.Fatalf("overlay script field origin = %+v", origin)
	}
	opts.Overlay = nil
	replaced := compileModule(t, strings.Replace(profile, "id: own", "id: native/imported", 1), opts)
	if len(replaced.Scripts) != 2 || replaced.Scripts[1].Origin.Layer != LayerProfile || replaced.Scripts[1].Origin.Overrides == nil ||
		replaced.Scripts[1].Origin.Overrides.Layer != LayerSource {
		t.Fatalf("profile script replacement = %+v", replaced.Scripts)
	}
}

func TestScriptSourceAndOverlayDiagnosticPaths(t *testing.T) {
	const profile = `schema-version: 1
imports: [{source: native, rewrites: true}]
`
	hash := resource.Hash([]byte(scriptSource))
	const source = `sources:
  - id: native
    scripts: [{id: imported, type: http-request, hash: %s}]
`
	for _, tc := range []struct{ overlay, doc, path string }{
		{"", model.DocSources, "/sources/native/scripts/imported/pattern"},
		{"patches: [{op: set, path: /scripts/native~1imported/pattern, value: '(?=bad)'}]", model.DocOverlay, "/patches/#0/value"},
	} {
		opts := Options{Sources: []byte(fmt.Sprintf(source, hash)), Overlay: []byte(tc.overlay), ReadResource: scriptReader(scriptSource)}
		_, ds := Compile([]byte(profile), nil, opts)
		if !slices.ContainsFunc(ds, func(d model.Diagnostic) bool {
			return d.Code == "script.pattern" && d.Document == tc.doc && d.Path == tc.path && d.Line != 0
		}) {
			t.Errorf("expected %s at %s: %v", tc.doc, tc.path, ds)
		}
	}
	unselected, ds := Compile([]byte(strings.Replace(profile, "rewrites: true", "outbounds: true", 1)), nil,
		Options{Sources: []byte(fmt.Sprintf(source, hash))})
	if ds.HasErrors() || len(unselected.Scripts) != 0 {
		t.Fatalf("unselected source scripts: %v", ds)
	}
}

func TestScriptDuplicateIDs(t *testing.T) {
	const profile = `schema-version: 1
scripts: [{id: dup, type: cron}, {id: dup, type: generic}]
`
	const overlay = `patches: [{op: remove, path: /scripts/dup}]`
	if _, ds := Compile([]byte(profile), nil, Options{Overlay: []byte(overlay)}); !slices.ContainsFunc(ds, func(d model.Diagnostic) bool {
		return d.Code == "schema.duplicate-id" && d.Path == "/scripts/dup/id"
	}) {
		t.Fatalf("missing duplicate script ID error: %v", ds)
	}
	const sources = `sources:
  - id: native
    scripts: [{id: dup, type: cron}, {id: dup, type: generic}]
`
	if _, ds := Compile([]byte("schema-version: 1"), nil, Options{Sources: []byte(sources)}); !slices.ContainsFunc(ds, func(d model.Diagnostic) bool {
		return d.Code == "schema.duplicate-id" && d.Path == "/sources/native/scripts/dup/id"
	}) {
		t.Fatalf("missing duplicate source script ID error: %v", ds)
	}
}

func TestScriptFingerprint(t *testing.T) {
	compile := func(text, pattern string) string {
		return compileModule(t, string(scriptProfile(fmt.Sprintf("id: sample, type: http-request, pattern: '%s', hash: %s", pattern, resource.Hash([]byte(text))))),
			Options{ReadResource: scriptReader(text)}).ScriptFingerprint
	}
	first := compile(scriptSource, scriptPattern)
	if first == "" || first != compile(scriptSource, scriptPattern) || first == compile(scriptSource+";", scriptPattern) || first == compile(scriptSource, "example") {
		t.Fatal("script fingerprint must be stable and include the definition and source hash")
	}
}

func TestModuleScriptSnapshotLimits(t *testing.T) {
	root := resource.Hash([]byte("module root"))
	src := model.Source{Module: &model.ModuleSnapshot{Format: model.ModuleFormatSurge, Request: root}, Lock: &model.SourceLock{Root: root}}
	node := &yaml.Node{Kind: yaml.MappingNode}
	for _, tc := range []struct {
		maps, scripts int
		valid         bool
	}{
		{model.MaxModuleResources, model.MaxModuleScripts, true},
		{model.MaxModuleResources + 1, 1, false},
		{1, model.MaxModuleScripts + 1, false},
	} {
		src.Lock.Resources = nil
		for kind, count := range map[string]int{"map-local": tc.maps, "script": tc.scripts} {
			for i := range count {
				request := resource.Hash([]byte(fmt.Sprintf("entry-%d", i)))
				src.Lock.Resources = append(src.Lock.Resources, model.ResourceLock{ID: request[:24], Kind: kind, Request: request, Hash: root})
			}
		}
		if err := validateModuleSnapshot(src, node); (err == nil) != tc.valid {
			t.Errorf("snapshot with %d Map Local and %d script entries: %v", tc.maps, tc.scripts, err)
		}
	}
}
