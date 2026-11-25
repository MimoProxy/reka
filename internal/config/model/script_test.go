package model

import (
	"strings"
	"testing"
)

func TestDecodeScripts(t *testing.T) {
	const script = `{id: inspect-response, name: Inspect, type: http-response, pattern: '^https://example\.test/', requires-body: true, binary-body-mode: false, max-size: 4294967296, timeout: 15, argument: 'a=1&b=2', engine: webview, format: stash, hash: abc, download: {url: 'secret://scripts/source', automatic: true}}`
	profile, positions, ds := ParseProfile([]byte("schema-version: 1\nscripts: [" + script + "]"))
	if ds.HasErrors() || len(profile.Scripts) != 1 {
		t.Fatal(ds)
	}
	s := profile.Scripts[0]
	if s.ID != "inspect-response" || *s.Name != "Inspect" || s.Type != "http-response" ||
		*s.Pattern != `^https://example\.test/` || !*s.RequiresBody || *s.BinaryBodyMode || *s.MaxSize != 4294967296 || *s.Timeout != 15 ||
		*s.Argument != "a=1&b=2" || *s.Engine != "webview" || *s.Format != "stash" || *s.Hash != "abc" || s.File != nil ||
		s.Download.URL != "secret://scripts/source" || !s.Download.Automatic || s.Download.WithDefaultInterval().Interval != DefaultResourceInterval {
		t.Fatalf("unexpected decoded script: %+v", s)
	}
	if positions["/scripts/inspect-response/id"].Line != 2 || positions["/scripts/inspect-response/download/url"].Line != 2 {
		t.Fatal(positions)
	}
	sources, positions, ds := ParseSources([]byte("sources: [{id: provider, scripts: [" + script + "]}]"))
	if ds.HasErrors() || len(sources.Sources) != 1 || len(sources.Sources[0].Scripts) != 1 || positions["/sources/provider/scripts/inspect-response/id"].Line != 1 {
		t.Fatal(sources, positions, ds)
	}
}

func TestDecodeScriptFieldDiagnostics(t *testing.T) {
	for _, tc := range []struct{ name, input, path, code string }{
		{"unknown field", `{id: check, options: {}}`, "/scripts/check/options", "schema.unknown-field"},
		{"unknown download field", `{id: check, download: {policy: direct}}`, "/scripts/check/download/policy", "schema.unknown-field"},
		{"non-scalar ID", `{id: [check]}`, "/scripts/#0/id", "yaml.type"},
		{"integer overflow", `{id: check, max-size: 9223372036854775808}`, "/scripts/check/max-size", "yaml.type"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, ds := ParseProfile([]byte("schema-version: 1\nscripts: [" + tc.input + "]"))
			if len(ds) != 1 || ds[0].Code != tc.code || ds[0].Path != tc.path {
				t.Fatalf("unexpected diagnostics: %+v", ds)
			}
		})
	}
}

func TestScriptDownloadURLsMaskAndRestore(t *testing.T) {
	const raw = `https://cdn.example.test/script?token=private-value`
	for _, tc := range []struct {
		doc, input string
		count      int
	}{
		{DocProfile, "scripts: [{id: check, download: {url: '" + raw + "'}}, {id: secret, download: {url: 'secret://scripts/source'}}]", 1},
		{DocSources, "sources: [{id: provider, scripts: [{id: check, download: {url: '" + raw + "'}}]}]", 1},
		{DocOverlay, `patches:
  - {op: insert, path: /scripts, value: {id: new, download: {url: '` + raw + `'}}}
  - {op: set, path: /scripts/source~1modify, value: {id: source/modify, download: {url: '` + raw + `'}}}
  - {op: set, path: /scripts/check/download, value: {url: '` + raw + `'}}
  - {op: set, path: /scripts/check/download/url, value: '` + raw + `'}
`, 4},
	} {
		t.Run(tc.doc, func(t *testing.T) {
			base, ds := LoadDoc(tc.doc, []byte(tc.input))
			if ds.HasErrors() {
				t.Fatal(ds)
			}
			masked, _ := LoadDoc(tc.doc, []byte(tc.input))
			if masked.MaskSecrets() != tc.count || strings.Contains(string(masked.Bytes()), "private-value") {
				t.Fatal("script download credential leaked")
			}
			if err := masked.UnmaskSecrets(base); err != nil || string(masked.Bytes()) != string(base.Bytes()) {
				t.Fatal("script download credential was not restored", err)
			}
		})
	}
}

func TestMaskedScriptInsertCannotChangeID(t *testing.T) {
	const input = `patches: [{op: insert, path: /scripts, value: {id: original, download: {url: 'https://cdn.example.test/script?token=private-value'}}}]`
	base, _ := LoadDoc(DocOverlay, []byte(input))
	modified, _ := LoadDoc(DocOverlay, []byte(strings.ReplaceAll(input, "original", "edited")))
	modified.MaskSecrets()
	if err := modified.UnmaskSecrets(base); err == nil {
		t.Fatal("a different script inherited the stored credential")
	}
}
