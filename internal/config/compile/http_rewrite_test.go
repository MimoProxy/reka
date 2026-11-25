package compile

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/MimoProxy/reka/internal/config/model"
	"github.com/MimoProxy/reka/internal/httprewrite"
	"github.com/MimoProxy/reka/internal/resource"
)

func TestMITMDefaultsAndLocalCA(t *testing.T) {
	for _, tc := range []struct {
		name, local, ca string
		enabled, log    bool
	}{
		{name: "default"},
		{name: "disabled with CA", local: "mitm: {enabled: false, ca: 'secret://mitm/ca'}", ca: "secret://mitm/ca"},
		{name: "enabled with unresolved CA", local: "mitm: {enabled: true, ca: 'secret://mitm/ca'}", ca: "secret://mitm/ca", enabled: true},
		{name: "script log", local: "mitm: {script-log: true}", log: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			eff, diags := Compile([]byte("schema-version: 1"), []byte(tc.local), Options{})
			if diags.HasErrors() {
				t.Fatal(diags)
			}
			if got := eff.MITM; got.Enabled != tc.enabled || got.CA != tc.ca || got.ScriptLog != tc.log || got.H2 || got.SkipServerCertVerify || !got.QUICBlock {
				t.Fatalf("MITM = %+v", got)
			}
			if eff.HTTPRewrite != nil || eff.HTTPRewriteFingerprint != "" {
				t.Fatal("empty rules should have no set or fingerprint")
			}
		})
	}
}

func TestMITMAndRewriteValidation(t *testing.T) {
	const localOnly = "mitm.local-only"
	const invalid = "rewrite.invalid"
	for _, tc := range []struct {
		name, doc, yaml, code, path string
	}{
		{"CA required", model.DocLocal, `mitm: {enabled: true}`, "mitm.ca", "/mitm/ca"},
		{"inline CA", model.DocLocal, `mitm: {ca: inline}`, "mitm.ca", "/mitm/ca"},
		{"invalid CA name", model.DocLocal, `mitm: {ca: 'secret://../ca'}`, "mitm.ca", "/mitm/ca"},
		{"other secret", model.DocLocal, `mitm: {ca: 'secret://tls/example'}`, "mitm.ca", "/mitm/ca"},
		{"local hostname", model.DocLocal, `mitm: {hostnames: [example.test]}`, "schema.unknown-field", "/mitm/hostnames"},
		{"local client source", model.DocLocal, `mitm: {client-source-address: ['192.0.2.1']}`, "schema.unknown-field", "/mitm/client-source-address"},
		{"enabled in profile", model.DocProfile, `mitm: {enabled: false}`, localOnly, "/mitm/enabled"},
		{"CA in profile", model.DocProfile, `mitm: {ca: 'secret://mitm/ca'}`, localOnly, "/mitm/ca"},
		{"script log in profile", model.DocProfile, `mitm: {script-log: true}`, localOnly, "/mitm/script-log"},
		{"enabled in source", model.DocSources, `sources: [{id: ads, mitm: {enabled: true}}]`, localOnly, "/sources/ads/mitm/enabled"},
		{"CA in source", model.DocSources, `sources: [{id: ads, mitm: {ca: 'secret://mitm/ca'}}]`, localOnly, "/sources/ads/mitm/ca"},
		{"script log in source", model.DocSources, `sources: [{id: ads, mitm: {script-log: true}}]`, localOnly, "/sources/ads/mitm/script-log"},
		{"enabled in overlay", model.DocOverlay, `patches: [{op: set, path: /mitm/enabled, value: false}]`, localOnly, "/patches/#0/path"},
		{"CA in overlay", model.DocOverlay, `patches: [{op: set, path: /mitm, value: {ca: 'secret://mitm/ca'}}]`, localOnly, "/patches/#0/value/ca"},
		{"script log in overlay", model.DocOverlay, `patches: [{op: set, path: /mitm/script-log, value: true}]`, localOnly, "/patches/#0/path"},
		{"invalid hostname", model.DocProfile, `mitm: {hostnames: ['']}`, "mitm.hostname", "/mitm/hostnames/#0"},
		{"invalid port", model.DocProfile, `mitm: {hostnames: ['example.test:65536']}`, "mitm.hostname", "/mitm/hostnames/#0"},
		{"invalid hostname character", model.DocProfile, `mitm: {hostnames: ['example.test/path']}`, "mitm.hostname", "/mitm/hostnames/#0"},
		{"invalid inserted hostname", model.DocOverlay, `patches: [{op: insert, path: /mitm/hostnames, value: '-'}]`, "mitm.hostname", "/patches/#0/value"},
		{"empty client source", model.DocProfile, `mitm: {client-source-address: ['']}`, "mitm.client-source-address", "/mitm/client-source-address/#0"},
		{"empty client source exclusion", model.DocProfile, `mitm: {client-source-address: ['-']}`, "mitm.client-source-address", "/mitm/client-source-address/#0"},
		{"invalid client source address", model.DocProfile, `mitm: {client-source-address: ['example.test']}`, "mitm.client-source-address", "/mitm/client-source-address/#0"},
		{"invalid client source prefix", model.DocProfile, `mitm: {client-source-address: ['192.0.2.0/33']}`, "mitm.client-source-address", "/mitm/client-source-address/#0"},
		{"scoped client source address", model.DocProfile, `mitm: {client-source-address: ['fe80::1%link']}`, "mitm.client-source-address", "/mitm/client-source-address/#0"},
		{"invalid overlay client source", model.DocOverlay, `patches: [{op: set, path: /mitm, value: {client-source-address: ['-']}}]`, "mitm.client-source-address", "/patches/#0/value/client-source-address/#0"},
		{"unknown MITM field", model.DocProfile, `mitm: {http-2: true}`, "schema.unknown-field", "/mitm/http-2"},
		{"missing rewrite ID", model.DocProfile, `http-rewrites: [{match: '.*', action: reject}]`, "schema.id", "/http-rewrites/#0"},
		{"invalid rewrite ID", model.DocProfile, `http-rewrites: [{id: invalid/ID, match: '.*', action: reject}]`, "schema.id", "/http-rewrites/invalid~1ID/id"},
		{"duplicate rewrite ID", model.DocProfile, `http-rewrites: [{id: a, match: '.*', action: reject}, {id: a, match: '.*', action: reject}]`, "schema.duplicate-id", "/http-rewrites/a/id"},
		{"missing source ID", model.DocSources, `sources: [{id: ads, map-local: [{match: '.*', data-type: text, data: ok}]}]`, "source.id", "/sources/ads/map-local/#0"},
		{"unsupported URL regex", model.DocProfile, `http-rewrites: [{id: a, match: 'a(?=d)', action: reject}]`, invalid, "/http-rewrites/a/match"},
		{"invalid URL action", model.DocProfile, `http-rewrites: [{id: a, match: 'a', action: 301}]`, invalid, "/http-rewrites/a/action"},
		{"missing URL target", model.DocProfile, `http-rewrites: [{id: a, match: 'a', action: 302}]`, invalid, "/http-rewrites/a/target"},
		{"unexpected URL target", model.DocProfile, `http-rewrites: [{id: a, match: 'a', action: reject, target: b}]`, invalid, "/http-rewrites/a/target"},
		{"invalid reject response", model.DocProfile, `http-rewrites: [{id: a, match: 'a', action: reject, response: 401}]`, invalid, "/http-rewrites/a/response"},
		{"unexpected response", model.DocProfile, `http-rewrites: [{id: a, match: 'a', action: header, target: b, response: 200}]`, invalid, "/http-rewrites/a/response"},
		{"invalid header phase", model.DocProfile, `header-rewrites: [{id: a, match: 'a', phase: '', op: del, name: X-A}]`, invalid, "/header-rewrites/a/phase"},
		{"invalid header op", model.DocProfile, `header-rewrites: [{id: a, match: 'a', op: append, name: X-A}]`, invalid, "/header-rewrites/a/op"},
		{"invalid header name", model.DocProfile, `header-rewrites: [{id: a, match: 'a', op: del, name: 'X A'}]`, invalid, "/header-rewrites/a/name"},
		{"pseudo header", model.DocProfile, `header-rewrites: [{id: a, match: 'a', op: del, name: ':path'}]`, invalid, "/header-rewrites/a/name"},
		{"framing header", model.DocProfile, `header-rewrites: [{id: a, match: 'a', op: del, name: cOnTeNt-LeNgTh}]`, invalid, "/header-rewrites/a/name"},
		{"hop header", model.DocProfile, `header-rewrites: [{id: a, match: 'a', op: del, name: Upgrade}]`, invalid, "/header-rewrites/a/name"},
		{"invalid header value", model.DocProfile, `header-rewrites: [{id: a, match: 'a', op: replace, name: X-A, value: "a\nb"}]`, invalid, "/header-rewrites/a/value"},
		{"missing header value", model.DocProfile, `header-rewrites: [{id: a, match: 'a', op: add, name: X-A}]`, invalid, "/header-rewrites/a/value"},
		{"unexpected header value", model.DocProfile, `header-rewrites: [{id: a, match: 'a', op: del, name: X-A, value: ''}]`, invalid, "/header-rewrites/a/value"},
		{"invalid header regex", model.DocProfile, `header-rewrites: [{id: a, match: 'a', op: replace-regex, name: X-A, pattern: '(', value: ''}]`, invalid, "/header-rewrites/a/pattern"},
		{"missing body phase", model.DocProfile, `body-rewrites: [{id: a, match: 'a', jq: '.'}]`, invalid, "/body-rewrites/a/phase"},
		{"empty replace", model.DocProfile, `body-rewrites: [{id: a, match: 'a', phase: response, replace: []}]`, invalid, "/body-rewrites/a/replace"},
		{"invalid body regex", model.DocProfile, `body-rewrites: [{id: a, match: 'a', phase: response, replace: [{pattern: '(?=b)', value: ''}]}]`, invalid, "/body-rewrites/a/replace/#0/pattern"},
		{"invalid jq syntax", model.DocProfile, `body-rewrites: [{id: a, match: 'a', phase: response, jq: '('}]`, invalid, "/body-rewrites/a/jq"},
		{"invalid jq compile", model.DocProfile, `body-rewrites: [{id: a, match: 'a', phase: response, jq: 'unknown_function'}]`, invalid, "/body-rewrites/a/jq"},
		{"missing file hash", model.DocProfile, `map-local: [{id: a, match: 'a'}]`, invalid, "/map-local/a/hash"},
		{"bad file hash", model.DocProfile, `map-local: [{id: a, match: 'a', hash: wrong}]`, "rewrite.resource", "/map-local/a/hash"},
		{"invalid download", model.DocProfile, `map-local: [{id: a, match: 'a', download: {url: 'ftp://test', interval: 600}}]`, "resource.download", "/map-local/a/download"},
		{"unknown data type", model.DocProfile, `map-local: [{id: a, match: 'a', data-type: unknown}]`, invalid, "/map-local/a/data-type"},
		{"missing map-local data", model.DocProfile, `map-local: [{id: a, match: 'a', data-type: text}]`, invalid, "/map-local/a/data"},
		{"invalid JSON", model.DocProfile, `map-local: [{id: a, match: 'a', data-type: json, data: '{'}]`, invalid, "/map-local/a/data"},
		{"invalid base64", model.DocProfile, `map-local: [{id: a, match: 'a', data-type: base64, data: '?'}]`, invalid, "/map-local/a/data"},
		{"unexpected tiny GIF data", model.DocProfile, `map-local: [{id: a, match: 'a', data-type: tiny-gif, data: ''}]`, invalid, "/map-local/a/data"},
		{"invalid status", model.DocProfile, `map-local: [{id: a, match: 'a', data-type: tiny-gif, status-code: 1000}]`, invalid, "/map-local/a/status-code"},
		{"map-local framing header", model.DocProfile, `map-local: [{id: a, match: 'a', data-type: tiny-gif, headers: [{name: transfer-encoding, value: chunked}]}]`, invalid, "/map-local/a/headers/#0/name"},
		{"map-local unknown field", model.DocProfile, `map-local: [{id: a, match: 'a', type: tiny-gif}]`, "schema.unknown-field", "/map-local/a/type"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			profile := "schema-version: 1\n"
			var local []byte
			var opts Options
			switch tc.doc {
			case model.DocProfile:
				profile += tc.yaml
			case model.DocLocal:
				local = []byte(tc.yaml)
			case model.DocSources:
				opts.Sources = []byte(tc.yaml)
			case model.DocOverlay:
				opts.Overlay = []byte(tc.yaml)
			}
			eff, diags := Compile([]byte(profile), local, opts)
			if eff != nil || !slices.ContainsFunc(diags, func(d model.Diagnostic) bool {
				return d.Severity == model.SeverityError && d.Code == tc.code && d.Document == tc.doc && d.Path == tc.path
			}) {
				t.Fatalf("want %s at %s %s, got %v", tc.code, tc.doc, tc.path, diags)
			}
		})
	}
}

func TestMITMClientSourceMatcher(t *testing.T) {
	for _, tc := range []struct {
		name    string
		profile string
		allow   []string
		deny    []string
	}{
		{name: "omitted", allow: []string{"192.0.2.4", "2001:db8::1"}},
		{name: "empty", profile: `mitm: {client-source-address: []}`, allow: []string{"192.0.2.4", "2001:db8::1"}},
		{name: "inclusions and exclusions", profile: `mitm: {client-source-address: ['192.0.2.7/24', '2001:db8::1', '-192.0.2.32/28', '-192.0.2.200']}`,
			allow: []string{"192.0.2.4", "::ffff:192.0.2.4", "2001:db8::1"}, deny: []string{"192.0.2.35", "192.0.2.200", "198.51.100.1", "2001:db8::2"}},
		{name: "exclusions only", profile: `mitm: {client-source-address: ['-::ffff:192.0.2.0/120', '-2001:db8::/32']}`,
			allow: []string{"198.51.100.1", "2001:db9::1"}, deny: []string{"192.0.2.4", "::ffff:192.0.2.4", "2001:db8::1"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			eff, diags := Compile([]byte("schema-version: 1\n"+tc.profile), nil, Options{})
			if diags.HasErrors() {
				t.Fatal(diags)
			}
			match := eff.MITM.ClientSourceMatcher.Match
			for _, addr := range tc.allow {
				if !match(netip.MustParseAddr(addr)) {
					t.Errorf("source %s should match", addr)
				}
			}
			for _, addr := range tc.deny {
				if match(netip.MustParseAddr(addr)) {
					t.Errorf("source %s should be excluded", addr)
				}
			}
		})
	}
}

func TestMITMClientSourceFromRewriteImport(t *testing.T) {
	profile := `schema-version: 1
imports: [{source: example, rewrites: true}]
`
	opts := Options{Sources: []byte(`sources:
  - id: example
    mitm: {client-source-address: ['192.0.2.0/24', 'invalid']}
`)}
	eff, diags := Compile([]byte(profile), nil, opts)
	if eff != nil || !slices.ContainsFunc(diags, func(d model.Diagnostic) bool {
		return d.Code == "mitm.client-source-address" && d.Document == model.DocSources && d.Path == "/sources/example/mitm/client-source-address/#1"
	}) {
		t.Fatalf("wanted error in source list, got %+v, %v", eff, diags)
	}

	profile += `mitm: {client-source-address: ['198.51.100.0/24']}`
	eff, diags = Compile([]byte(profile), nil, opts)
	if diags.HasErrors() {
		t.Fatal(diags)
	}
	if !eff.MITM.ClientSourceMatcher.Match(netip.MustParseAddr("198.51.100.4")) || eff.MITM.ClientSourceMatcher.Match(netip.MustParseAddr("192.0.2.4")) {
		t.Fatal("profile source list must replace the imported list")
	}
}

func TestRewriteWarningsAndFingerprints(t *testing.T) {
	profile := `schema-version: 1
mitm: {hostnames: [dup.test, dup.test]}
http-rewrites:
  - {id: redirect, match: '^https://a\.test/(.*)', action: 302, target: 'https://b.test/$2'}
  - {id: reject, match: '^https://reject\.test/', action: reject, response: 200}
header-rewrites: [{id: add, match: 'a', op: add, name: X-A, value: '$9'}]
body-rewrites: [{id: body, match: 'a', phase: request, replace: [{pattern: '(a)', value: '$2'}]}]
map-local: [{id: local, match: '^https://local\.test/', hash: '%s', download: {url: 'https://example.test/test.JSON?version=2', interval: 86400}}]
`
	var reads []string
	opts := Options{ReadResource: func(hash string) ([]byte, error) {
		reads = append(reads, hash)
		if hash == resource.Hash([]byte(`[]`)) {
			return []byte(`[]`), nil
		}
		return []byte(`{}`), nil
	}}
	hash := resource.Hash([]byte(`{}`))
	eff, diags := Compile([]byte(fmt.Sprintf(profile, hash)), nil, opts)
	if diags.HasErrors() || eff.HTTPRewriteFingerprint == "" || eff.HTTPRewrite == nil || eff.MITM.Enabled {
		t.Fatalf("compile failed: %v", diags)
	}
	wantPaths := []string{"/mitm/hostnames/#1", "/http-rewrites/redirect/target", "/header-rewrites/add/value", "/body-rewrites/body/replace/#0/value"}
	for _, path := range wantPaths {
		if !slices.ContainsFunc(diags, func(d model.Diagnostic) bool { return d.Severity == model.SeverityWarning && d.Path == path }) {
			t.Errorf("missing warning at %s: %v", path, diags)
		}
	}
	if !slices.Equal(reads, []string{hash}) {
		t.Fatalf("reads at compile: %v", reads)
	}
	redirect := eff.HTTPRewrite.Request(httprewrite.Request{URL: "https://a.test/path"})
	reject := eff.HTTPRewrite.Request(httprewrite.Request{URL: "https://reject.test/"})
	local := eff.HTTPRewrite.Request(httprewrite.Request{URL: "https://local.test/"})
	if redirect.Local == nil || redirect.Local.StatusCode != 302 || reject.Local == nil || reject.Local.StatusCode != 200 || local.Local == nil || local.Local.StatusCode != 200 || local.Local.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("redirect = %+v, reject = %+v, map-local = %+v", redirect, reject, local)
	}
	if !slices.Equal(reads, []string{hash, hash}) {
		t.Fatalf("reads at runtime: %v", reads)
	}
	for _, changed := range []string{
		fmt.Sprintf(strings.Replace(profile, "action: 302", "action: 307", 1), hash),
		fmt.Sprintf(profile, resource.Hash([]byte(`[]`))),
	} {
		other, ds := Compile([]byte(changed), nil, opts)
		if ds.HasErrors() || other.HTTPRewriteFingerprint == eff.HTTPRewriteFingerprint {
			t.Fatalf("changed rewrite retained fingerprint: %v", ds)
		}
	}
	same, ds := Compile([]byte(fmt.Sprintf(profile, hash)), []byte("mitm: {enabled: true, ca: 'secret://mitm/ca'}"), opts)
	if ds.HasErrors() || same.HTTPRewriteFingerprint != eff.HTTPRewriteFingerprint {
		t.Fatalf("local-only change affected rewrite fingerprint: %v", ds)
	}
}

func TestMapLocalResourceValidation(t *testing.T) {
	profile := fmt.Sprintf("schema-version: 1\nmap-local: [{id: local, match: 'a', hash: '%s'}]", resource.Hash(nil))
	for _, tc := range []struct {
		name string
		read func(string) ([]byte, error)
	}{
		{"unavailable store", nil},
		{"missing resource", func(string) ([]byte, error) { return nil, errors.New("missing resource") }},
		{"resource hash mismatch", func(string) ([]byte, error) { return []byte("different content"), nil }},
		{"oversize resource", func(string) ([]byte, error) { return make([]byte, httprewrite.MaxMapLocalSize+1), nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			eff, diags := Compile([]byte(profile), nil, Options{ReadResource: tc.read})
			if eff != nil || !slices.ContainsFunc(diags, func(d model.Diagnostic) bool {
				return d.Severity == model.SeverityError && d.Path == "/map-local/local/hash" && d.Code == "rewrite.resource"
			}) {
				t.Fatalf("wanted resource error at hash, got %v", diags)
			}
		})
	}
}
