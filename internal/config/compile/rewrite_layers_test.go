package compile

import (
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/MimoProxy/reka/internal/config/model"
	"github.com/MimoProxy/reka/internal/httprewrite"
)

const rewriteSources = `schema-version: 1
sources:
  - id: first
    mitm:
      hostnames: [first.test, blocked.test]
      h2: false
      skip-server-cert-verify: false
      quic-block: true
    http-rewrites: [{id: reject, match: '/priority$', action: reject, response: dict}]
    header-rewrites: [{id: header, match: '/chain$', op: add, name: X-Trace, value: first}]
    body-rewrites: [{id: body, match: '/chain$', phase: request, replace: [{pattern: '0', value: '1'}]}]
    map-local: [{id: map, match: '/map$', data-type: text, data: first}]
  - id: second
    mitm:
      hostnames: [second.test]
      h2: true
      skip-server-cert-verify: true
      quic-block: false
    http-rewrites: [{id: reject, match: '/priority$', action: reject, response: gif}]
    header-rewrites: [{id: header, match: '/chain$', op: add, name: X-Trace, value: second}]
    body-rewrites: [{id: body, match: '/chain$', phase: request, replace: [{pattern: '1', value: '2'}]}]
    map-local: [{id: map, match: '/map$', data-type: text, data: second}]
  - id: unused
    mitm: {hostnames: [unused.test], h2: false, skip-server-cert-verify: false, quic-block: true}
    http-rewrites: [{id: unused, match: '.*', action: reject, response: close}]
`

const rewriteProfile = `schema-version: 1
imports:
  - {source: first, rewrites: true}
  - {source: second, rewrites: true}
mitm:
  hostnames: [profile.test, '*.test']
  skip-server-cert-verify: false
http-rewrites:
  - {id: profile, match: '/priority$', action: reject, response: error}
  - {id: first/reject, match: '/priority$', action: reject, response: array}
header-rewrites: [{id: header, match: '/chain$', op: add, name: X-Trace, value: profile}]
body-rewrites: [{id: body, match: '/chain$', phase: request, replace: [{pattern: '2', value: '3'}]}]
map-local: [{id: map, match: '/map$', data-type: text, data: profile}]
`

func TestRewriteSourceComposition(t *testing.T) {
	eff, diags := Compile([]byte(rewriteProfile), nil, Options{Sources: []byte(rewriteSources)})
	if diags.HasErrors() {
		t.Fatal(diags)
	}
	if got := eff.MITM; !got.H2 || got.SkipServerCertVerify || got.QUICBlock || !slices.Equal(got.Hostnames, []string{"profile.test", "*.test", "first.test", "blocked.test", "second.test"}) {
		t.Fatalf("MITM = %+v", got)
	}
	for _, tc := range []struct {
		path, source, sourcePath string
		override                 bool
	}{
		{"/http-rewrites/first~1reject/response", "first", "/sources/first/http-rewrites/reject/response", true},
		{"/http-rewrites/second~1reject/response", "second", "/sources/second/http-rewrites/reject/response", false},
		{"/header-rewrites/first~1header/value", "first", "/sources/first/header-rewrites/header/value", false},
		{"/body-rewrites/second~1body/replace/#0/pattern", "second", "/sources/second/body-rewrites/body/replace/#0/pattern", false},
		{"/map-local/second~1map/data", "second", "/sources/second/map-local/map/data", false},
		{"/mitm/hostnames/#2", "first", "/sources/first/mitm/hostnames/#0", false},
		{"/mitm/h2", "second", "/sources/second/mitm/h2", false},
		{"/mitm/skip-server-cert-verify", "second", "/sources/second/mitm/skip-server-cert-verify", true},
	} {
		origin, _ := eff.OriginOf(tc.path)
		if tc.override {
			if origin.Layer != LayerProfile || origin.Overrides == nil {
				t.Fatalf("%s: no profile override: %+v", tc.path, origin)
			}
			origin = *origin.Overrides
		}
		if origin.Document != model.DocSources || origin.Source != tc.source || origin.Path != tc.sourcePath || origin.Line == 0 {
			t.Errorf("%s: origin = %+v", tc.path, origin)
		}
	}
	request := func(path string) httprewrite.RequestResult {
		return eff.HTTPRewrite.Request(httprewrite.Request{URL: "https://server.test" + path, Body: []byte("0")})
	}
	if got := request("/priority"); got.Local == nil || string(got.Local.Body) != "[]" || !slices.Equal(got.MatchedIDs, []string{"first/reject"}) {
		t.Fatalf("profile replacement lost imported priority: %+v", got)
	}
	if got := request("/map"); got.Local == nil || string(got.Local.Body) != "first" || !slices.Equal(got.MatchedIDs, []string{"first/map"}) {
		t.Fatalf("first map-local = %+v", got)
	}
	if got := request("/chain"); string(got.Body) != "3" || !slices.Equal(got.Header.Values("X-Trace"), []string{"first", "second", "profile"}) ||
		!slices.Equal(got.MatchedIDs, []string{"first/header", "second/header", "header", "first/body", "second/body", "body"}) {
		t.Fatalf("rewrite order = %+v", got)
	}
}

func TestMITMAndRewriteOverlay(t *testing.T) {
	const overlay = `patches:
  - {op: remove, path: /http-rewrites/first~1reject}
  - {op: remove, path: /mitm/hostnames/#0}
  - {op: insert, path: /mitm/hostnames, before: '#0', value: '-blocked.test'}
  - {op: set, path: /mitm/skip-server-cert-verify, value: true}
  - {op: remove, path: /mitm/quic-block}
`
	eff, diags := Compile([]byte(rewriteProfile), nil, Options{Sources: []byte(rewriteSources), Overlay: []byte(overlay)})
	if diags.HasErrors() {
		t.Fatal(diags)
	}
	if got := eff.MITM; !got.H2 || !got.SkipServerCertVerify || !got.QUICBlock || !slices.Equal(got.Hostnames, []string{"-blocked.test", "*.test", "first.test", "blocked.test", "second.test"}) {
		t.Fatalf("MITM = %+v", got)
	}
	if eff.MITM.Matcher.Match("BLOCKED.TEST", 443) || !eff.MITM.Matcher.Match("first.test", 443) {
		t.Fatal("overlay exclusion should precede the overlapping wildcard")
	}
	if got := eff.HTTPRewrite.Request(httprewrite.Request{URL: "https://server.test/priority"}); got.Local == nil || got.Local.Header.Get("Content-Type") != "image/gif" || !slices.Equal(got.MatchedIDs, []string{"second/reject"}) {
		t.Fatalf("next source rewrite = %+v", got)
	}
	for _, tc := range []struct{ key, doc, original string }{
		{"/mitm/hostnames/#0", model.DocOverlay, "/patches/#2/value"},
		{"/mitm/hostnames/#1", model.DocProfile, "/mitm/hostnames/#1"},
		{"/mitm/hostnames/#2", model.DocSources, "/sources/first/mitm/hostnames/#0"},
		{"/mitm/skip-server-cert-verify", model.DocOverlay, "/patches/#3/value"},
	} {
		origin, _ := eff.OriginOf(tc.key)
		if origin.Document != tc.doc || origin.Path != tc.original || origin.Line == 0 {
			t.Errorf("%s: %+v", tc.key, origin)
		}
	}
	overridden, _ := eff.OriginOf("/mitm/skip-server-cert-verify")
	if overridden.Overrides == nil || overridden.Overrides.Layer != LayerProfile || overridden.Overrides.Overrides == nil || overridden.Overrides.Overrides.Source != "second" {
		t.Fatalf("switch provenance = %+v", overridden)
	}
}

func TestImportedRewriteErrorPaths(t *testing.T) {
	profile := `schema-version: 1
imports: [{source: first, rewrites: true}]
mitm: {hostnames: [profile.test]}
`
	sources := strings.Replace(rewriteSources, "hostnames: [first.test, blocked.test]", "hostnames: [first.test, 'no:99999']", 1)
	sources = strings.Replace(sources, "op: add, name: X-Trace, value: first", "op: add, name: X-Trace", 1)
	const overlay = `patches:
  - {op: insert, path: /mitm/hostnames, after: '#0', value: '-profile.test'}
  - {op: remove, path: /mitm/hostnames/#2}
  - {op: set, path: /body-rewrites/first~1body/replace/#0/pattern, value: '(?=bad)'}
`
	eff, diags := Compile([]byte(profile), nil, Options{Sources: []byte(sources), Overlay: []byte(overlay)})
	if eff != nil || !diags.HasErrors() {
		t.Fatalf("invalid source and overlay accepted: %v", diags)
	}
	for _, tc := range []struct{ doc, path string }{
		{model.DocSources, "/sources/first/mitm/hostnames/#1"},
		{model.DocSources, "/sources/first/header-rewrites/header/value"},
		{model.DocOverlay, "/patches/#2/value"},
	} {
		if !slices.ContainsFunc(diags, func(d model.Diagnostic) bool {
			return d.Document == tc.doc && d.Path == tc.path && d.Line != 0 && d.Severity == model.SeverityError
		}) {
			t.Errorf("missing error at %s %s: %v", tc.doc, tc.path, diags)
		}
	}
}

func TestRewriteImportSelection(t *testing.T) {
	const profile = "schema-version: 1\nimports: [{source: first, rewrites: false, outbounds: true}]"
	eff, diags := Compile([]byte(profile), nil, Options{Sources: []byte(rewriteSources)})
	if diags.HasErrors() || eff.HTTPRewrite != nil || len(eff.MITM.Hostnames) != 0 || !eff.MITM.QUICBlock {
		t.Fatalf("unselected rewrite resources were composed: %v", diags)
	}
	if resp := eff.HTTPRewrite.Response("https://example.test/", httprewrite.Response{StatusCode: http.StatusOK}); resp.StatusCode != http.StatusOK {
		t.Fatalf("empty rewrite changed response: %+v", resp)
	}
}
