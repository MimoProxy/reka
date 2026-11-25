package module

import (
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/MimoProxy/reka/internal/config/model"
	"github.com/MimoProxy/reka/internal/resource"
)

func TestStashConversion(t *testing.T) {
	const input = `name: Ad filters
desc: Example override
icon: https://example.test/icon.png
category: Tools
author: Example
date: 2026-01-01
raw-url: https://example.test/override.stoverride
tg-channel: example
rules:
  - DOMAIN,api.example.test,Route
  - RULE-SET,example,DIRECT
http:
  mitm:
    - '%INSERT%'
    - '-ads.example.test'
    - '%APPEND% *.example.test'
    - 'api.example.test:0'
  url-rewrite:
    - >-
      ^https://example\.test/redirect
      https://example.test/new 302
    - '^https://example\.test/temporary https://example.test/new 307'
    - '^https://example\.test/transparent https://example.test/new transparent'
    - '^https://example\.test/blocked - reject'
    - '^https://example\.test/blocked - reject-200'
    - '^https://example\.test/blocked - reject-img'
    - '^https://example\.test/blocked - reject-dict'
    - '^https://example\.test/blocked - reject-array'
  header-rewrite:
    - >-
      ^https://example\.test/ request-add X-Tag 'two words'
    - '^https://example\.test/ response-del X-Old'
    - '^https://example\.test/ request-replace X-Tag replacement'
    - '^https://example\.test/ response-replace-regex X-Tag "old (.*)" "$1 new"'
  body-rewrite:
    - >-
      ^https://example\.test/ response-jq 'del(.debug) | .name = "Example"'
    - '^https://example\.test/ request-jq "example"'
    - '^https://example\.test/ response-replace-regex "old value" "new value" remove ""'
    - '^https://example\.test/ request-replace-regex old new'
  mock:
    - match: '^https://example\.test/mock'
      status-code: 201
      text: |-
        line one
        line two
      headers:
        Content-Type: application/example
        X-Tag: ['a | b', 'c']
    - match: '^https://example\.test/bytes'
      base64: aGk=
    - match: '^https://example\.test/json'
      data-type: json
      data: '{"ok":true}'
    - match: '^https://example\.test/empty'
      status-code: 503
  script:
    - match: '^https://example\.test/response'
      name: hook
      type: response
      require-body: true
      binary-mode: true
      timeout: 15
      max-size: 4096
      debug: true
      argument: '{"name":"Example"}'
    - match: '^https://example\.test/request'
      name: same-source
      type: request
script-providers:
  hook:
    url: https://example.test/hook.js
    interval: 900
  same-source:
    url: https://example.test/hook.js
`
	const scriptURL = "https://example.test/hook.js"
	hash := resource.Hash([]byte("script"))
	metadata, refs := InspectWithOptions([]byte(input), Options{Format: model.ModuleFormatStash, ModuleInterval: 600})
	wantMetadata := Metadata{Name: "Ad filters", Desc: "Example override", Icon: "https://example.test/icon.png", Category: "Tools"}
	if !reflect.DeepEqual(metadata, wantMetadata) || !slices.Equal(refs.Scripts, []ScriptReference{{URL: scriptURL, Interval: 600}}) || len(refs.MapLocal) != 0 {
		t.Fatalf("metadata = %+v, references = %+v", metadata, refs)
	}
	result, report := Convert([]byte(input), Options{
		Format: model.ModuleFormatStash,
		Resolve: func(policy string) (string, bool) {
			return "route", policy == "Route"
		},
		ResourceForKind: func(kind, url string) (string, bool) {
			return hash, kind == "script" && url == scriptURL
		},
	})
	if !report.CanApply || report.Partial || report.Format != model.ModuleFormatStash || !reflect.DeepEqual(report.Metadata, wantMetadata) ||
		report.Rules != (Count{Total: 2, Imported: 2}) || report.Hostnames != (Count{Total: 3, Imported: 3}) ||
		report.Rewrites != (Count{Total: 20, Imported: 20}) || report.Scripts != (Count{Total: 2, Imported: 2}) {
		t.Fatalf("unexpected report %+v", report)
	}
	if len(result.Rules) != 2 || result.Rules[0].Outbound != "route" || result.Rules[1].Match.Kind != "rule-set" || result.ItemLines[result.Rules[0].ID] != 10 {
		t.Fatalf("unexpected rules %+v or provenance %+v", result.Rules, result.ItemLines)
	}
	if !slices.Equal(result.InsertHostnames, []Hostname{{Value: "-ads.example.test", Line: 15}, {Value: "api.example.test:0", Line: 17}}) ||
		!slices.Equal(result.AppendHostnames, []Hostname{{Value: "*.example.test", Line: 16}}) {
		t.Fatalf("unexpected MITM hostnames %+v, %+v", result.InsertHostnames, result.AppendHostnames)
	}
	if len(result.HTTPRewrites) != 8 || result.ItemLines[result.HTTPRewrites[0].ID] != 19 {
		t.Fatalf("unexpected URL rewrites %+v", result.HTTPRewrites)
	}
	for i, want := range []string{"302", "307", "header"} {
		rule := result.HTTPRewrites[i]
		if rule.Action != want || rule.Target == nil || *rule.Target != "https://example.test/new" {
			t.Fatalf("unexpected URL rewrite %+v", rule)
		}
	}
	for i, want := range []string{"error", "200", "gif", "dict", "array"} {
		rule := result.HTTPRewrites[i+3]
		if rule.Action != "reject" || rule.Response == nil || *rule.Response != want {
			t.Fatalf("unexpected reject rewrite %+v", rule)
		}
	}
	if rules := result.HeaderRewrites; len(rules) != 4 || *rules[0].Value != "two words" || *rules[1].Phase != "response" || rules[1].Op != "del" ||
		rules[2].Op != "replace" || *rules[3].Pattern != "old (.*)" || *rules[3].Value != "$1 new" {
		t.Fatalf("unexpected header rewrites %+v", rules)
	}
	if rules := result.BodyRewrites; len(rules) != 4 || *rules[0].JQ != `del(.debug) | .name = "Example"` || *rules[1].JQ != `"example"` ||
		len(rules[2].Replace) != 2 || *rules[2].Replace[0].Value != "new value" || *rules[2].Replace[1].Value != "" || rules[3].Phase != "request" {
		t.Fatalf("unexpected body rewrites %+v", rules)
	}
	if rules := result.MapLocal; len(rules) != 4 || *rules[0].StatusCode != 201 || *rules[0].Data != "line one\nline two" ||
		len(rules[0].Headers) != 3 || *rules[0].Headers[1].Value != "a | b" || *rules[1].DataType != "base64" || *rules[2].DataType != "json" ||
		*rules[3].StatusCode != 503 || *rules[3].Data != "" {
		t.Fatalf("unexpected mock responses %+v", rules)
	}
	if scripts := result.Scripts; len(scripts) != 2 || len(report.ScriptItems) != 2 || *scripts[0].Format != model.ModuleFormatStash ||
		scripts[0].Type != "http-response" || *scripts[0].Name != "hook" || !*scripts[0].RequiresBody || !*scripts[0].BinaryBodyMode ||
		*scripts[0].Timeout != 15 || *scripts[0].MaxSize != 4096 || *scripts[0].Argument != `{"name":"Example"}` || *scripts[0].Hash != hash ||
		scripts[1].Type != "http-request" || *scripts[1].RequiresBody || scripts[1].Argument != nil {
		t.Fatalf("unexpected scripts %+v", scripts)
	}
}

func TestStashUnsupportedEntries(t *testing.T) {
	const input = `name: Filters
arguments:
  example: value
dns: {enable: true}
hosts: {example.test: 192.0.2.1}
proxies: [{name: example}]
proxy-groups: []
proxy-providers: {}
external-controller: 127.0.0.1:9090
secret: example
mode: global
log-level: debug
cron: []
tiles: []
rule-providers:
  remote: {url: https://example.test/rules}
rules:
  - MATCH,DIRECT
  - RULE-SET,https://example.test/rules,DIRECT
  - {invalid: true}
  - DOMAIN,good.example.test,DIRECT
http:
  force-http-engine: ['*:80']
  rewrite: []
  mitm: [true, example.test]
  url-rewrite:
    - '^(?=x) - reject'
    - 'example.test - unknown'
  header-rewrite:
    - 'example.test response-del Content-Length'
  body-rewrite:
    - match: example.test
      name: remote-filter
    - 'example.test response-jq ??'
  mock:
    - {match: example.test, status-code: 99}
    - {match: example.test, data-type: file, data: /private/example}
  script:
    - {match: example.test, name: missing, type: request}
    - {match: example.test, name: local, type: request}
    - {match: example.test, name: source, type: request}
    - {match: example.test, name: custom, type: response}
script-providers:
  local: {url: /private/never-read.js}
  source: {url: https://example.test/hook.js}
  custom: {url: 'https://example.test/custom.js', headers: {Accept: text/javascript}}
`
	result, report := Convert([]byte(input), Options{Format: model.ModuleFormatStash})
	if !report.CanApply || !report.Partial || report.Rules != (Count{Total: 4, Imported: 1, Unavailable: 3}) ||
		report.Hostnames != (Count{Total: 2, Imported: 1, Unavailable: 1}) ||
		report.Rewrites != (Count{Total: 7, Unavailable: 7}) || report.Scripts != (Count{Total: 4, Unavailable: 4}) ||
		len(result.Rules) != 1 || len(result.AppendHostnames) != 1 || len(result.Scripts) != 0 || len(report.ScriptItems) != 1 || report.ScriptItems[0].Locked {
		t.Fatalf("unexpected result %+v or report %+v", result, report)
	}
	byLine := make(map[int]Line)
	for _, line := range report.Lines {
		byLine[line.Line] = line
	}
	for _, want := range []Line{
		{Line: 2, Section: "arguments", Status: Unsupported, Code: "module.arguments"},
		{Line: 15, Section: "rule-providers", Status: Ignored, Code: "module.rule-set"},
		{Line: 18, Section: "rules", Status: Unsupported, Code: "module.final-rule"},
		{Line: 23, Section: "http.force-http-engine", Status: Ignored, Code: "module.http-setting"},
		{Line: 27, Section: "http.url-rewrite", Status: Unsupported, Code: "module.regexp"},
		{Line: 30, Section: "http.header-rewrite", Status: Unsupported, Code: "module.header-framing"},
		{Line: 32, Section: "http.body-rewrite", Status: Unsupported, Code: "module.body-rewrite-provider"},
		{Line: 36, Section: "http.mock", Status: Unsupported, Code: "module.map-local-status"},
		{Line: 39, Section: "http.script", Status: Unsupported, Code: "module.script-provider"},
		{Line: 40, Section: "http.script", Status: Unsupported, Code: "module.script-path"},
		{Line: 41, Section: "http.script", Status: Unsupported, Code: "module.script-unavailable"},
	} {
		got := byLine[want.Line]
		if got.Section != want.Section || got.Status != want.Status || got.Code != want.Code || got.Message == "" {
			t.Errorf("line %d = %+v, want %+v", want.Line, got, want)
		}
	}
	_, refs := InspectWithOptions([]byte(input), Options{Format: model.ModuleFormatStash})
	if !slices.Equal(refs.Scripts, []ScriptReference{{URL: "https://example.test/hook.js", Interval: model.DefaultResourceInterval}}) || len(refs.MapLocal) != 0 {
		t.Fatalf("unexpected references %+v", refs)
	}
}

func TestStashDocumentErrors(t *testing.T) {
	for _, tc := range []struct{ name, text, code string }{
		{"invalid YAML", "name: [", "yaml.syntax"},
		{"sequence root", "- name\n", "yaml.type"},
		{"duplicate key", "name: same\nname: duplicate\n", "yaml.mapping"},
		{"multiple documents", "name: one\n---\nname: two\n", "yaml.documents"},
		{"document limit", strings.Repeat("#", model.MaxDocumentSize+1), "module.size"},
		{"rule policy", "rules:\n  - DOMAIN,example.test,missing\n", "module.rule-policy"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, report := Convert([]byte(tc.text), Options{Format: model.ModuleFormatStash})
			if report.CanApply || len(report.Diagnostics) != 1 || report.Diagnostics[0].Code != tc.code || len(result.Rules) != 0 {
				t.Fatalf("unexpected result %+v or report %+v", result, report)
			}
		})
	}
}

func TestStashCronAndTileScripts(t *testing.T) {
	const input = `name: Background
cron:
  script:
    - name: daily
      cron: '12 0 * * *'
      argument: '{ "key": false }'
      timeout: 10
    - name: seconds
      cron: "02 00 10 * * *"
    - name: daily
      cron: '*/0 * * * *'
    - name: seconds
    - name: daily
      cron: '0 9 * * *'
      match: example.test
  schedule: []
tiles:
  - name: panel
    interval: 600
    title: 'Tile'
    content: 'Before the first run'
    icon: 'calendar'
    backgroundColor: '#663399'
    collapsed: true
    url: https://example.test/
    argument: |-
      TYPE=TILE&flag=1
    timeout: 30
  - name: panel
    type: request
script-providers:
  daily: {url: https://example.test/daily.js, interval: 3600}
  seconds: {url: https://example.test/seconds.js}
  panel: {url: https://example.test/panel.js}
`
	hash := resource.Hash([]byte("background"))
	opts := Options{Format: model.ModuleFormatStash, ResourceForKind: func(kind, path string) (string, bool) {
		return hash, kind == "script"
	}}
	result, report := Convert([]byte(input), opts)
	if !report.CanApply || !report.Partial || report.Scripts != (Count{Total: 7, Imported: 3, Unavailable: 4}) || len(result.Scripts) != 3 {
		t.Fatalf("unexpected report %+v", report)
	}
	for i, want := range []struct {
		name, kind, cronExp, argument string
		timeout                       int
	}{
		{"daily", "cron", "12 0 * * *", `{ "key": false }`, 10},
		{"seconds", "cron", "02 00 10 * * *", "", model.DefaultScriptTimeout},
		{"panel", "generic", "", "TYPE=TILE&flag=1", 30},
	} {
		script := result.Scripts[i]
		if *script.Name != want.name || script.Type != want.kind || *script.Format != model.ModuleFormatStash || valueOf(script.CronExp) != want.cronExp ||
			valueOf(script.Argument) != want.argument || *script.Timeout != want.timeout || script.Pattern != nil || *script.Hash != hash {
			t.Fatalf("script %d = %+v", i, script)
		}
	}
	for line, code := range map[int]string{10: "module.script-cronexp", 12: "module.script-cronexp", 13: "module.script-setting", 16: "module.section", 29: "module.script-setting"} {
		if !slices.ContainsFunc(report.Lines, func(got Line) bool { return got.Line == line && got.Code == code }) {
			t.Fatalf("line %d lacks %s: %+v", line, code, report.Lines)
		}
	}
	_, refs := InspectWithOptions([]byte(input), opts)
	want := []ScriptReference{{"https://example.test/daily.js", 3600}, {"https://example.test/seconds.js", model.DefaultResourceInterval}, {"https://example.test/panel.js", model.DefaultResourceInterval}}
	if !slices.Equal(refs.Scripts, want) {
		t.Fatalf("references = %+v", refs.Scripts)
	}
}
