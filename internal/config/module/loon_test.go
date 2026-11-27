package module

import (
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/MimoProxy/reka/internal/config/model"
	"github.com/MimoProxy/reka/internal/resource"
)

func TestLoonArgumentsPoliciesAndResources(t *testing.T) {
	input := "\ufeff" + `#!name = {Display}
#!desc = Example
#!icon = https://example.test/icon
#!category = Tests
#!loon_version = 3.5
#!requirement = informational
#!author = Example

[Argument]
Display = input,"Filters, local",tag=Display,desc="Text, shown"
PROXY = select,"Default route","Second route",tag=Route
Enabled = switch,true,false
Source = input,https://example.test/script.js
[Rule]
DOMAIN,example.test,PROXY
DOMAIN,other.test,REJECT-ARRAY
DOMAIN,drop.test,REJECT-DROP
[MiTm]
hostname = %INSERT% -skip.example.test, {Display}.example.test
hostname = %APPEND% *.example.net
h2 = true
skip-server-cert-verify = false
[Map Local]
example\.test/txt data=https://example.test/content
[Script]
http-response ^https://example\.test/a{2}/{unknown} script-path={{{Source}}}, requires_body=true, binary_body_mode=1, tag="Response, hook", argument=[{Display},{Enabled}], max-size=40, img_url=none
request ^https://example\.test/ script-path={Source}, tag=Request, timeout=20, argument="[{Display}]"
http-response example\.test script-path=https://example.test/skipped.js, enable={Enabled}
[Remote Rule]
https://example.test/rules
[General]
dns-server = 192.0.2.1
[Host]
example.test = 192.0.2.1
[Proxy]
proxy = direct
`
	options := Options{
		ID: "filters", Format: model.ModuleFormatLoon, ModuleInterval: 600,
		Arguments: map[string]string{"Display": "local", "PROXY": "Other route", "Enabled": "false"},
		Resolve: func(policy string) (string, bool) {
			return "resolved", policy == "Other route"
		},
		ResourceForKind: func(kind, url string) (string, bool) {
			return resource.Hash([]byte(url)), kind == "script" || kind == "map-local"
		},
	}
	got, report := Convert([]byte(input), options)
	if !report.CanApply || !report.Partial || report.Format != model.ModuleFormatLoon || report.Rules.Imported != 3 ||
		report.Scripts != (Count{Total: 3, Imported: 2, Unavailable: 1}) || report.Rewrites.Imported != 1 || report.Hostnames.Imported != 3 {
		t.Fatalf("invalid report %+v", report)
	}
	if report.Name != "local" || report.Desc != "Example" || report.Icon != "https://example.test/icon" || report.Category != "Tests" {
		t.Fatalf("invalid metadata %+v", report.Metadata)
	}
	arguments := []Argument{
		{Name: "Display", Default: "Filters, local", Value: "local", Description: "Text, shown"},
		{Name: "PROXY", Default: "Default route", Value: "Other route", Options: []string{"Default route", "Second route"}},
		{Name: "Enabled", Default: "true", Value: "false", Type: "switch"},
		{Name: "Source", Default: "https://example.test/script.js", Value: "https://example.test/script.js"},
	}
	if !reflect.DeepEqual(report.Arguments, arguments) || len(report.Diagnostics) != 1 || report.Diagnostics[0].Code != "module.argument-option" || report.Diagnostics[0].Severity != model.SeverityWarning {
		t.Fatalf("invalid arguments %+v, diagnostics %+v", report.Arguments, report.Diagnostics)
	}
	if got.Rules[0].Outbound != "resolved" || got.Rules[1].Outbound != "reject" || got.Rules[2].Outbound != "reject-drop" ||
		got.MITM.H2 != nil || got.MITM.SkipServerCertVerify != nil || got.InsertHostnames[1].Value != "local.example.test" || got.AppendHostnames[0].Value != "*.example.net" {
		t.Fatalf("unexpected converted rules or MITM %+v", got)
	}
	for _, action := range []string{"module.policy-approximate", "module.mitm-setting", "module.script-disabled", "module.rule-set", "module.general", "module.host", "module.proxy"} {
		if !slices.ContainsFunc(report.Lines, func(line Line) bool { return line.Code == action }) {
			t.Errorf("missing report code %s", action)
		}
	}
	for _, line := range report.Lines {
		if line.Section == "metadata" && line.Status != Supported {
			t.Errorf("informational metadata made import partial: %+v", line)
		}
	}
	script := got.Scripts[0]
	if *script.Format != "loon" || *script.Timeout != 10 || script.Type != "http-response" || *script.Name != "Response, hook" ||
		!(*script.RequiresBody && *script.BinaryBodyMode) || *script.Pattern != `^https://example\.test/a{2}/{unknown}` || *script.MaxSize != 40 ||
		script.ArgumentType == nil || *script.ArgumentType != "object" {
		t.Fatalf("incorrect Loon script %+v", script)
	}
	var object map[string]any
	if err := json.Unmarshal([]byte(*script.Argument), &object); err != nil || !reflect.DeepEqual(object, map[string]any{"Display": "local", "Enabled": false}) {
		t.Fatalf("invalid argument JSON %s: %v", *script.Argument, err)
	}
	if got.Scripts[1].ArgumentType != nil || *got.Scripts[1].Argument != "[local]" || *got.Scripts[1].Timeout != 20 {
		t.Fatalf("quoted argument should remain a string: %+v", got.Scripts[1])
	}
	metadata, refs := InspectWithOptions([]byte(input), options)
	if !reflect.DeepEqual(metadata, report.Metadata) || !slices.Equal(refURLs(refs.MapLocal), []string{"https://example.test/content"}) ||
		!slices.Equal(refs.Scripts, []ScriptReference{{"https://example.test/script.js", 600}}) {
		t.Fatalf("incorrect inspection %+v, %+v", metadata, refs)
	}
}

func TestLoonProxyPlaceholder(t *testing.T) {
	for _, test := range []struct {
		name, declaration, supplied, lookup, target string
	}{
		{name: "declared", declaration: "[Argument]\nPROXY=select,Default\n", lookup: "Default", target: "resolved"},
		{name: "override", declaration: "[Argument]\nPROXY=select,Default\n", supplied: "DIRECT", target: "direct"},
		{name: "supplied without declaration", supplied: "DIRECT", target: "direct"},
		{name: "effective policy", lookup: "PROXY", target: "resolved"},
		{name: "missing"},
	} {
		t.Run(test.name, func(t *testing.T) {
			options := Options{Format: model.ModuleFormatLoon, Resolve: func(policy string) (string, bool) {
				return "resolved", policy == test.lookup
			}}
			if test.supplied != "" {
				options.Arguments = map[string]string{"PROXY": test.supplied}
			}
			got, report := Convert([]byte(test.declaration+"[Rule]\nDOMAIN,example.test,proxy"), options)
			if test.target == "" {
				if report.CanApply || len(got.Rules) != 0 || report.Rules.Unavailable != 1 || report.Diagnostics[0].Code != "module.rule-policy" {
					t.Fatalf("unresolved PROXY was accepted: %+v, %+v", got, report)
				}
				return
			}
			if !report.CanApply || report.Partial || len(got.Rules) != 1 || got.Rules[0].Outbound != test.target {
				t.Fatalf("wrong PROXY resolution: %+v, %+v", got, report)
			}
		})
	}
}

func TestLoonClassicRewrites(t *testing.T) {
	const input = `[Rewrite]
example\.test - reject
example\.test reject-200
example\.test reject-img
example\.test reject-dict
example\.test reject-array
example\.test 302 https://example.net/
example\.test 307 https://example.net/
example\.test header https://example.net/
example\.test header-add X-One "new value"
example\.test request-header-del X-Two
example\.test response-header-replace X-Three new
example\.test response-header-replace-regex X-Four old new
example\.test response-body-json-jq 'del(.one)'
example\.test request-body-json-del data.test[0].nested extra-property
example\.test response-body-json-replace data.test "true" data.other {"new": true}
example\.test request-body-replace-regex a b "c d" ""
example\.test mock-response-body data-type=text data="https://example.net/" status-code=201
example\.test mock-response-body data-type=json data="{\"ok\":true}" status-code=203
example\.test mock-response-body data-type=png data="aGVsbG8=" mock-data-is-base64=true
example\.test mock-response-body data-type=text data-path=local.txt
example\.test response-body-json-del data.[*]
example\.test header-del Connection
example\.test mock-request-body data-type=text data="abc"
[URL Rewrite]
example\.test - reject-array
`
	result, report := Convert([]byte(input), Options{Format: model.ModuleFormatLoon})
	if !report.CanApply || !report.Partial || report.Rewrites != (Count{Total: 24, Imported: 20, Unavailable: 4}) {
		t.Fatalf("unexpected report %+v", report)
	}
	var responses, actions []string
	for _, rule := range result.HTTPRewrites {
		if rule.Response != nil {
			responses = append(responses, *rule.Response)
		}
		actions = append(actions, rule.Action)
	}
	if !slices.Equal(responses, []string{"close", "200", "gif", "dict", "array", "array"}) ||
		!slices.Equal(actions, []string{"reject", "reject", "reject", "reject", "reject", "302", "307", "header", "reject"}) {
		t.Fatalf("unexpected URL rewrites %+v", result.HTTPRewrites)
	}
	if result.HeaderRewrites[0].Op != "add" || *result.HeaderRewrites[0].Value != "new value" || result.HeaderRewrites[1].Op != "del" ||
		result.HeaderRewrites[2].Op != "replace" || *result.HeaderRewrites[2].Phase != "response" || result.HeaderRewrites[3].Op != "replace-regex" {
		t.Fatalf("unexpected header rewrites %+v", result.HeaderRewrites)
	}
	body := result.BodyRewrites
	if *body[0].JQ != "del(.one)" || body[1].Phase != "request" || *body[1].JQ != `del(.data.test[0].nested, .["extra-property"])` ||
		*body[2].JQ != `(.data.test = "true") | (.data.other = {"new": true})` || len(body[3].Replace) != 2 {
		t.Fatalf("unexpected body rewrites %+v", body)
	}
	if *result.MapLocal[0].Data != "https://example.net/" || *result.MapLocal[0].StatusCode != 201 ||
		*result.MapLocal[1].Data != `{"ok":true}` || *result.MapLocal[1].StatusCode != 203 ||
		*result.MapLocal[2].DataType != "base64" || *result.MapLocal[2].Headers[0].Value != "image/png" {
		t.Fatalf("unexpected mock responses %+v", result.MapLocal)
	}
}

func TestLoonUnsupportedScriptAndArgumentRows(t *testing.T) {
	const input = `[Argument]
declared = input,first
declared = input,duplicate
malformed = switch,invalid
[Script]
dns script-path=https://example.test/script.js
cron "*/0 * * * *" script-path=https://example.test/script.js
generic then reject()
request .* script-path=https://example.test/script.js,argument=[{missing}]
request .* script-path=https://example.test/script.js,argument=[{declared}],requires-body=true,requires_body=true
request .* script-path=https://example.test/script.js,enable=false
`
	opts := Options{Format: model.ModuleFormatLoon}
	result, report := Convert([]byte(input), opts)
	_, refs := InspectWithOptions([]byte(input), opts)
	if !report.CanApply || !report.Partial || len(report.Arguments) != 1 || report.Arguments[0].Default != "first" ||
		report.Scripts != (Count{Total: 6, Unavailable: 6}) || len(result.Scripts) != 0 || len(refs.Scripts) != 0 {
		t.Fatalf("unexpected results %+v, %+v, %+v", result, report, refs)
	}
}

func TestLoonExpandedArgumentsAreBounded(t *testing.T) {
	text := `[Argument]
Large = input,x
[Script]
response .* script-path=https://example.test/script.js, argument=[{Large}]
`
	_, report := Convert([]byte(text), Options{
		Format: model.ModuleFormatLoon, Arguments: map[string]string{"Large": strings.Repeat("x", model.MaxDocumentSize)},
	})
	if report.CanApply || !slices.ContainsFunc(report.Lines, func(line Line) bool { return line.Code == "module.arguments-size" }) {
		t.Fatalf("expected size limit diagnostic %+v", report.Diagnostics)
	}
}

func TestLoonSurgeOrderRewriteAndCommaDescription(t *testing.T) {
	input := `#!name=Order
[Argument]
Keep = input, "--", tag = Kept, desc = comma separated: a,b,c
[Rewrite]
^http://example\.test/ https://example.test/ 302
`
	result, report := Convert([]byte(input), Options{Format: model.ModuleFormatLoon,
		Resolve: func(policy string) (string, bool) { return policy, true }})
	if report.Partial || !report.CanApply {
		t.Fatalf("report = %+v", report.Lines)
	}
	if len(report.Arguments) != 1 || report.Arguments[0].Default != "--" || report.Arguments[0].Description != "comma separated: a,b,c" {
		t.Fatalf("arguments = %+v", report.Arguments)
	}
	if len(result.HTTPRewrites) != 1 {
		t.Fatalf("rewrites = %+v", result.HTTPRewrites)
	}
}

func TestLoonBackgroundScripts(t *testing.T) {
	const base = "https://example.test/"
	const input = `[Argument]
cron = input,"30 8 * * *",tag=Schedule
appName = input,Example
Enabled = switch,true
[Script]
cron "0 18 * * *" script-path=` + base + `a.js, timeout=20, tag=Daily, img-url=https://example.test/a.png, enable=true
cron "0 0 8-22 * * ?" script-path=` + base + `b.js, tag=Seconds
cron {cron} script-path=` + base + `c.js,tag = Argument,argument=[{appName},{Enabled}],enable={Enabled}
generic script-path = ` + base + `d.js, timeout = 10, tag = Panel, img-url = location.circle.system
network-changed script-path=` + base + `e.js, argument="TYPE=EVENT&a=1"
cron "0/24 * * * *" then script("` + base + `f.js") with tag="Expression", enable=true
cron ${cron} then script("` + base + `g.js", {${appName}}) with tag="Object", timeout=120
generic then script("` + base + `h.js") with tag="Lookup", img_url="location.circle.system", timeout=10
network-changed then script("` + base + `i.js", "mode=1") with tag="Changed", debug=true
cron "0 9 * * *" script-path=` + base + `j.js, enable=false
cron "0 9 * * *" script-path=` + base + `k.js, cronexp=0 10 * * *
generic script-path=` + base + `l.js, pattern=.*
`
	hash := resource.Hash([]byte("background"))
	opts := Options{Format: model.ModuleFormatLoon, ResourceForKind: func(kind, path string) (string, bool) {
		return hash, kind == "script" && strings.HasPrefix(path, base)
	}}
	result, report := Convert([]byte(input), opts)
	if !report.CanApply || !report.Partial || report.Scripts != (Count{Total: 12, Imported: 9, Unavailable: 3}) || len(result.Scripts) != 9 {
		t.Fatalf("unexpected report %+v", report)
	}
	for i, want := range []struct {
		name, kind, cronExp, event, argument string
		timeout                              int
		object                               bool
	}{
		{"Daily", "cron", "0 18 * * *", "", "", 20, false},
		{"Seconds", "cron", "0 0 8-22 * * ?", "", "", 300, false},
		{"Argument", "cron", "30 8 * * *", "", `{"appName":"Example","Enabled":true}`, 300, true},
		{"Panel", "generic", "", "", "", 10, false},
		{"e.js", "event", "", "network-changed", "TYPE=EVENT&a=1", 300, false},
		{"Expression", "cron", "0/24 * * * *", "", "", 300, false},
		{"Object", "cron", "30 8 * * *", "", `{"appName":"Example"}`, 120, true},
		{"Lookup", "generic", "", "", "", 10, false},
		{"Changed", "event", "", "network-changed", "mode=1", 300, false},
	} {
		script := result.Scripts[i]
		if *script.Name != want.name || script.Type != want.kind || *script.Format != model.ModuleFormatLoon || *script.Timeout != want.timeout ||
			script.Pattern != nil || valueOf(script.CronExp) != want.cronExp || valueOf(script.EventName) != want.event ||
			valueOf(script.Argument) != want.argument || (script.ArgumentType != nil) != want.object || *script.Hash != hash {
			t.Fatalf("script %d = %+v", i, script)
		}
	}
	for line, code := range map[int]string{15: "module.script-disabled", 16: "module.script-syntax", 17: "module.script-syntax"} {
		if !slices.ContainsFunc(report.Lines, func(got Line) bool { return got.Line == line && got.Code == code }) {
			t.Fatalf("line %d lacks %s: %+v", line, code, report.Lines)
		}
	}
	_, refs := InspectWithOptions([]byte(input), opts)
	if len(refs.Scripts) != 9 {
		t.Fatalf("background script references: %+v", refs.Scripts)
	}
}

func valueOf[T any](p *T) T {
	var zero T
	if p == nil {
		return zero
	}
	return *p
}
