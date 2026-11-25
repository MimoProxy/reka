package module

import (
	"reflect"
	"slices"
	"testing"

	"github.com/MimoProxy/reka/internal/config/model"
	"github.com/MimoProxy/reka/internal/httprewrite"
	"github.com/MimoProxy/reka/internal/resource"
)

func TestLoonExpressionRewrites(t *testing.T) {
	for _, test := range []struct {
		name, line, action, target, response, phase, jq, code string
	}{
		{name: "dictionary", line: `request if ${url} ~= /item/i then reject_dict(200)`, action: "reject", response: "dict"},
		{name: "image", line: `request if ${url} ~= /item/ then reject_img(200)`, action: "reject", response: "gif"},
		{name: "array", line: `request if ${url} ~= /item/ then reject_array(200)`, action: "reject", response: "array"},
		{name: "empty success", line: `request if ${url} ~= /item/ then reject(200)`, action: "reject", response: "200"},
		{name: "not found", line: `request if ${url} ~= /item/ then reject(404)`, action: "reject", response: "error"},
		{name: "no arguments", line: `request if ${url} ~= /item/ then reject()`, action: "reject", response: "error"},
		{name: "bare reject", line: `request if ${url} ~= /item/ then reject`, action: "reject", response: "error"},
		{name: "redirect", line: `request if ${url} ~= /item/ then redirect(307, "https://example.test/${path}")`, action: "307", target: "https://example.test/from-argument"},
		{name: "redirect capture", line: `request if ${url} ~= /\/item\/(\d+)/i as urlMatch then redirect(302, "https://example.test/${urlMatch[1]}")`, action: "302", target: "https://example.test/$1"},
		{name: "dotted capture", line: `request if ${url} ~= /^https:\/\/original\.test\/item\/(\d+)/i as m then redirect(302, "https://example.test/${m.1}suffix/$23")`, action: "302", target: "https://example.test/$1suffix/$$23"},
		{name: "body delete", line: `response if ${url} ~= /item/ then response.json.delete("data.test[0]")`, phase: "response", jq: "del(.data.test[0])"},
		{name: "body delete array", line: `response if ${url} ~= /item/ then response.json.delete(["p1", "p2"])`, phase: "response", jq: "del(.p1, .p2)"},
		{name: "body jq", line: `response if ${url} ~= /item/ then response.json.jq("del(.test)\n | .")`, phase: "response", jq: "del(.test)\n | ."},
		{name: "body replace", line: `response if ${url} ~= /item/ then response.json.replace("path", "typed, value")`, phase: "response", jq: `(.path = "typed, value")`},
		{name: "request body jq", line: `request if ${url} ~= /item/ then request.json.jq(".test = []")`, phase: "request", jq: ".test = []"},
		{name: "request body replace", line: `request if ${url} ~= /item/ then request.json.replace("path", ${enabled})`, phase: "request", jq: "(.path = true)"},
		{name: "remote jq", line: `response if ${url} ~= /item/ then response.json.jq_file("https://example.test/test.jq")`, code: "module.jq-path"},
		{name: "unknown variable", line: `response if ${url} ~= /item/ then response.json.delete("${unknown}")`, code: "module.expression"},
		{name: "unknown capture", line: `request if ${url} ~= /(item)/ as m then redirect(302, "${other[1]}")`, code: "module.expression"},
		{name: "out of range capture", line: `request if ${url} ~= /(item)/ as m then redirect(302, "${m[2]}")`, code: "module.expression"},
		{name: "ambiguous capture", line: `request if ${url} ~= /(item)/ as m then redirect(302, "${m[1]}2")`, code: "module.expression"},
		{name: "invalid status", line: `request if ${url} ~= /item/ then reject(418)`, code: "module.expression"},
		{name: "invalid flag", line: `request if ${url} ~= /item/g then reject(200)`, code: "module.expression"},
		{name: "incompatible regex", line: `request if ${url} ~= /(?<=a)b/ then reject(200)`, code: "module.regexp"},
		{name: "wrong direction", line: `response if ${url} ~= /item/ then request.json.delete("path")`, code: "module.expression"},
		{name: "response reject", line: `response if ${url} ~= /item/ then reject(200)`, code: "module.expression"},
		{name: "second condition", line: `request if ${url} ~= /item/ and ${url} ~= /other/ then reject(200)`, code: "module.expression"},
		{name: "alternative condition", line: `request if ${url} ~= /item/ || ${url} ~= /other/ then reject(200)`, code: "module.expression"},
		{name: "host condition", line: `request if ${host} ~= /example/ then reject(200)`, code: "module.expression"},
		{name: "header condition", line: `request if ${header} ~= /example/ then reject(200)`, code: "module.expression"},
		{name: "unsupported function", line: `request if ${url} ~= /item/ then request.header.set("X-Test", "1")`, code: "module.expression"},
		{name: "chained actions", line: `request if ${url} ~= /item/ then reject(200) | reject(404)`, code: "module.expression"},
		{name: "unterminated regex", line: `request if ${url} ~= /item then reject(200)`, code: "module.expression"},
		{name: "unbalanced arguments", line: `response if ${url} ~= /item/ then response.json.delete(["p1", "p2")`, code: "module.expression"},
	} {
		t.Run(test.name, func(t *testing.T) {
			const prefix = "[Argument]\npath=input,from-argument\nenabled=switch,true\n[Rewrite]\n"
			result, report := Convert([]byte(prefix+test.line), Options{Format: model.ModuleFormatLoon})
			line := report.Lines[len(report.Lines)-1]
			if test.code != "" {
				if !report.CanApply || !report.Partial || report.Rewrites != (Count{Total: 1, Unavailable: 1}) ||
					line.Status != Unsupported || line.Code != test.code || len(result.HTTPRewrites)+len(result.BodyRewrites) != 0 {
					t.Fatalf("unexpected unsupported expression result %+v, %+v", result, report)
				}
				return
			}
			if !report.CanApply || report.Partial || report.Rewrites != (Count{Total: 1, Imported: 1}) || line.Status != Supported {
				t.Fatalf("unexpected report %+v", report)
			}
			if test.action != "" {
				rule := result.HTTPRewrites[0]
				if rule.Action != test.action || test.target != "" && *rule.Target != test.target || test.response != "" && *rule.Response != test.response {
					t.Fatalf("wrong URL rewrite %+v", rule)
				}
				if test.name == "redirect capture" && rule.Match != `(?i)/item/(\d+)` {
					t.Fatalf("flag or slash escaping changed: %q", rule.Match)
				}
				if test.name == "dotted capture" {
					checkLoonRedirect(t, rule)
				}
			} else {
				rule := result.BodyRewrites[0]
				if rule.Phase != test.phase || *rule.JQ != test.jq {
					t.Fatalf("wrong body rewrite %+v, filter=%s", rule, *rule.JQ)
				}
			}
		})
	}
}

func checkLoonRedirect(t *testing.T, rule model.HTTPRewrite) {
	t.Helper()
	spec := httprewrite.Spec{HTTPRewrites: []httprewrite.HTTPRewrite{{Match: rule.Match, Action: rule.Action, Target: rule.Target}}}
	rules, err := httprewrite.New(spec, httprewrite.Options{})
	if err != nil {
		t.Fatal(err)
	}
	got := rules.RequestBeforeBody(httprewrite.Request{URL: "https://original.test/item/12"})
	const want = "https://example.test/12suffix/$23"
	if loc := got.Local.Header.Get("Location"); loc != want {
		t.Fatalf("redirect location = %q, want %q", loc, want)
	}
}

func TestLoonExpressionScriptsAndInspection(t *testing.T) {
	const input = `[Argument]
Source = input,https://example.test/source.js
Name = input,"filters, local"
Enabled = switch,true
[Script]
response if ${url} ~= /example\.test\/items/i then script("${Source}", {${Name}, ${Enabled}}) with tag="Script, enabled", requires_body=true, timeout=60, binary_body_mode=true, enable=${Enabled}
request if ${url} ~= /example\.test/ then script("https://example.test/disabled.js") with enable=false
request if ${url} ~= /example\.test/ then script("https://example.test/plain.js", "mode=${Name}") with tag="Plain"
[Rewrite]
request if ${url} ~= /example\.test/ then script("https://example.test/source.js")
`
	opts := Options{
		Format:    model.ModuleFormatLoon,
		Arguments: map[string]string{"Name": "override"},
		ResourceForKind: func(kind, url string) (string, bool) {
			return resource.Hash([]byte(url)), kind == "script"
		},
	}
	result, report := Convert([]byte(input), opts)
	if !report.CanApply || !report.Partial || report.Scripts != (Count{Total: 4, Imported: 3, Unavailable: 1}) || report.Rewrites.Total != 0 {
		t.Fatalf("unexpected report %+v", report)
	}
	script := result.Scripts[0]
	if *script.Name != "Script, enabled" || *script.Format != model.ModuleFormatLoon ||
		*script.Pattern != `(?i)example\.test/items` || *script.Timeout != 60 || !*script.RequiresBody || !*script.BinaryBodyMode ||
		*script.ArgumentType != "object" || *script.Argument != `{"Name":"override","Enabled":true}` {
		t.Fatalf("unexpected expression script %+v", script)
	}
	if *result.Scripts[1].Argument != "mode=override" || result.Scripts[1].ArgumentType != nil || *result.Scripts[2].Timeout != 10 {
		t.Fatalf("unexpected optional script settings %+v", result.Scripts[1:])
	}
	metadata, refs := InspectWithOptions([]byte(input), opts)
	if !reflect.DeepEqual(metadata, report.Metadata) || !slices.Equal(refs.Scripts, []ScriptReference{
		{"https://example.test/source.js", model.DefaultResourceInterval},
		{"https://example.test/plain.js", model.DefaultResourceInterval},
	}) {
		t.Fatalf("unexpected inspection %+v, %+v", metadata, refs)
	}
}
