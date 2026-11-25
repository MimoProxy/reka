package module

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/MimoProxy/reka/internal/config/model"
	"github.com/MimoProxy/reka/internal/resource"
)

func TestScriptConversion(t *testing.T) {
	const input = `#!arguments=source:https://example.test/default.js,option:default
[Script]
Response hook = type=HTTP-RESPONSE, pattern="^https://example\.test/a{1,2}", requires-body=1, binary-body-mode=TrUe, max-size=-1, timeout=3600, engine=webview, script-path="{{{source}}}", argument="{{{option}}}", debug=1
Request hook = type=http-request, pattern=^https://example.test, script-path={{{source}}}, requires-body=0, binary-body-mode=FaLsE, debug=false
`
	const url = "https://example.test/hook.js?one=1&two=2"
	const argument = `a=1,b=2&string=\"quoted\"`
	hash := resource.Hash([]byte("hook"))
	result, report := Convert([]byte(input), Options{
		Arguments: map[string]string{"source": url, "option": argument},
		ResourceForKind: func(kind, path string) (string, bool) {
			return hash, kind == "script" && path == url
		},
	})
	if !report.CanApply || report.Partial || report.Scripts != (Count{Total: 2, Imported: 2}) || len(result.Scripts) != 2 || len(report.ScriptItems) != 2 {
		t.Fatalf("unexpected conversion %+v", report)
	}
	response := result.Scripts[0]
	if !strings.HasPrefix(response.ID, "s-") || result.ItemLines[response.ID] != 3 || *response.Name != "Response hook" || response.Type != "http-response" ||
		*response.Pattern != `^https://example\.test/a{1,2}` || !*response.RequiresBody || !*response.BinaryBodyMode || *response.MaxSize != -1 ||
		*response.Timeout != 3600 || *response.Engine != "webview" || *response.Format != "surge" || *response.Hash != hash || *response.Argument != `a=1,b=2&string="quoted"` {
		t.Fatalf("unexpected response script %+v", response)
	}
	request := result.Scripts[1]
	if result.ItemLines[request.ID] != 4 || request.Type != "http-request" || *request.RequiresBody || *request.BinaryBodyMode || request.MaxSize != nil ||
		*request.Timeout != model.DefaultScriptTimeout || *request.Engine != "auto" || request.Argument != nil || *request.Hash != hash {
		t.Fatalf("unexpected request script %+v", request)
	}
	item := report.ScriptItems[0]
	if item.ID != response.ID || !item.Locked || item.Hash != hash || item.Name != *response.Name || item.Pattern != *response.Pattern ||
		!item.RequiresBody || !item.BinaryBodyMode || *item.MaxSize != -1 || item.Timeout != 3600 || item.Engine != "webview" {
		t.Fatalf("unexpected report item %+v", item)
	}
	jsonItems, err := json.Marshal(report.ScriptItems)
	if err != nil || strings.Contains(string(jsonItems), "hook.js") || strings.Contains(string(jsonItems), "string=") {
		t.Fatalf("unexpected script items %s (%v)", jsonItems, err)
	}
}

func TestUnsupportedScriptSettings(t *testing.T) {
	const path = "https://example.test/hook.js"
	const http = "type=http-request, pattern=^https://example.test, script-path=" + path
	for _, tc := range []struct {
		name, settings, code string
	}{
		{"cron", "type=cron, cronexp=0 10 * * *", "module.script-type"},
		{"generic", "type=generic", "module.script-type"},
		{"event", "type=event", "module.script-type"},
		{"dns", "type=dns", "module.script-type"},
		{"rule", "type=rule", "module.script-type"},
		{"unknown type", "type=unknown", "module.script-type"},
		{"missing type", "script-path=" + path, "module.script-type"},
		{"missing pattern", "type=http-request, script-path=" + path, "module.script-pattern"},
		{"lookahead", `type=http-response, pattern="^(?=abc)", script-path=` + path, "module.regexp"},
		{"relative path", "type=http-request, pattern=^https://example.test, script-path=local.js", "module.script-path"},
		{"absolute path", "type=http-request, pattern=^https://example.test, script-path=/scripts/local.js", "module.script-path"},
		{"non-HTTP URL", "type=http-request, pattern=^https://example.test, script-path=ftp://example.test/hook.js", "module.script-path"},
		{"missing path", "type=http-request, pattern=^https://example.test", "module.script-path"},
		{"unknown setting", http + ", extra=1", "module.script-setting"},
		{"full headers", http + ", full-header-mode=1", "module.script-setting"},
		{"wake", http + ", wake-system=true", "module.script-setting"},
		{"cron setting", http + ", cronexp=0 10 * * *", "module.script-setting"},
		{"event setting", http + ", event-name=example", "module.script-setting"},
		{"requires-body", http + ", requires-body=maybe", "module.script-requires-body"},
		{"binary-body-mode", http + ", binary-body-mode=2", "module.script-binary-body-mode"},
		{"max-size range", http + ", max-size=-2", "module.script-max-size"},
		{"max-size integer", http + ", max-size=1.5", "module.script-max-size"},
		{"timeout zero", http + ", timeout=0", "module.script-timeout"},
		{"timeout range", http + ", timeout=3601", "module.script-timeout"},
		{"timeout integer", http + ", timeout=1.5", "module.script-timeout"},
		{"engine", http + ", engine=unknown", "module.script-engine"},
		{"interval range", http + ", script-update-interval=-2", "module.script-update-interval"},
		{"interval integer", http + ", script-update-interval=3.14", "module.script-update-interval"},
		{"duplicate key", http + ", TYPE=http-response", "module.script-syntax"},
		{"unterminated quote", http + `, argument="part`, "module.script-syntax"},
		{"undefined argument", http + ", argument={{{undefined}}}", "module.undefined-argument"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := []byte("[Script]\nHook = " + tc.settings + "\n")
			result, report := Convert(input, Options{})
			if !report.CanApply || !report.Partial || report.Scripts != (Count{Total: 1, Unavailable: 1}) || len(result.Scripts) != 0 || len(report.ScriptItems) != 0 {
				t.Fatalf("unexpected conversion %+v", report)
			}
			line := report.Lines[1]
			if line.Line != 2 || line.Section != "script" || line.Code != tc.code || line.Status != Unsupported || line.Message == "" {
				t.Fatalf("unexpected diagnostic %+v", line)
			}
			if _, refs := Inspect(input, nil); len(refs.Scripts) != 0 {
				t.Fatalf("unsupported script would be downloaded %+v", refs)
			}
		})
	}
}

func TestScriptLockAndStableID(t *testing.T) {
	const url = "https://example.test/shared.js"
	const mapLocal = `[Map Local]
^https://example.test data="` + url + `"
[Script]
`
	const first = `Hook = type=http-request, pattern=^https://example.test, requires-body=true, script-path=` + url + `, argument="a=1&b=2"
`
	const equivalent = `Hook = argument=a=1&b=2, type=http-request, script-path=` + url + `, pattern="^https://example.test", requires-body=1, debug=1, script-update-interval=300
`
	mapHash := resource.Hash([]byte("map local"))
	oldHash := resource.Hash([]byte("old script"))
	newHash := resource.Hash([]byte("new script"))
	convert := func(line, scriptHash string) (*Result, Report) {
		return Convert([]byte(mapLocal+line), Options{
			ResourceForKind: func(kind, path string) (string, bool) {
				if path == url && kind == "map-local" {
					return mapHash, true
				}
				return scriptHash, path == url && kind == "script" && scriptHash != ""
			},
		})
	}
	old, before := convert(first, oldHash)
	updated, after := convert(equivalent+equivalent, newHash)
	unlocked, missing := convert(equivalent, "")
	if before.Partial || after.Partial || !missing.CanApply || !missing.Partial || missing.Scripts != (Count{Total: 1, Unavailable: 1}) ||
		missing.Lines[3].Code != "module.script-unavailable" || len(unlocked.Scripts) != 0 || len(missing.ScriptItems) != 1 || missing.ScriptItems[0].Locked || missing.ScriptItems[0].Hash != "" {
		t.Fatalf("unexpected reports %+v, %+v, %+v", before, after, missing)
	}
	if len(old.Scripts) != 1 || len(updated.Scripts) != 2 || len(updated.MapLocal) != 1 || *updated.MapLocal[0].Hash != mapHash ||
		*old.Scripts[0].Hash != oldHash || *updated.Scripts[0].Hash != newHash {
		t.Fatalf("unexpected locked resources %+v, %+v", old, updated)
	}
	id := old.Scripts[0].ID
	if updated.Scripts[0].ID != id || updated.Scripts[1].ID != id+"-2" || missing.ScriptItems[0].ID != id || updated.ItemLines[id+"-2"] != 5 {
		t.Fatalf("unexpected IDs %+v, %+v, %+v", old.ItemLines, updated.ItemLines, missing.ScriptItems)
	}
	legacy, report := Convert([]byte(mapLocal+first), Options{Resource: func(path string) (string, bool) { return mapHash, path == url }})
	if !report.CanApply || !report.Partial || report.Rewrites.Imported != 1 || report.Scripts.Unavailable != 1 ||
		len(legacy.MapLocal) != 1 || *legacy.MapLocal[0].Hash != mapHash || len(legacy.Scripts) != 0 ||
		len(report.ScriptItems) != 1 || report.ScriptItems[0].ID != id || report.ScriptItems[0].Locked || report.ScriptItems[0].Hash != "" {
		t.Fatalf("unexpected conversion using the Map Local resolver %+v", report)
	}
}

func TestInspectScriptReferences(t *testing.T) {
	const input = `#!name=Script filters
#!arguments=source:https://example.test/default.js
[Script]
First = type=http-request, pattern=^https://example.test, script-path={{{source}}}, script-update-interval=0
Second = type=http-response, pattern=^https://example.test, script-path={{{source}}}, script-update-interval=900
Lower bound = type=http-request, pattern=^https://example.test, script-path=https://example.test/lower.js, script-update-interval=1
Upper bound = type=http-request, pattern=^https://example.test, script-path=https://example.test/upper.js, script-update-interval=1000000
Inherit explicit = type=http-request, pattern=^https://example.test, script-path=https://example.test/inherit.js, script-update-interval=-1
Inherit omitted = type=http-request, pattern=^https://example.test, script-path=https://example.test/omit.js
Skip = type=cron, script-path=https://example.test/skip.js
[Map Local]
^https://example.test data={{{source}}}
`
	const url = "https://example.test/override.js"
	arguments := map[string]string{"source": url}
	for _, tc := range []struct {
		moduleInterval, firstInterval, inheritInterval int
	}{
		{0, 900, model.DefaultResourceInterval},
		{600, 600, 600},
		{1200, 900, 1200},
	} {
		metadata, refs := Inspect([]byte(input), arguments, tc.moduleInterval)
		if metadata.Name != "Script filters" || !slices.Equal(refs.MapLocal, []string{url}) {
			t.Fatalf("unexpected metadata %+v or Map Local references %+v", metadata, refs.MapLocal)
		}
		want := []ScriptReference{
			{url, tc.firstInterval},
			{"https://example.test/lower.js", model.ModuleMinInterval},
			{"https://example.test/upper.js", model.ModuleMaxInterval},
			{"https://example.test/inherit.js", tc.inheritInterval},
			{"https://example.test/omit.js", tc.inheritInterval},
		}
		if !slices.Equal(refs.Scripts, want) {
			t.Fatalf("interval %d: got %+v, want %+v", tc.moduleInterval, refs.Scripts, want)
		}
	}
	_, refs := Inspect([]byte(input), arguments)
	if len(refs.Scripts) != 5 || refs.Scripts[3].Interval != model.DefaultResourceInterval {
		t.Fatalf("unexpected default references %+v", refs.Scripts)
	}
}

func TestScriptSettingsKeepUnescapedArgumentText(t *testing.T) {
	const input = `[Script]
json = type=http-response, pattern=^https://example\.test/, script-path=https://example.test/a.js, argument="{"a":"1","b":"2"}"
list = type=http-response, pattern=^https://example\.test/, script-path=https://example.test/a.js, argument=Tab="one,two"&Level=1, requires-body=1
`
	result, report := Convert([]byte(input), Options{
		ResourceForKind: func(string, string) (string, bool) { return resource.Hash([]byte("a")), true },
	})
	if report.Partial || len(result.Scripts) != 2 {
		t.Fatalf("unexpected conversion %+v", report)
	}
	if got := *result.Scripts[0].Argument; got != `{"a":"1","b":"2"}` {
		t.Fatalf("json argument = %q", got)
	}
	if got := *result.Scripts[1].Argument; got != `Tab="one,two"&Level=1` || !*result.Scripts[1].RequiresBody {
		t.Fatalf("list argument = %q", got)
	}
}
