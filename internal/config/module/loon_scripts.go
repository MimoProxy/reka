package module

import (
	"encoding/json"
	"net/url"
	"path"
	"regexp"
	"strings"

	"github.com/MimoProxy/reka/internal/config/model"
)

// Loon accepts underscores and hyphens in script setting names.
var loonNextSetting = regexp.MustCompile(`^\s*(?:$|,\s*[A-Za-z][A-Za-z0-9_-]*\s*=)`)

func parseLoonScript(text string, args loonArguments, remaining *int) (model.Script, ScriptReference, outcome) {
	var script model.Script
	var ref ScriptReference
	direction, rest, ok := word(text, false)
	direction = strings.TrimPrefix(strings.ToLower(direction), "http-")
	var pattern, settings, cronExp string
	switch {
	case !ok:
		return script, ref, unsupported("module.script-type", "expected a script type")
	case direction == "request" || direction == "response":
		if pattern, settings, ok = word(rest, false); !ok {
			return script, ref, unsupported("module.script-pattern", "HTTP scripts require a URL pattern")
		}
	case direction == "cron":
		if pattern, settings, ok = word(rest, false); !ok {
			return script, ref, unsupported("module.script-cronexp", "cron scripts require a cron expression")
		}
		if then, action, ok := word(settings, false); ok && strings.EqualFold(then, "then") {
			return loonBackgroundExpression(direction, pattern, action, args, remaining)
		}
		cronExp, pattern = pattern, ""
	case direction == "generic" || direction == "network-changed":
		settings = rest
		if then, action, ok := word(settings, false); ok && strings.EqualFold(then, "then") {
			return loonBackgroundExpression(direction, "", action, args, remaining)
		}
	default:
		return script, ref, unsupported("module.script-type", "expected an HTTP, cron, generic or network-changed script")
	}
	argumentQuoted := false
	fields, ok := parseScriptSettingsWithSeparator(settings, loonNextSetting, func(key string) {
		if key == "argument" {
			argumentQuoted = true
		}
	})
	if !ok {
		return script, ref, unsupported("module.script-syntax", "expected unique comma-separated script settings")
	}
	if direction == "cron" {
		fields = append([]scriptSetting{{"cronexp", cronExp}}, fields...)
	}
	var object string
	if !argumentQuoted {
		for _, field := range fields {
			if field.key == "argument" {
				trimmed := strings.TrimSpace(strings.TrimPrefix(field.value, "["))
				if strings.HasPrefix(field.value, "[") && strings.HasPrefix(trimmed, "{") {
					object = field.value
				}
			}
		}
	}
	return makeLoonScript(direction, pattern, fields, object, args, remaining)
}

// loonBackgroundExpression parses the script(...) action of the cron,
// generic and network-changed expression forms.
func loonBackgroundExpression(kind, cronExp, action string, args loonArguments, remaining *int) (model.Script, ScriptReference, outcome) {
	expression := loonExpression{phase: kind, cronExp: cronExp}
	if issue := expression.parseAction(action); issue.status != "" {
		return model.Script{}, ScriptReference{}, issue
	}
	if expression.action != "script" {
		return model.Script{}, ScriptReference{}, badExpression("background scripts require a script action")
	}
	return expression.script(args, remaining)
}

// makeLoonScript builds a script of the Loon kind request, response, cron,
// generic or network-changed. pattern is the URL pattern of HTTP scripts.
func makeLoonScript(kind, pattern string, settings []scriptSetting, object string, args loonArguments, remaining *int) (model.Script, ScriptReference, outcome) {
	var script model.Script
	var ref ScriptReference
	seen := make(map[string]bool)
	for i, field := range settings {
		key := strings.ReplaceAll(field.key, "_", "-")
		if seen[key] || key == "type" || key == "pattern" || key == "event-name" || key == "cronexp" && kind != "cron" {
			return script, ref, unsupported("module.script-syntax", "expected unique script settings")
		}
		seen[key] = true
		settings[i].key = key
		if key == "enable" {
			value, issue := args.expandDeferred(field.value, remaining)
			if issue.skips() {
				return script, ref, issue
			}
			enabled, ok := parseScriptBool(value)
			if !ok {
				return script, ref, unsupported("module.script-enable", "enable must be 1, 0, true or false")
			}
			if !enabled {
				return script, ref, ignored("module.script-disabled", "script is disabled")
			}
		}
	}
	var fields []scriptSetting
	switch kind {
	case "request", "response":
		pattern, issue := args.expandDeferred(pattern, remaining)
		if issue.skips() {
			return script, ref, issue
		}
		fields = []scriptSetting{{"type", "http-" + kind}, {"pattern", pattern}}
	case "network-changed":
		fields = []scriptSetting{{"type", "event"}, {"event-name", "network-changed"}}
	default:
		fields = []scriptSetting{{"type", kind}}
	}
	var issue outcome
	var name, scriptURL string
	for _, field := range settings {
		if field.key == "enable" || field.key == "img-url" || field.key == "argument" && object != "" {
			continue
		}
		field.value, issue = args.expandDeferred(field.value, remaining)
		if issue.skips() {
			return script, ref, issue
		}
		switch field.key {
		case "tag":
			name = strings.TrimSpace(field.value)
		default:
			fields = append(fields, field)
			if field.key == "script-path" {
				scriptURL = field.value
			}
		}
	}
	if name == "" {
		name = fields[0].value
		if parsed, err := url.Parse(scriptURL); err == nil && nameFromPath(parsed.Path) != "" {
			name = nameFromPath(parsed.Path)
		}
	}
	script, ref, issue = parseScriptFields(name, model.ModuleFormatLoon, fields)
	if issue.skips() || object == "" {
		return script, ref, issue
	}
	value, issue := args.scriptObject(object, remaining)
	if !issue.skips() {
		script.Argument = ptr(value)
		script.ArgumentType = ptr("object")
	}
	return script, ref, issue
}

func nameFromPath(file string) string {
	name := path.Base(file)
	if name == "." || name == "/" {
		return ""
	}
	return name
}

func (a loonArguments) scriptObject(text string, remaining *int) (string, outcome) {
	badObject := unsupported("module.script-argument", "expected declared arguments in the Loon script argument object")
	legacy := strings.HasPrefix(text, "[")
	open, close := "{", "}"
	if legacy {
		open, close = "[", "]"
	}
	if !strings.HasPrefix(text, open) || !strings.HasSuffix(text, close) {
		return "", badObject
	}
	fields, ok := splitLoonList(text[1:len(text)-1], true)
	if !ok {
		return "", badObject
	}
	var out strings.Builder
	out.WriteByte('{')
	seen := make(map[string]bool)
	for _, field := range fields {
		prefix := "${"
		if legacy {
			prefix = "{"
		}
		name, prefixed := strings.CutPrefix(field, prefix)
		name, suffixed := strings.CutSuffix(name, "}")
		name = strings.TrimSpace(name)
		argument, declared := a.declared[name]
		if !prefixed || !suffixed || !declared || seen[name] {
			return "", badObject
		}
		seen[name] = true
		// Check the unescaped size before allocating temporary JSON.
		budget := *remaining + len(text) - out.Len()
		if len(name)+len(argument.Value) > budget {
			return "", loonExpansionLimit(remaining)
		}
		var value any = argument.Value
		if argument.Type == "switch" {
			flag, ok := parseScriptBool(argument.Value)
			if !ok {
				return "", unsupported("module.script-argument", "switch argument must be true or false")
			}
			value = flag
		}
		encodedName, _ := json.Marshal(name)
		encodedValue, _ := json.Marshal(value)
		if len(encodedName)+len(encodedValue)+3 > budget {
			return "", loonExpansionLimit(remaining)
		}
		if out.Len() > 1 {
			out.WriteByte(',')
		}
		out.Write(encodedName)
		out.WriteByte(':')
		out.Write(encodedValue)
	}
	out.WriteByte('}')
	*remaining += len(text) - out.Len()
	return out.String(), outcome{}
}
