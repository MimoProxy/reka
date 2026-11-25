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
	if !ok || direction != "request" && direction != "response" {
		return script, ref, unsupported("module.script-type", "only HTTP request and response scripts are supported")
	}
	pattern, settings, ok := word(rest, false)
	if !ok {
		return script, ref, unsupported("module.script-pattern", "HTTP scripts require a URL pattern")
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

func makeLoonScript(direction, pattern string, settings []scriptSetting, object string, args loonArguments, remaining *int) (model.Script, ScriptReference, outcome) {
	var script model.Script
	var ref ScriptReference
	seen := make(map[string]bool)
	for i, field := range settings {
		key := strings.ReplaceAll(field.key, "_", "-")
		if seen[key] || key == "type" || key == "pattern" {
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
	pattern, issue := args.expandDeferred(pattern, remaining)
	if issue.skips() {
		return script, ref, issue
	}
	fields := []scriptSetting{{"type", "http-" + direction}, {"pattern", pattern}}
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
		name = "http-" + direction
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
