package module

import (
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/MimoProxy/reka/internal/config/model"
)

// ScriptReference identifies a remote script and its refresh interval in seconds.
type ScriptReference struct {
	URL      string
	Interval int
}

// ScriptItem describes a convertible script in a module report or preview.
type ScriptItem struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	Type           string `json:"type"`
	Pattern        string `json:"pattern"`
	RequiresBody   bool   `json:"requires_body"`
	BinaryBodyMode bool   `json:"binary_body_mode"`
	MaxSize        *int64 `json:"max_size,omitempty"`
	Timeout        int    `json:"timeout"`
	Engine         string `json:"engine"`
	Hash           string `json:"hash,omitempty"`
	Locked         bool   `json:"locked"`
}

func (c *converter) script(line int, text string) outcome {
	script, ref, issue := parseScript(text)
	if issue.skips() {
		return issue
	}
	// Identify the declaration before pinning source bytes so overlays keep working
	// across script updates.
	script.ID = c.id("s", struct {
		Script model.Script
		URL    string
	}{script, ref.URL}, line)
	hash := c.opts.resourceHash("script", ref.URL)
	c.report.ScriptItems = append(c.report.ScriptItems, ScriptItem{
		ID: script.ID, Name: *script.Name, Type: script.Type, Pattern: *script.Pattern,
		RequiresBody: *script.RequiresBody, BinaryBodyMode: *script.BinaryBodyMode,
		MaxSize: script.MaxSize, Timeout: *script.Timeout, Engine: *script.Engine,
		Hash: hash, Locked: hash != "",
	})
	if hash == "" {
		return unsupported("module.script-unavailable", "module script is not downloaded; refresh the module")
	}
	script.Hash = ptr(hash)
	c.result.Scripts = append(c.result.Scripts, script)
	return outcome{}
}

type scriptSetting struct{ key, value string }

func parseScript(text string) (model.Script, ScriptReference, outcome) {
	var script model.Script
	var ref ScriptReference
	name, settings, ok := strings.Cut(text, "=")
	name = strings.TrimSpace(name)
	if !ok || name == "" {
		return script, ref, unsupported("module.script-syntax", "expected a script name followed by settings")
	}
	fields, ok := parseScriptSettings(settings)
	if !ok {
		return script, ref, unsupported("module.script-syntax", "expected unique comma-separated script settings")
	}
	for _, field := range fields {
		if field.key == "type" {
			script.Type = strings.ToLower(field.value)
			break
		}
	}
	if script.Type != "http-request" && script.Type != "http-response" {
		return script, ref, unsupported("module.script-type", "only http-request and http-response script types are supported")
	}
	script.Name = ptr(name)
	script.Format = ptr(model.ModuleFormatSurge)
	script.RequiresBody = ptr(false)
	script.BinaryBodyMode = ptr(false)
	script.Timeout = ptr(model.DefaultScriptTimeout)
	script.Engine = ptr("auto")
	for _, field := range fields {
		value := field.value
		switch field.key {
		case "type", "debug":
		case "pattern":
			script.Pattern = ptr(value)
		case "requires-body", "binary-body-mode":
			flag, ok := parseScriptBool(value)
			if !ok {
				return script, ref, unsupported("module.script-"+field.key, field.key+" must be 1, 0, true or false")
			}
			if field.key == "requires-body" {
				script.RequiresBody = ptr(flag)
			} else {
				script.BinaryBodyMode = ptr(flag)
			}
		case "max-size":
			limit, err := strconv.ParseInt(value, 10, 64)
			if err != nil || limit < -1 {
				return script, ref, unsupported("module.script-max-size", "max-size must be an integer greater than or equal to -1")
			}
			script.MaxSize = ptr(limit)
		case "timeout":
			seconds, err := strconv.Atoi(value)
			if err != nil || seconds < 1 || seconds > model.MaxScriptTimeout {
				return script, ref, unsupported("module.script-timeout", "timeout must be an integer from 1 to 3600 seconds")
			}
			script.Timeout = ptr(seconds)
		case "argument":
			script.Argument = ptr(value)
		case "engine":
			engine := strings.ToLower(value)
			switch engine {
			case "auto", "jsc", "webview":
				script.Engine = ptr(engine)
			default:
				return script, ref, unsupported("module.script-engine", "engine must be auto, jsc or webview")
			}
		case "script-path":
			ref.URL = value
		case "script-update-interval":
			seconds, err := strconv.ParseInt(value, 10, 64)
			if err != nil || seconds < -1 {
				return script, ref, unsupported("module.script-update-interval", "script-update-interval must be an integer greater than or equal to -1")
			}
			if seconds > 0 {
				ref.Interval = int(min(max(seconds, model.ModuleMinInterval), model.ModuleMaxInterval))
			}
		default:
			return script, ref, unsupported("module.script-setting", "unsupported script setting")
		}
	}
	if script.Pattern == nil || *script.Pattern == "" {
		return script, ref, unsupported("module.script-pattern", "HTTP scripts require a URL pattern")
	}
	if issue := validateMatch(*script.Pattern); issue.skips() {
		return script, ref, issue
	}
	parsed, err := url.Parse(ref.URL)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Hostname() == "" || parsed.Fragment != "" {
		return script, ref, unsupported("module.script-path", "script-path must be a remote HTTP(S) URL")
	}
	return script, ref, outcome{}
}

func parseScriptBool(value string) (bool, bool) {
	switch strings.ToLower(value) {
	case "1", "true":
		return true, true
	case "0", "false":
		return false, true
	default:
		return false, false
	}
}

func parseScriptSettings(settings string) ([]scriptSetting, bool) {
	var fields []scriptSetting
	seen := make(map[string]bool)
	for settings = strings.TrimSpace(settings); settings != ""; settings = strings.TrimSpace(settings) {
		separator := strings.IndexAny(settings, "=,")
		if separator < 0 || settings[separator] != '=' {
			return nil, false
		}
		key := strings.ToLower(strings.TrimSpace(settings[:separator]))
		if key == "" || seen[key] {
			return nil, false
		}
		value := strings.TrimSpace(settings[separator+1:])
		if strings.HasPrefix(value, `"`) {
			var ok bool
			value, settings, ok = quotedSetting(value)
			if !ok {
				return nil, false
			}
		} else {
			value, settings = unquotedSetting(value)
		}
		fields = append(fields, scriptSetting{key, value})
		seen[key] = true
	}
	return fields, true
}

// Module authors often leave commas and quotes unescaped inside argument
// values, such as embedded JSON or comma-separated choices. A value therefore
// ends only at the end of the line or at a comma that starts another
// key=value setting.
var nextSetting = regexp.MustCompile(`^\s*(?:$|,\s*[A-Za-z][A-Za-z0-9-]*\s*=)`)

// unquotedSetting reads a bare value.
func unquotedSetting(s string) (value, rest string) {
	for i := 0; i < len(s); i++ {
		if s[i] == ',' && nextSetting.MatchString(s[i:]) {
			return strings.TrimSpace(s[:i]), s[i+1:]
		}
	}
	return strings.TrimSpace(s), ""
}

// quotedSetting reads a double-quoted value. A backslash escapes a quote.
func quotedSetting(s string) (value, rest string, ok bool) {
	var out strings.Builder
	for i := 1; i < len(s); i++ {
		switch {
		case s[i] == '\\' && i+1 < len(s) && s[i+1] == '"':
			out.WriteByte('"')
			i++
		case s[i] == '"' && nextSetting.MatchString(s[i+1:]):
			rest = strings.TrimSpace(s[i+1:])
			return out.String(), strings.TrimPrefix(rest, ","), true
		default:
			out.WriteByte(s[i])
		}
	}
	return "", "", false
}
