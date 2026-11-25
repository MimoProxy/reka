package module

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/MimoProxy/reka/internal/config/model"
	"go.yaml.in/yaml/v3"
)

func (c *converter) stashRewrite(node *yaml.Node, key string) outcome {
	if key == "mock" {
		rule, issue := parseStashMock(node)
		if !issue.skips() {
			return c.addMapLocal(node.Line, rule, "")
		}
		return issue
	}
	text, ok := stashString(node)
	if !ok {
		if key == "body-rewrite" {
			return unsupported("module.body-rewrite-provider", "body rewrites require an inline rewrite expression")
		}
		return badRewrite("expected a rewrite string")
	}
	switch key {
	case "url-rewrite":
		fields, ok := words(text, false)
		if !ok || len(fields) < 2 {
			return badRewrite("invalid URL rewrite syntax")
		}
		if strings.EqualFold(fields[len(fields)-1], "transparent") {
			fields[len(fields)-1] = "header"
		}
		rule, issue := parseURLRewriteFields(fields)
		if !issue.skips() {
			c.addURLRewrite(node.Line, rule)
		}
		return issue
	case "header-rewrite":
		fields, ok := words(text, false)
		if !ok || len(fields) < 3 {
			return badRewrite("invalid header rewrite syntax")
		}
		phase, action, ok := stashRewriteAction(fields[1])
		if !ok {
			return unsupported("module.header-operation", "unknown header rewrite direction")
		}
		rule, issue := parseHeaderRewriteFields(append([]string{"http-" + phase, fields[0], "header-" + action}, fields[2:]...))
		if !issue.skips() {
			c.addHeaderRewrite(node.Line, rule)
		}
		return issue
	case "body-rewrite":
		rule, issue := parseStashBodyRewrite(text)
		if !issue.skips() {
			c.addBodyRewrite(node.Line, rule)
		}
		return issue
	}
	return unsupported("module.section", "unknown rewrite section")
}

func stashRewriteAction(value string) (phase, action string, ok bool) {
	phase, action, ok = strings.Cut(strings.ToLower(value), "-")
	return phase, action, ok && (phase == "request" || phase == "response")
}

func parseStashBodyRewrite(text string) (model.BodyRewrite, outcome) {
	match, rest, ok := word(text, false)
	if !ok {
		return model.BodyRewrite{}, badRewrite("body rewrite requires a URL pattern")
	}
	operation, args, ok := word(rest, false)
	if !ok {
		return model.BodyRewrite{}, badRewrite("body rewrite requires an operation")
	}
	phase, action, ok := stashRewriteAction(operation)
	if !ok {
		return model.BodyRewrite{}, badRewrite("unknown body rewrite direction")
	}
	args = strings.TrimSpace(args)
	switch action {
	case "jq":
		// Single quotes wrap the whole filter. Double quotes can start a jq
		// string literal and are preserved.
		if strings.HasPrefix(args, "'") {
			filter, tail, ok := quoted(args)
			if !ok || strings.TrimSpace(tail) != "" {
				return model.BodyRewrite{}, badRewrite("invalid quoted jq filter")
			}
			args = filter
		}
		return parseBodyRewriteJQ(phase, match, args)
	case "replace-regex":
		return parseBodyRewriteParts(phase, match, args, false)
	default:
		return model.BodyRewrite{}, unsupported("module.body-operation", "unknown body rewrite operation")
	}
}

func parseStashMock(node *yaml.Node) (model.MapLocal, outcome) {
	var rule model.MapLocal
	fields, ok := stashMapping(node)
	if !ok {
		return rule, unsupported("module.mock-syntax", "expected a mock response mapping with unique keys")
	}
	rule.Match, _ = stashString(fields["match"])
	if issue := validateMatch(rule.Match); issue.skips() {
		return rule, issue
	}
	for name := range fields {
		switch name {
		case "match", "status-code", "headers", "text", "base64", "data", "data-type":
		default:
			return rule, unsupported("module.mock-setting", "unknown mock response setting")
		}
	}
	if status := fields["status-code"]; status != nil {
		if status.Kind != yaml.ScalarNode {
			return rule, unsupported("module.map-local-status", "mock status code must be an integer")
		}
		code, err := strconv.Atoi(status.Value)
		if err != nil || code < http.StatusOK || code > 999 {
			return rule, unsupported("module.map-local-status", "mock responses require a final HTTP status code from 200 to 999")
		}
		rule.StatusCode = ptr(code)
	}
	if fields["headers"] != nil {
		headers, ok := stashMockHeaders(fields["headers"])
		if !ok {
			return rule, unsupported("module.map-local-header", "expected mock headers and string values")
		}
		rule.Headers = headers
	}
	kind := "text"
	data := fields["data"]
	switch {
	case fields["data-type"] != nil:
		kind, _ = stashString(fields["data-type"])
		kind = strings.ToLower(kind)
		if fields["text"] != nil || fields["base64"] != nil {
			return rule, unsupported("module.mock-syntax", "mock response has conflicting data fields")
		}
	case fields["text"] != nil:
		if data != nil || fields["base64"] != nil {
			return rule, unsupported("module.mock-syntax", "mock response has conflicting data fields")
		}
		data = fields["text"]
	case fields["base64"] != nil:
		if data != nil {
			return rule, unsupported("module.mock-syntax", "mock response has conflicting data fields")
		}
		kind, data = "base64", fields["base64"]
	}
	rule.DataType = ptr(kind)
	switch kind {
	case "text", "json", "base64", "tiny-gif":
	default:
		return rule, unsupported("module.map-local-type", "mock responses require an inline data type")
	}
	if data != nil {
		value, ok := stashString(data)
		if !ok {
			return rule, unsupported("module.map-local-value", "expected inline mock data as a string")
		}
		if kind != "tiny-gif" || value != "" {
			rule.Data = ptr(value)
		}
	} else if kind == "text" {
		rule.Data = ptr("")
	}
	if !validMapLocal(rule) {
		return rule, unsupported("module.map-local-value", "invalid or unsupported mock data or headers")
	}
	return rule, outcome{}
}

func stashMockHeaders(node *yaml.Node) ([]model.MapLocalHeader, bool) {
	if _, ok := stashMapping(node); !ok {
		return nil, false
	}
	var headers []model.MapLocalHeader
	for i := 0; i < len(node.Content); i += 2 {
		name := http.CanonicalHeaderKey(node.Content[i].Value)
		value := node.Content[i+1]
		values := []*yaml.Node{value}
		if seq := stashSequence(value); seq != nil {
			values = seq.Content
		}
		for _, field := range values {
			if field.Kind != yaml.ScalarNode {
				return nil, false
			}
			switch field.ShortTag() {
			case "!!str", "!!int", "!!float", "!!bool":
				headers = append(headers, model.MapLocalHeader{Name: name, Value: ptr(field.Value)})
			default:
				return nil, false
			}
		}
	}
	return headers, true
}
