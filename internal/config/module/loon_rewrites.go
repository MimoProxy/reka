package module

import (
	"encoding/json"
	"regexp"
	"strconv"
	"strings"

	"github.com/MimoProxy/reka/internal/config/model"
)

func (row *loonLine) parseRewrite() {
	switch row.section {
	case "header rewrite":
		result, issue := parseHeaderRewrite(row.text)
		row.headerRewrite, row.issue = &result, issue
		return
	case "body rewrite":
		result, issue := parseBodyRewrite(row.text)
		row.bodyRewrite, row.issue = &result, issue
		return
	}
	match, tail, ok := word(row.text, false)
	action, tail, actionOK := word(tail, false)
	if action == "-" {
		action, tail, actionOK = word(tail, false)
	}
	if !ok || !actionOK {
		row.issue = badRewrite("invalid Loon rewrite syntax")
		return
	}
	action = strings.ToLower(action)
	phase := "request"
	if body, ok := strings.CutPrefix(action, "response-"); ok {
		action, phase = body, "response"
	} else {
		action = strings.TrimPrefix(action, "request-")
	}
	switch action {
	case "reject", "reject-200", "reject-img", "reject-dict", "reject-array", "reject-drop", "reject-no-drop", "reject-tinygif":
		if strings.TrimSpace(tail) != "" || phase == "response" {
			row.issue = badRewrite("reject takes no arguments and runs before the upstream request")
			return
		}
		result, issue := parseURLRewriteFields([]string{match, action})
		// Loon's legacy reject closes the connection immediately.
		if action == "reject" {
			result.Response = ptr("close")
		}
		row.urlRewrite, row.issue = &result, issue
	case "header", "302", "307":
		target, rest, ok := word(tail, false)
		if !ok || strings.TrimSpace(rest) != "" || phase == "response" {
			row.issue = badRewrite("URL rewrite requires one replacement before the upstream request")
			return
		}
		result, issue := parseURLRewriteFields([]string{match, target, action})
		row.urlRewrite, row.issue = &result, issue
	case "header-add", "header-del", "header-replace", "header-replace-regex":
		fields, ok := words(tail, false)
		if !ok {
			row.issue = badRewrite("invalid Loon header rewrite arguments")
			return
		}
		result, issue := parseHeaderRewriteFields(append([]string{"http-" + phase, match, action}, fields...))
		row.headerRewrite, row.issue = &result, issue
	case "body-json-jq", "body-replace-regex":
		result, issue := parseBodyRewriteParts(phase, match, tail, action == "body-json-jq")
		row.bodyRewrite, row.issue = &result, issue
	case "body-json-del":
		paths, ok := words(tail, false)
		if !ok {
			row.issue = badRewrite("invalid Loon JSON rewrite paths")
			return
		}
		result, issue := loonJSONDelete(phase, match, paths)
		row.bodyRewrite, row.issue = &result, issue
	case "body-json-replace":
		result, issue := loonLegacyJSONReplace(phase, match, tail)
		row.bodyRewrite, row.issue = &result, issue
	case "mock-response-body":
		result, issue := parseLoonMock(match, tail)
		row.mapLocal, row.issue = &result, issue
	default:
		// Loon also accepts the Surge order: pattern, replacement, type.
		if fields, ok := words(row.text, false); ok && len(fields) == 3 {
			switch strings.ToLower(fields[2]) {
			case "header", "302", "307":
				result, issue := parseURLRewriteFields(fields)
				row.urlRewrite, row.issue = &result, issue
				return
			}
		}
		row.issue = badRewrite("unsupported Loon rewrite action")
	}
}

func parseLoonMock(match, tail string) (model.MapLocal, outcome) {
	result := model.MapLocal{Match: match, DataType: ptr("text")}
	fields, ok := words("match "+tail, true)
	if !ok || len(fields) < 2 {
		return result, badRewrite("invalid Loon mock response syntax")
	}
	if issue := validateMatch(match); issue.skips() {
		return result, issue
	}
	var contentType string
	base64 := false
	seen := make(map[string]bool)
	for _, field := range fields[1:] {
		key, value, ok := strings.Cut(field, "=")
		key = strings.ToLower(key)
		if !ok || seen[key] {
			return result, badRewrite("expected unique Loon mock response key=value settings")
		}
		seen[key] = true
		switch key {
		case "data":
			result.Data = ptr(value)
		case "data-type":
			switch strings.ToLower(value) {
			case "text", "json", "base64", "tiny-gif":
				result.DataType = ptr(strings.ToLower(value))
			case "plain", "text/plain":
				contentType = "text/plain"
			case "text/event-stream":
				contentType = "text/event-stream"
			case "css", "html", "javascript":
				contentType = "text/" + strings.ToLower(value)
			case "png", "gif", "jpeg", "tiff":
				contentType = "image/" + strings.ToLower(value)
			case "svg":
				contentType = "image/svg+xml"
			case "mp4":
				contentType = "video/mp4"
			default:
				return result, unsupported("module.map-local-type", "unknown Loon mock response data type")
			}
		case "status-code":
			code, err := strconv.Atoi(value)
			if err != nil || code < 100 || code > 599 {
				return result, unsupported("module.map-local-status", "mock response status code must be between 100 and 599")
			}
			result.StatusCode = ptr(code)
		case "mock-data-is-base64":
			base64, ok = parseScriptBool(value)
			if !ok {
				return result, badRewrite("mock-data-is-base64 must be true or false")
			}
		default:
			return result, unsupported("module.map-local-setting", "unsupported Loon mock response setting")
		}
	}
	if base64 {
		if *result.DataType == "json" {
			contentType = "application/json"
		} else if contentType == "" && *result.DataType == "text" {
			contentType = "text/plain"
		}
		result.DataType = ptr("base64")
	}
	if contentType != "" {
		result.Headers = []model.MapLocalHeader{{Name: "Content-Type", Value: ptr(contentType)}}
	}
	if !validMapLocal(result) {
		return result, unsupported("module.map-local-value", "invalid Loon mock response data")
	}
	return result, outcome{}
}

func loonJSONDelete(phase, match string, paths []string) (model.BodyRewrite, outcome) {
	if len(paths) == 0 {
		return model.BodyRewrite{}, badRewrite("JSON deletion requires a path")
	}
	fields := make([]string, 0, len(paths))
	for _, path := range paths {
		expression, ok := loonJQPath(path)
		if !ok {
			return model.BodyRewrite{}, unsupported("module.json-path", "unsupported Loon JSON key path")
		}
		fields = append(fields, expression)
	}
	return parseBodyRewriteJQ(phase, match, "del("+strings.Join(fields, ", ")+")")
}

func loonLegacyJSONReplace(phase, match, text string) (model.BodyRewrite, outcome) {
	var pairs []string
	for strings.TrimSpace(text) != "" {
		path, rest, ok := word(text, false)
		if !ok {
			return model.BodyRewrite{}, badRewrite("invalid Loon JSON rewrite path")
		}
		value, tail, ok := loonLegacyJSONValue(rest)
		if !ok {
			return model.BodyRewrite{}, badRewrite("JSON replacement requires path and value pairs")
		}
		pairs = append(pairs, path, value)
		text = tail
	}
	return loonJSONReplace(phase, match, pairs)
}

func loonLegacyJSONValue(text string) (value, rest string, ok bool) {
	text = strings.TrimSpace(text)
	if text == "" {
		return "", "", false
	}
	if text[0] == '{' || text[0] == '[' || text[0] == '"' {
		var raw json.RawMessage
		decoder := json.NewDecoder(strings.NewReader(text))
		if err := decoder.Decode(&raw); err == nil {
			tail := text[decoder.InputOffset():]
			if tail == "" || startsSpace(tail) {
				return string(raw), tail, true
			}
		}
		if text[0] != '"' {
			return "", "", false
		}
	}
	value, rest, ok = word(text, false)
	if !ok {
		return "", "", false
	}
	if text[0] != '\'' && text[0] != '"' && json.Valid([]byte(value)) {
		return value, rest, true
	}
	return loonJSONString(value), rest, true
}

// pairs contains alternating paths and already encoded JSON values.
func loonJSONReplace(phase, match string, pairs []string) (model.BodyRewrite, outcome) {
	if len(pairs) == 0 || len(pairs)%2 != 0 {
		return model.BodyRewrite{}, badRewrite("JSON replacement requires path and value pairs")
	}
	var filters []string
	for i := 0; i < len(pairs); i += 2 {
		expression, ok := loonJQPath(pairs[i])
		if !ok {
			return model.BodyRewrite{}, unsupported("module.json-path", "unsupported Loon JSON key path")
		}
		filters = append(filters, "("+expression+" = "+pairs[i+1]+")")
	}
	return parseBodyRewriteJQ(phase, match, strings.Join(filters, " | "))
}

var loonJQIdentifier = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func loonJQPath(path string) (string, bool) {
	path = strings.TrimPrefix(path, ".")
	if path == "" {
		return "", false
	}
	var expression strings.Builder
	expression.WriteByte('.')
	for {
		at := strings.IndexAny(path, ".[]")
		if at < 0 {
			at = len(path)
		}
		key := path[:at]
		if key == "" && (expression.Len() != 1 || !strings.HasPrefix(path, "[")) {
			return "", false
		}
		if key != "" {
			if loonJQIdentifier.MatchString(key) {
				if expression.Len() > 1 {
					expression.WriteByte('.')
				}
				expression.WriteString(key)
			} else {
				expression.WriteByte('[')
				expression.WriteString(loonJSONString(key))
				expression.WriteByte(']')
			}
		}
		path = path[at:]
		for strings.HasPrefix(path, "[") {
			index, tail, ok := strings.Cut(path[1:], "]")
			number, err := strconv.ParseUint(index, 10, 31)
			if !ok || err != nil {
				return "", false
			}
			expression.WriteByte('[')
			expression.WriteString(strconv.FormatUint(number, 10))
			expression.WriteByte(']')
			path = tail
		}
		if path == "" {
			return expression.String(), true
		}
		var ok bool
		path, ok = strings.CutPrefix(path, ".")
		if !ok || path == "" {
			return "", false
		}
	}
}

func loonJSONString(s string) string {
	encoded, _ := json.Marshal(s)
	return string(encoded)
}
