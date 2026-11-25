package module

import (
	"encoding/json"
	"regexp"
	"strconv"
	"strings"

	"github.com/MimoProxy/reka/internal/config/model"
)

type loonExpression struct {
	phase    string
	pattern  string
	capture  string
	action   string
	params   []string
	settings string
	cronExp  string // Set by background script expressions.
}

func isLoonExpression(text string) bool {
	_, rest, ok := word(text, false)
	keyword, _, hasKeyword := word(rest, false)
	return ok && hasKeyword && strings.EqualFold(keyword, "if")
}

func badExpression(message string) outcome {
	return unsupported("module.expression", message)
}

func parseLoonExpression(text string) (loonExpression, outcome) {
	var expression loonExpression
	phase, rest, _ := word(text, false)
	expression.phase = strings.ToLower(phase)
	keyword, rest, _ := word(rest, false)
	rest, hasURL := strings.CutPrefix(strings.TrimSpace(rest), "${url}")
	rest, hasComparison := strings.CutPrefix(strings.TrimSpace(rest), "~=")
	if expression.phase != "request" && expression.phase != "response" || !strings.EqualFold(keyword, "if") || !hasURL || !hasComparison {
		return expression, badExpression("expected a request or response URL regex condition")
	}
	pattern, rest, ok := loonDelimitedRegexp(strings.TrimSpace(rest))
	if !ok {
		return expression, badExpression("expected a slash-delimited URL regular expression")
	}
	flags, tail, _ := word(rest, false)
	if !startsSpace(rest) {
		rest = tail
		if flags != "i" {
			return expression, badExpression("only the i regular expression flag is supported")
		}
		pattern = "(?i)" + pattern
	}
	expression.pattern = pattern
	keyword, rest, _ = word(rest, false)
	if strings.EqualFold(keyword, "as") {
		expression.capture, rest, ok = word(rest, false)
		if !ok || !loonArgumentName.MatchString(expression.capture) {
			return expression, badExpression("invalid regular expression capture name")
		}
		keyword, rest, _ = word(rest, false)
	}
	if !strings.EqualFold(keyword, "then") {
		return expression, badExpression("only a single URL regex condition is supported")
	}
	return expression, expression.parseAction(rest)
}

// parseAction reads the text after then: an action call and optional settings.
func (e *loonExpression) parseAction(rest string) outcome {
	action, args, call := strings.Cut(strings.TrimSpace(rest), "(")
	e.action = strings.ToLower(strings.TrimSpace(action))
	if !call {
		if e.action == "reject" {
			return outcome{}
		}
		return badExpression("expected an action call")
	}
	end, ok := loonGroupEnd("(" + args)
	if !ok {
		return badExpression("invalid action arguments")
	}
	e.params, ok = splitLoonList(args[:end-1], true)
	if !ok {
		return badExpression("invalid action arguments")
	}
	if tail := strings.TrimSpace(args[end:]); tail != "" {
		keyword, rest, ok := word(tail, false)
		if !ok || !strings.EqualFold(keyword, "with") || strings.TrimSpace(rest) == "" {
			return badExpression("unexpected text after the action")
		}
		e.settings = strings.TrimSpace(rest)
	}
	return outcome{}
}

func loonDelimitedRegexp(text string) (pattern, rest string, ok bool) {
	if !strings.HasPrefix(text, "/") {
		return "", "", false
	}
	var out strings.Builder
	for i := 1; i < len(text); i++ {
		switch text[i] {
		case '\\':
			if i+1 == len(text) {
				return "", "", false
			}
			if text[i+1] != '/' {
				out.WriteByte('\\')
			}
			i++
			out.WriteByte(text[i])
		case '/':
			return out.String(), text[i+1:], true
		default:
			out.WriteByte(text[i])
		}
	}
	return "", "", false
}

func (row *loonLine) parseExpression(args loonArguments, remaining *int) {
	expression, issue := parseLoonExpression(row.text)
	if issue.status != "" {
		row.issue = issue
		return
	}
	switch expression.action {
	case "script":
		row.script, row.rewrite = true, false
		row.scriptSpec, row.scriptRef, row.issue = expression.script(args, remaining)
		return
	case "reject", "reject_dict", "reject_img", "reject_array", "redirect":
	case "request.json.delete", "response.json.delete", "request.json.replace", "response.json.replace", "request.json.jq", "response.json.jq":
	case "request.json.jq_file", "response.json.jq_file":
		row.issue = unsupported("module.jq-path", "modules cannot load Loon jq filter files")
		return
	default:
		row.issue = badExpression("unsupported Loon expression action")
		return
	}
	row.script, row.rewrite = false, true
	if expression.settings != "" {
		row.issue = badExpression("action settings are only supported on scripts")
		return
	}
	pattern, issue := args.expandDeferred(expression.pattern, remaining)
	if issue.status != "" {
		row.issue = issue
		return
	}
	switch expression.action {
	case "reject", "reject_dict", "reject_img", "reject_array", "redirect":
		row.urlRewrite, row.issue = expression.urlRewrite(pattern, args, remaining)
	default:
		row.bodyRewrite, row.issue = expression.bodyRewrite(pattern, args, remaining)
	}
}

func (e loonExpression) script(args loonArguments, remaining *int) (script model.Script, ref ScriptReference, issue outcome) {
	if len(e.params) < 1 || len(e.params) > 2 {
		return script, ref, badExpression("script requires a URL and optionally an argument")
	}
	source, ok := loonExpressionString(e.params[0])
	if !ok {
		return script, ref, badExpression("script requires a string URL")
	}
	fields, ok := parseScriptSettingsWithSeparator(e.settings, loonNextSetting, nil)
	if !ok {
		return script, ref, badExpression("invalid script action settings")
	}
	fields = append(fields, scriptSetting{"script-path", source})
	if e.cronExp != "" {
		fields = append(fields, scriptSetting{"cronexp", e.cronExp})
	}
	var object string
	if len(e.params) == 2 {
		if strings.HasPrefix(e.params[1], "{") {
			object = e.params[1]
		} else {
			argument, ok := loonExpressionString(e.params[1])
			if !ok {
				return script, ref, badExpression("script argument must be a string or an argument object")
			}
			fields = append(fields, scriptSetting{"argument", argument})
		}
	}
	return makeLoonScript(e.phase, e.pattern, fields, object, args, remaining)
}

func (e loonExpression) urlRewrite(pattern string, args loonArguments, remaining *int) (*model.HTTPRewrite, outcome) {
	if e.phase != "request" {
		return nil, badExpression("rejects and redirects must run before the upstream request")
	}
	if e.action == "redirect" {
		if len(e.params) != 2 || e.params[0] != "302" && e.params[0] != "307" {
			return nil, badExpression("redirect requires status 302 or 307 and a replacement URL")
		}
		target, ok := loonExpressionString(e.params[1])
		if !ok {
			return nil, badExpression("redirect requires a string replacement URL")
		}
		target, issue := args.expandDeferred(target, remaining)
		if issue.skips() {
			return nil, issue
		}
		compiled, err := regexp.Compile(pattern)
		if err != nil {
			return nil, incompatibleRegexp()
		}
		target, ok = loonRedirectCaptures(target, e.capture, compiled.NumSubexp())
		if !ok {
			return nil, badExpression("unsupported redirect capture reference")
		}
		result, issue := parseURLRewriteFields([]string{pattern, target, e.params[0]})
		return &result, issue
	}
	var action string
	switch e.action {
	case "reject":
		switch {
		case len(e.params) == 0 || len(e.params) == 1 && e.params[0] == "404":
			// The native generic reject returns an empty 404.
			action = "reject"
		case len(e.params) == 1 && e.params[0] == "200":
			action = "reject-200"
		}
	default:
		if len(e.params) == 1 && e.params[0] == "200" {
			action = strings.ReplaceAll(e.action, "_", "-")
		}
	}
	if action == "" {
		return nil, badExpression("unsupported reject status or arguments")
	}
	result, issue := parseURLRewriteFields([]string{pattern, action})
	return &result, issue
}

func loonRedirectCaptures(text, alias string, groups int) (string, bool) {
	var out strings.Builder
	for {
		prefix, token, found := strings.Cut(text, "${")
		out.WriteString(strings.ReplaceAll(prefix, "$", "$$"))
		if !found {
			return out.String(), true
		}
		name, tail, closed := strings.Cut(token, "}")
		if !closed || alias == "" {
			return "", false
		}
		index, bracket := strings.CutPrefix(name, alias+"[")
		if bracket {
			index, closed = strings.CutSuffix(index, "]")
			if !closed {
				return "", false
			}
		} else {
			index, found = strings.CutPrefix(name, alias+".")
			if !found {
				return "", false
			}
		}
		n, err := strconv.Atoi(index)
		// Native URL templates support $0 through $99.
		if err != nil || n < 0 || n > 99 || n > groups {
			return "", false
		}
		// The native template parser would read a one-digit capture followed
		// immediately by a literal digit as a different capture group.
		if n > 0 && n < 10 && tail != "" && tail[0] >= '0' && tail[0] <= '9' {
			return "", false
		}
		out.WriteByte('$')
		out.WriteString(strconv.Itoa(n))
		text = tail
	}
}

func (e loonExpression) bodyRewrite(pattern string, args loonArguments, remaining *int) (*model.BodyRewrite, outcome) {
	phase, action, _ := strings.Cut(e.action, ".json.")
	if phase != e.phase {
		return nil, badExpression("JSON action direction must match the expression direction")
	}
	switch action {
	case "jq":
		if len(e.params) != 1 {
			return nil, badExpression("jq requires one filter")
		}
		filter, issue := args.expressionString(e.params[0], remaining)
		if issue.skips() {
			return nil, issue
		}
		result, issue := parseBodyRewriteJQ(phase, pattern, filter)
		return &result, issue
	case "delete":
		if len(e.params) != 1 {
			return nil, badExpression("JSON deletion requires a path or a path array")
		}
		params := e.params
		if inside, array := strings.CutPrefix(params[0], "["); array {
			inside, ok := strings.CutSuffix(inside, "]")
			if !ok {
				return nil, badExpression("invalid JSON deletion path array")
			}
			params, ok = splitLoonList(inside, true)
			if !ok {
				return nil, badExpression("invalid JSON deletion path array")
			}
		}
		paths := make([]string, 0, len(params))
		for _, param := range params {
			path, issue := args.expressionString(param, remaining)
			if issue.skips() {
				return nil, issue
			}
			paths = append(paths, path)
		}
		result, issue := loonJSONDelete(phase, pattern, paths)
		return &result, issue
	case "replace":
		if len(e.params) != 2 {
			return nil, badExpression("JSON replacement requires a path and a value")
		}
		path, issue := args.expressionString(e.params[0], remaining)
		if issue.skips() {
			return nil, issue
		}
		value, issue := args.expressionJSONValue(e.params[1], remaining)
		if issue.skips() {
			return nil, issue
		}
		result, issue := loonJSONReplace(phase, pattern, []string{path, value})
		return &result, issue
	}
	return nil, badExpression("unsupported Loon JSON action")
}

func (a loonArguments) expressionString(text string, remaining *int) (string, outcome) {
	value, ok := loonExpressionString(text)
	if !ok {
		return "", badExpression("expected a string or a declared argument")
	}
	value, issue := a.expandDeferred(value, remaining)
	if issue.skips() {
		return "", issue
	}
	if strings.Contains(value, "${") {
		return "", badExpression("unresolved Loon expression variable")
	}
	return value, outcome{}
}

func (a loonArguments) expressionJSONValue(text string, remaining *int) (string, outcome) {
	if name, ok := loonExpressionVariable(text); ok {
		argument, ok := a.declared[name]
		if !ok {
			return "", badExpression("expected a declared argument")
		}
		value, issue := a.expressionString(text, remaining)
		if issue.skips() {
			return "", issue
		}
		if argument.Type == "switch" {
			flag, ok := parseScriptBool(value)
			if !ok {
				return "", badExpression("switch argument must be true or false")
			}
			return strconv.FormatBool(flag), outcome{}
		}
		return loonJSONString(value), outcome{}
	}
	if !strings.HasPrefix(text, "\"") && json.Valid([]byte(text)) {
		return text, outcome{}
	}
	value, issue := a.expressionString(text, remaining)
	if issue.skips() {
		return "", issue
	}
	return loonJSONString(value), outcome{}
}

func loonExpressionVariable(text string) (string, bool) {
	if strings.HasPrefix(text, "${") && strings.HasSuffix(text, "}") {
		name := text[2 : len(text)-1]
		return name, loonArgumentName.MatchString(name)
	}
	return "", false
}

func loonExpressionString(text string) (string, bool) {
	if text == "" {
		return "", false
	}
	if _, ok := loonExpressionVariable(text); ok {
		return text, true
	}
	if text[0] == '"' {
		var value string
		if err := json.Unmarshal([]byte(text), &value); err == nil {
			return value, true
		}
	} else if text[0] != '\'' {
		return "", false
	}
	return loonValue(text)
}

// splitLoonList reads commas outside quotes and, for expressions, groups.
func splitLoonList(text string, grouped bool) ([]string, bool) {
	if strings.TrimSpace(text) == "" {
		return nil, true
	}
	var fields []string
	start := 0
	for i := 0; i < len(text); i++ {
		switch text[i] {
		case '\'', '"':
			if !grouped {
				prefix := strings.TrimSpace(text[start:i])
				if prefix != "" && !strings.HasSuffix(prefix, "=") {
					continue
				}
			}
			end, ok := loonQuoteEnd(text[i:])
			if !ok {
				return nil, false
			}
			i += end
		case '(', '[', '{':
			if grouped {
				end, ok := loonGroupEnd(text[i:])
				if !ok {
					return nil, false
				}
				i += end
			}
		case ')', ']', '}':
			if grouped {
				return nil, false
			}
		case ',':
			fields = append(fields, strings.TrimSpace(text[start:i]))
			start = i + 1
		}
	}
	return append(fields, strings.TrimSpace(text[start:])), true
}

func loonGroupEnd(text string) (int, bool) {
	var pending []byte
	for i := 0; i < len(text); i++ {
		switch text[i] {
		case '(':
			pending = append(pending, ')')
		case '[':
			pending = append(pending, ']')
		case '{':
			pending = append(pending, '}')
		case '\'', '"':
			end, ok := loonQuoteEnd(text[i:])
			if !ok {
				return 0, false
			}
			i += end
		case ')', ']', '}':
			if len(pending) == 0 || pending[len(pending)-1] != text[i] {
				return 0, false
			}
			pending = pending[:len(pending)-1]
			if len(pending) == 0 {
				return i, true
			}
		}
	}
	return 0, false
}

func loonQuoteEnd(text string) (int, bool) {
	for i := 1; i < len(text); i++ {
		switch {
		case text[i] == '\\':
			i++
		case text[i] == text[0]:
			return i, true
		}
	}
	return 0, false
}
