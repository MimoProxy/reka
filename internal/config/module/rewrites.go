package module

import (
	"net/http"
	"regexp"
	"strings"

	"github.com/MimoProxy/reka/internal/config/model"
	"github.com/MimoProxy/reka/internal/httprewrite"
)

func (c *converter) rewrite(line int, section, text string) outcome {
	switch section {
	case "url rewrite":
		r, issue := parseURLRewrite(text)
		if !issue.skips() {
			c.addURLRewrite(line, r)
		}
		return issue
	case "header rewrite":
		r, issue := parseHeaderRewrite(text)
		if !issue.skips() {
			c.addHeaderRewrite(line, r)
		}
		return issue
	case "body rewrite":
		r, issue := parseBodyRewrite(text)
		if !issue.skips() {
			c.addBodyRewrite(line, r)
		}
		return issue
	case "map local":
		r, url, issue := parseMapLocal(text)
		if issue.skips() {
			return issue
		}
		return c.addMapLocal(line, r, url)
	}
	return unsupported("module.section", "unknown rewrite section")
}

func (c *converter) addURLRewrite(line int, r model.HTTPRewrite) {
	r.ID = c.id("u", r, line)
	c.result.HTTPRewrites = append(c.result.HTTPRewrites, r)
}

func (c *converter) addHeaderRewrite(line int, r model.HeaderRewrite) {
	r.ID = c.id("h", r, line)
	c.result.HeaderRewrites = append(c.result.HeaderRewrites, r)
}

func (c *converter) addBodyRewrite(line int, r model.BodyRewrite) {
	r.ID = c.id("b", r, line)
	c.result.BodyRewrites = append(c.result.BodyRewrites, r)
}

func (c *converter) addMapLocal(line int, r model.MapLocal, url string) outcome {
	var hash string
	if url != "" {
		hash = c.opts.resourceHash("map-local", url)
		if hash == "" {
			return failed("module.resource-missing", "module resource is not downloaded; refresh the module")
		}
	}
	// Identify remote rules by their declaration. Updated resource bytes do
	// not invalidate overlays targeting the rule.
	r.ID = c.id("m", r, line)
	if hash != "" {
		r = lockMapLocal(r, hash)
	}
	c.result.MapLocal = append(c.result.MapLocal, r)
	return outcome{}
}

func parseURLRewrite(text string) (model.HTTPRewrite, outcome) {
	fields, ok := words(text, false)
	if !ok {
		return model.HTTPRewrite{}, badRewrite("invalid URL rewrite syntax")
	}
	return parseURLRewriteFields(fields)
}

func parseURLRewriteFields(fields []string) (model.HTTPRewrite, outcome) {
	var r model.HTTPRewrite
	if len(fields) < 2 || len(fields) > 3 {
		return r, badRewrite("invalid URL rewrite syntax")
	}
	r.Match = fields[0]
	if issue := validateMatch(r.Match); issue.skips() {
		return r, issue
	}
	action := strings.ToLower(fields[len(fields)-1])
	switch action {
	case "header", "302", "307":
		if len(fields) != 3 {
			return r, badRewrite("this URL rewrite requires a replacement")
		}
		r.Action, r.Target = action, ptr(fields[1])
	default:
		responses := map[string]string{
			"reject": "error", "reject-no-drop": "error", "reject-200": "200", "reject-img": "gif",
			"reject-tinygif": "gif", "reject-dict": "dict", "reject-array": "array", "reject-drop": "drop",
		}
		response, ok := responses[action]
		if !ok {
			return r, unsupported("module.url-action", "unknown URL rewrite action")
		}
		r.Action, r.Response = "reject", ptr(response)
	}
	return r, outcome{}
}

func parseHeaderRewrite(text string) (model.HeaderRewrite, outcome) {
	fields, ok := words(text, false)
	if !ok {
		return model.HeaderRewrite{}, badRewrite("invalid header rewrite syntax")
	}
	return parseHeaderRewriteFields(fields)
}

func parseHeaderRewriteFields(fields []string) (model.HeaderRewrite, outcome) {
	var r model.HeaderRewrite
	if len(fields) < 3 {
		return r, badRewrite("invalid header rewrite syntax")
	}
	phase := "request"
	if value, found := rewritePhase(fields[0]); found {
		phase, fields = value, fields[1:]
	}
	if len(fields) < 3 {
		return r, badRewrite("invalid header rewrite syntax")
	}
	r.Phase, r.Match, r.Name = ptr(phase), fields[0], http.CanonicalHeaderKey(fields[2])
	if issue := validateMatch(r.Match); issue.skips() {
		return r, issue
	}
	if r.Name == "Content-Length" || r.Name == "Transfer-Encoding" {
		return r, unsupported("module.header-framing", "HTTP framing headers cannot be rewritten")
	}
	switch strings.ToLower(fields[1]) {
	case "header-del":
		if len(fields) != 3 {
			return r, badRewrite("header-del accepts only a field name")
		}
		r.Op = "del"
	case "header-add", "header-replace":
		if len(fields) != 4 {
			return r, badRewrite("this header operation requires a value")
		}
		r.Op, r.Value = strings.TrimPrefix(strings.ToLower(fields[1]), "header-"), ptr(fields[3])
	case "header-replace-regex":
		if len(fields) != 5 {
			return r, badRewrite("header-replace-regex requires a pattern and replacement")
		}
		if _, err := regexp.Compile(fields[3]); err != nil {
			return r, incompatibleRegexp()
		}
		r.Op, r.Pattern, r.Value = "replace-regex", ptr(fields[3]), ptr(fields[4])
	default:
		return r, unsupported("module.header-operation", "unknown header rewrite operation")
	}
	_, err := httprewrite.New(httprewrite.Spec{HeaderRewrites: []httprewrite.HeaderRewrite{{
		Match: r.Match, Phase: r.Phase, Op: r.Op, Name: r.Name, Pattern: r.Pattern, Value: r.Value,
	}}}, httprewrite.Options{})
	if err != nil {
		return r, badRewrite("invalid or unsupported HTTP header field")
	}
	return r, outcome{}
}

func parseBodyRewrite(text string) (model.BodyRewrite, outcome) {
	var r model.BodyRewrite
	direction, rest, ok := word(text, false)
	if !ok {
		return r, badRewrite("invalid body rewrite syntax")
	}
	jq := strings.HasSuffix(strings.ToLower(direction), "-jq")
	phase, ok := rewritePhase(strings.TrimSuffix(strings.ToLower(direction), "-jq"))
	if !ok {
		return r, badRewrite("unknown body rewrite direction")
	}
	match, args, ok := word(rest, false)
	if !ok {
		return r, badRewrite("body rewrite requires a URL pattern")
	}
	return parseBodyRewriteParts(phase, match, args, jq)
}

func parseBodyRewriteParts(phase, match, args string, jq bool) (model.BodyRewrite, outcome) {
	args = strings.TrimSpace(args)
	if jq {
		filter := args
		if filter != "" && (filter[0] == '\'' || filter[0] == '"') {
			var tail string
			var ok bool
			filter, tail, ok = quoted(filter)
			if !ok || strings.TrimSpace(tail) != "" {
				return model.BodyRewrite{}, badRewrite("invalid quoted jq filter")
			}
		}
		return parseBodyRewriteJQ(phase, match, filter)
	}
	pairs, ok := words(args, false)
	if !ok {
		return model.BodyRewrite{}, badRewrite("body rewrite requires pattern and replacement pairs")
	}
	return parseBodyRewritePairs(phase, match, pairs)
}

func parseBodyRewriteJQ(phase, match, filter string) (model.BodyRewrite, outcome) {
	r := model.BodyRewrite{Match: match, Phase: phase}
	if issue := validateMatch(match); issue.skips() {
		return r, issue
	}
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(filter)), "jq-path=") {
		return r, unsupported("module.jq-path", "modules cannot load jq filters from files")
	}
	r.JQ = ptr(filter)
	_, err := httprewrite.New(httprewrite.Spec{BodyRewrites: []httprewrite.BodyRewrite{{
		Phase: phase, Match: match, JQ: r.JQ,
	}}}, httprewrite.Options{})
	if err != nil {
		return r, unsupported("module.jq-filter", "invalid or unsupported jq filter")
	}
	return r, outcome{}
}

func parseBodyRewritePairs(phase, match string, pairs []string) (model.BodyRewrite, outcome) {
	r := model.BodyRewrite{Match: match, Phase: phase}
	if issue := validateMatch(match); issue.skips() {
		return r, issue
	}
	if len(pairs) == 0 || len(pairs)%2 != 0 {
		return r, badRewrite("body rewrite requires pattern and replacement pairs")
	}
	for i := 0; i < len(pairs); i += 2 {
		if _, err := regexp.Compile(pairs[i]); err != nil {
			return r, incompatibleRegexp()
		}
		r.Replace = append(r.Replace, model.BodyReplacement{Pattern: ptr(pairs[i]), Value: ptr(pairs[i+1])})
	}
	return r, outcome{}
}

func rewritePhase(value string) (string, bool) {
	switch strings.ToLower(value) {
	case "http-request":
		return "request", true
	case "http-response":
		return "response", true
	default:
		return "", false
	}
}

func validateMatch(pattern string) outcome {
	if pattern == "" {
		return badRewrite("missing URL pattern")
	}
	if _, err := regexp.Compile(pattern); err != nil {
		return incompatibleRegexp()
	}
	return outcome{}
}

func incompatibleRegexp() outcome {
	return unsupported("module.regexp", "regular expression is incompatible with RE2")
}

func badRewrite(message string) outcome { return unsupported("module.rewrite-syntax", message) }
