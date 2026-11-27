package module

import (
	"fmt"
	"maps"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/MimoProxy/reka/internal/config/model"
)

type ResourceReferences struct {
	MapLocal []ResourceReference
	Scripts  []ScriptReference
	RuleSets []RuleSetReference
}

// ResourceReference identifies a remote resource and its refresh interval in
// seconds. A zero interval uses the module's interval.
type ResourceReference struct {
	URL      string
	Interval int
}

// RuleSetReference is a remote RULE-SET or DOMAIN-SET list. Kind is the
// resource lock kind, RuleSetKind or DomainSetKind.
type RuleSetReference struct {
	Kind string
	ResourceReference
}

// Resource lock kinds for remote rule lists in modules.
const (
	RuleSetKind   = "rule-set"
	DomainSetKind = "domain-set"
)

// Inspect returns metadata and deduplicated remote references after argument
// substitution. It uses the optional module interval for scripts that inherit
// it, falling back to the default resource interval.
func Inspect(text []byte, arguments map[string]string, moduleInterval ...int) (Metadata, ResourceReferences) {
	interval := model.DefaultResourceInterval
	if len(moduleInterval) > 0 && moduleInterval[0] > 0 {
		interval = moduleInterval[0]
	}
	collector := newReferenceCollector(interval)
	metadata, _ := scan(text, arguments, func(_ int, section, _, expanded string, issue outcome) {
		if issue.skips() || isSection(expanded) {
			return
		}
		switch section {
		case "map local":
			_, ref, issue := parseMapLocal(expanded)
			if !issue.skips() {
				collector.mapLocal(ref)
			}
		case "rule":
			collector.ruleSet(expanded)
		case "script":
			_, ref, issue := parseScript(expanded)
			if !issue.skips() {
				collector.script(ref)
			}
		}
	})
	return metadata, collector.refs
}

type referenceCollector struct {
	refs            ResourceReferences
	mapLocalIndices map[string]int
	scriptIndices   map[string]int
	ruleSetIndices  map[RuleSetReference]int
	interval        int
}

func newReferenceCollector(interval int) *referenceCollector {
	if interval <= 0 {
		interval = model.DefaultResourceInterval
	}
	return &referenceCollector{
		mapLocalIndices: make(map[string]int), scriptIndices: make(map[string]int),
		ruleSetIndices: make(map[RuleSetReference]int), interval: interval,
	}
}

// Surge uses the first Map Local interval for a URL; scripts and rule sets
// take the shortest so every declaration is refreshed at least as often as it
// asks.
func (c *referenceCollector) mapLocal(ref ResourceReference) {
	if ref.URL == "" {
		return
	}
	if _, seen := c.mapLocalIndices[ref.URL]; !seen {
		c.mapLocalIndices[ref.URL] = len(c.refs.MapLocal)
		c.refs.MapLocal = append(c.refs.MapLocal, c.withInterval(ref))
	}
}

func (c *referenceCollector) script(ref ScriptReference) {
	ref = c.withInterval(ref)
	if i, seen := c.scriptIndices[ref.URL]; seen {
		c.refs.Scripts[i].Interval = min(c.refs.Scripts[i].Interval, ref.Interval)
		return
	}
	c.scriptIndices[ref.URL] = len(c.refs.Scripts)
	c.refs.Scripts = append(c.refs.Scripts, ref)
}

// ruleSet records the remote list named by a module rule line, if any.
func (c *referenceCollector) ruleSet(line string) {
	ref, ok := remoteRuleSet(line)
	if !ok {
		return
	}
	ref.ResourceReference = c.withInterval(ref.ResourceReference)
	key := RuleSetReference{Kind: ref.Kind, ResourceReference: ResourceReference{URL: ref.URL}}
	if i, seen := c.ruleSetIndices[key]; seen {
		c.refs.RuleSets[i].Interval = min(c.refs.RuleSets[i].Interval, ref.Interval)
		return
	}
	c.ruleSetIndices[key] = len(c.refs.RuleSets)
	c.refs.RuleSets = append(c.refs.RuleSets, ref)
}

func (c *referenceCollector) withInterval(ref ResourceReference) ResourceReference {
	if ref.Interval == 0 {
		ref.Interval = c.interval
	}
	return ref
}

func scan(text []byte, supplied map[string]string, visit func(int, string, string, string, outcome)) (Metadata, model.Diagnostics) {
	input := strings.TrimPrefix(string(text), "\ufeff")
	var metadata Metadata
	defaults := make(map[string]string)
	var keys []string
	var descriptions map[string]string
	for raw := range strings.Lines(input) {
		line := strings.TrimSpace(raw)
		if !isComment(line) {
			break
		}
		key, value, _ := metadataLine(line)
		switch key {
		case "arguments":
			if values, order, ok := parseArguments(value); ok {
				for _, name := range order {
					if _, exists := defaults[name]; !exists {
						keys = append(keys, name)
					}
					defaults[name] = values[name]
				}
			}
		case "arguments-desc":
			metadata.ArgumentsDesc = value
			descriptions, _, _ = parseArguments(value)
		}
	}

	values := maps.Clone(defaults)
	maps.Copy(values, supplied)
	for _, name := range keys {
		metadata.Arguments = append(metadata.Arguments, Argument{
			Name: name, Default: defaults[name], Value: values[name], Description: descriptions[name],
		})
	}
	var diagnostics model.Diagnostics
	for _, key := range slices.Sorted(maps.Keys(supplied)) {
		if _, ok := defaults[key]; !ok {
			diagnostics = append(diagnostics, model.Diagnostic{
				Severity: model.SeverityWarning, Code: "module.unknown-argument",
				Message: fmt.Sprintf("argument %q is not declared by the module", key),
			})
		}
	}

	walkModuleLines(input, func(text string, remaining *int) outcome {
		return metadata.apply(text, values, remaining)
	}, func(_ string, text string, remaining *int) (string, outcome) {
		return substitute(text, values, remaining)
	}, func(line int, section, raw, expanded string, issue outcome, _ *int) {
		visit(line, section, raw, expanded, issue)
	})
	return metadata, diagnostics
}

func walkModuleLines(
	input string,
	applyMetadata func(string, *int) outcome,
	expandLine func(string, string, *int) (string, outcome),
	visit func(int, string, string, string, outcome, *int),
) {
	line, section, inHeader := 0, "", true
	remaining := model.MaxDocumentSize
	for raw := range strings.Lines(input) {
		line++
		raw = strings.TrimRight(raw, "\r\n")
		trimmed := strings.TrimSpace(raw)
		if inHeader && strings.HasPrefix(trimmed, "#!") {
			issue := applyMetadata(trimmed, &remaining)
			visit(line, "metadata", raw, trimmed, issue, &remaining)
			if issue.status == Error {
				break
			}
			continue
		}
		if isComment(trimmed) {
			continue
		}
		expanded, issue := expandLine(section, trimmed, &remaining)
		if issue.skips() {
			visit(line, section, raw, expanded, issue, &remaining)
			if issue.status == Error {
				break
			}
			continue
		}
		for replaced := range strings.SplitSeq(expanded, "\n") {
			replaced = strings.TrimSpace(replaced)
			if isComment(replaced) {
				continue
			}
			inHeader = false
			if isSection(replaced) {
				section = strings.ToLower(strings.TrimSpace(replaced[1 : len(replaced)-1]))
			}
			visit(line, section, raw, replaced, outcome{}, &remaining)
			if remaining < 0 {
				return
			}
		}
	}
}

func (m *Metadata) apply(text string, values map[string]string, remaining *int) outcome {
	key, value, ok := metadataLine(text)
	if !ok {
		return outcome{Supported, "module.metadata", "comment without a metadata value"}
	}
	switch key {
	case "arguments":
		if _, _, ok := parseArguments(value); !ok {
			return unsupported("module.arguments", "invalid default argument list")
		}
		return outcome{}
	case "arguments-desc":
		return outcome{}
	case "requirement":
		return ignored("module.requirement", "module requirements are ignored")
	}
	return m.applyInfo(key, value, func(value string) (string, outcome) {
		return substitute(value, values, remaining)
	})
}

func (m *Metadata) applyInfo(key, value string, expand func(string) (string, outcome)) outcome {
	switch key {
	case "name", "desc", "system", "category", "icon":
	default:
		// Authors, links, dates and app-specific keys do not affect behavior,
		// so they do not make the import partial.
		return outcome{Supported, "module.metadata", "metadata is informational only"}
	}
	value, issue := expand(value)
	if issue.skips() {
		return issue
	}
	switch key {
	case "name":
		m.Name = value
	case "desc":
		m.Desc = value
	case "system":
		m.System = value
	case "category":
		m.Category = value
	case "icon":
		m.Icon = value
	}
	return outcome{}
}

func metadataLine(line string) (key, value string, ok bool) {
	line, marked := strings.CutPrefix(line, "#!")
	if !marked {
		return "", "", false
	}
	key, value, ok = strings.Cut(line, "=")
	key = strings.ToLower(strings.TrimSpace(key))
	return key, strings.TrimSpace(value), ok && key != ""
}

func isSection(line string) bool {
	return len(line) > 2 && line[0] == '[' && line[len(line)-1] == ']'
}

func isComment(line string) bool {
	return line == "" || line[0] == '#' || line[0] == ';' || strings.HasPrefix(line, "//")
}

func parseArguments(s string) (map[string]string, []string, bool) {
	values := make(map[string]string)
	var names []string
	for s = strings.TrimSpace(s); s != ""; s = strings.TrimSpace(s) {
		separator := strings.IndexAny(s, ":,")
		if separator < 0 || s[separator] != ':' {
			return nil, nil, false
		}
		name := strings.TrimSpace(s[:separator])
		if name == "" {
			return nil, nil, false
		}
		value := strings.TrimSpace(s[separator+1:])
		if strings.HasPrefix(value, `"`) {
			var ok bool
			value, s, ok = quoted(value)
			s = strings.TrimSpace(s)
			if !ok || s != "" && s[0] != ',' {
				return nil, nil, false
			}
			s = strings.TrimPrefix(s, ",")
		} else {
			value, s, _ = strings.Cut(value, ",")
			value = strings.TrimSpace(value)
		}
		if _, exists := values[name]; !exists {
			names = append(names, name)
		}
		values[name] = value
	}
	return values, names, true
}

func substitute(s string, values map[string]string, remaining *int) (string, outcome) {
	limit := failed("module.arguments-size", "expanded module exceeds the document size limit")
	var out strings.Builder
	if !strings.Contains(s, "{{{") {
		if len(s) > *remaining {
			return "", limit
		}
		*remaining -= len(s)
		return s, outcome{}
	}
	for {
		prefix, tail, open := strings.Cut(s, "{{{")
		name, rest, closed := strings.Cut(tail, "}}}")
		if !open || !closed {
			if len(s) > *remaining-out.Len() {
				return "", limit
			}
			out.WriteString(s)
			break
		}
		value, exists := values[strings.TrimSpace(name)]
		if !exists {
			*remaining -= out.Len()
			return "", unsupported("module.undefined-argument", "undefined module argument")
		}
		if len(prefix)+len(value) > *remaining-out.Len() {
			return "", limit
		}
		out.WriteString(prefix)
		out.WriteString(value)
		s = rest
	}
	expanded := out.String()
	*remaining -= len(expanded)
	_, rest, found := strings.Cut(expanded, "{{{")
	if found && strings.Contains(rest, "}}}") {
		return "", unsupported("module.undefined-argument", "undefined module argument")
	}
	return expanded, outcome{}
}

// quoted removes a wrapping quote and escapes of that same quote while
// preserving regular-expression and jq backslashes.
func quoted(s string) (value, rest string, ok bool) {
	quote := s[0]
	var out strings.Builder
	start := 1
	for i := 1; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			if s[i+1] == quote {
				out.WriteString(s[start:i])
				start = i + 1
			}
			i++
			continue
		}
		if s[i] == quote {
			out.WriteString(s[start:i])
			return out.String(), s[i+1:], true
		}
	}
	return "", "", false
}

func word(s string, assignment bool) (value, rest string, ok bool) {
	s = strings.TrimLeftFunc(s, unicode.IsSpace)
	if s == "" {
		return "", "", false
	}
	if s[0] == '"' || s[0] == '\'' {
		if value, rest, ok = quoted(s); ok && (rest == "" || startsSpace(rest)) {
			return value, rest, true
		}
		// Surge splits arguments on whitespace. A quote that does not
		// enclose the whole token is literal, as in a body rewrite pattern
		// such as "key":\{.+\}.
	}
	for i, r := range s {
		if unicode.IsSpace(r) {
			return s[:i], s[i:], true
		}
		if assignment && r == '=' && i+1 < len(s) && (s[i+1] == '"' || s[i+1] == '\'') {
			if value, rest, ok = quoted(s[i+1:]); ok && (rest == "" || startsSpace(rest)) {
				return s[:i+1] + value, rest, true
			}
			// Surge modules put unescaped quotes inside values such as
			// data="{"code":0}". The value then ends at the first matching
			// quote followed by whitespace or the end of the line.
			if end := closingQuote(s[i+1:]); end > 0 {
				return s[:i+1] + s[i+2:i+1+end], s[i+2+end:], true
			}
			return "", "", false
		}
		if r == '=' {
			assignment = false
		}
	}
	return s, "", true
}

// closingQuote returns the index of the first quote matching s[0] that is
// followed by whitespace or the end of s, or 0 when there is none.
func closingQuote(s string) int {
	for j := 1; j < len(s); j++ {
		if s[j] == s[0] && (j+1 == len(s) || startsSpace(s[j+1:])) {
			return j
		}
	}
	return 0
}

func startsSpace(s string) bool {
	first, _ := utf8.DecodeRuneInString(s)
	return unicode.IsSpace(first)
}

func words(s string, assignments bool) ([]string, bool) {
	var fields []string
	for s = strings.TrimSpace(s); s != ""; s = strings.TrimSpace(s) {
		field, rest, ok := word(s, assignments && len(fields) > 0)
		if !ok {
			return nil, false
		}
		fields = append(fields, field)
		s = rest
	}
	return fields, true
}
