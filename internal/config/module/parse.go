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

// Inspect returns metadata and deduplicated remote Map Local references after
// argument substitution, without resolving rule targets or acquiring resources.
func Inspect(text []byte, arguments map[string]string) (Metadata, []string) {
	var urls []string
	seen := make(map[string]bool)
	metadata, _ := scan(text, arguments, func(_ int, section, _, expanded string, issue outcome) {
		if section != "map local" || issue.skips() || isSection(expanded) {
			return
		}
		_, url, issue := parseMapLocal(expanded)
		if !issue.skips() && url != "" && !seen[url] {
			seen[url] = true
			urls = append(urls, url)
		}
	})
	return metadata, urls
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

	line, section, inHeader := 0, "", true
	remaining := model.MaxDocumentSize
	for raw := range strings.Lines(input) {
		line++
		raw = strings.TrimRight(raw, "\r\n")
		trimmed := strings.TrimSpace(raw)
		if inHeader && strings.HasPrefix(trimmed, "#!") {
			issue := metadata.apply(trimmed, values, &remaining)
			visit(line, "metadata", raw, trimmed, issue)
			if issue.status == Error {
				break
			}
			continue
		}
		if isComment(trimmed) {
			continue
		}
		expanded, issue := substitute(trimmed, values, &remaining)
		if issue.skips() {
			visit(line, section, raw, expanded, issue)
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
			visit(line, section, raw, replaced, outcome{})
		}
	}
	return metadata, diagnostics
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
	case "name", "desc", "system", "category", "icon":
	default:
		// Authors, links, dates and app-specific keys do not affect behavior,
		// so they do not make the import partial.
		return outcome{Supported, "module.metadata", "metadata is informational only"}
	}
	value, issue := substitute(value, values, remaining)
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
		value, rest, ok = quoted(s)
		return value, rest, ok && (rest == "" || startsSpace(rest))
	}
	for i, r := range s {
		if unicode.IsSpace(r) {
			return s[:i], s[i:], true
		}
		if assignment && r == '=' && i+1 < len(s) && (s[i+1] == '"' || s[i+1] == '\'') {
			value, rest, ok = quoted(s[i+1:])
			return s[:i+1] + value, rest, ok && (rest == "" || startsSpace(rest))
		}
		if r == '=' {
			assignment = false
		}
	}
	return s, "", true
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
