package module

import (
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"

	"github.com/MimoProxy/reka/internal/config/model"
)

type loonArguments struct {
	declared map[string]Argument
	supplied map[string]string
}

type loonLine struct {
	number        int
	section       string
	raw           string
	text          string
	issue         outcome
	script        bool
	rewrite       bool
	scriptSpec    model.Script
	scriptRef     ScriptReference
	urlRewrite    *model.HTTPRewrite
	headerRewrite *model.HeaderRewrite
	bodyRewrite   *model.BodyRewrite
	mapLocal      *model.MapLocal
	mapRef        ResourceReference
}

func (c *converter) convertLoon(text []byte) (Metadata, model.Diagnostics) {
	return scanLoon(text, c.opts.Arguments, func(row loonLine, args loonArguments) {
		issue := row.issue
		if row.script {
			if issue.status == "" {
				issue = c.addScript(row.number, row.scriptSpec, row.scriptRef)
			}
			c.report.Scripts.record(issue.status == "")
		} else if row.rewrite {
			if issue.status == "" {
				switch {
				case row.urlRewrite != nil:
					c.addURLRewrite(row.number, *row.urlRewrite)
				case row.headerRewrite != nil:
					c.addHeaderRewrite(row.number, *row.headerRewrite)
				case row.bodyRewrite != nil:
					c.addBodyRewrite(row.number, *row.bodyRewrite)
				case row.mapLocal != nil:
					issue = c.addMapLocal(row.number, *row.mapLocal, row.mapRef.URL)
				}
			}
			c.report.Rewrites.record(issue.status == "")
		} else if row.section == "rule" && issue.skips() {
			c.report.Rules.record(false)
		} else if issue.status == "" && row.section != "argument" && row.section != "metadata" && !isSection(row.text) {
			switch row.section {
			case "rule":
				rule, ruleIssue := convertRuleWithTarget(row.raw, row.text, func(policy string) (string, bool, string) {
					if strings.EqualFold(policy, "PROXY") {
						if value, ok := args.supplied["PROXY"]; ok {
							policy = value
						} else if argument, ok := args.declared["PROXY"]; ok {
							policy = argument.Value
						} else {
							policy = "PROXY"
						}
					}
					switch strings.ToUpper(policy) {
					case "REJECT-DICT", "REJECT-IMG", "REJECT-ARRAY", "REJECT-200":
						return "reject", true, ""
					}
					return ruleTarget(policy, c.opts.Resolve)
				})
				issue = c.addRule(row.number, rule, ruleIssue)
			case "mitm":
				key, _, ok := strings.Cut(row.text, "=")
				if ok && !strings.EqualFold(strings.TrimSpace(key), "hostname") {
					issue = ignored("module.mitm-setting", "only MITM hostnames are imported from Loon plugins")
				} else {
					issue = c.mitm(row.number, row.text)
				}
			case "remote rule", "remote filter":
				issue = ignored("module.rule-set", "modules cannot define remote rule sets")
			default:
				issue = c.convertLine(row.number, row.section, row.raw, row.text)
			}
		}
		c.report.record(row.number, row.section, issue)
	})
}

func inspectLoon(text []byte, supplied map[string]string, interval int) (Metadata, ResourceReferences) {
	collector := newReferenceCollector(interval)
	metadata, _ := scanLoon(text, supplied, func(row loonLine, _ loonArguments) {
		if row.issue.status != "" {
			return
		}
		if row.script {
			collector.script(row.scriptRef)
		}
		collector.mapLocal(row.mapRef)
		if row.section == "rule" {
			collector.ruleSet(row.text)
		}
	})
	return metadata, collector.refs
}

func scanLoon(text []byte, supplied map[string]string, visit func(loonLine, loonArguments)) (Metadata, model.Diagnostics) {
	input := strings.TrimPrefix(string(text), "\ufeff")
	args := loonArguments{declared: make(map[string]Argument), supplied: supplied}
	var metadata Metadata
	var diagnostics model.Diagnostics
	declarations := make(map[int]outcome)
	line, section := 0, ""
	for raw := range strings.Lines(input) {
		line++
		text := strings.TrimSpace(raw)
		if isComment(text) {
			continue
		}
		if isSection(text) {
			section = strings.ToLower(strings.TrimSpace(text[1 : len(text)-1]))
			continue
		}
		if section != "argument" {
			continue
		}
		argument, issue := parseLoonArgument(text)
		if _, exists := args.declared[argument.Name]; issue.status == "" && exists {
			issue = unsupported("module.arguments", "duplicate Loon argument declaration")
		}
		declarations[line] = issue
		if issue.skips() {
			continue
		}
		if value, ok := supplied[argument.Name]; ok {
			argument.Value = value
			if len(argument.Options) != 0 && !slices.Contains(argument.Options, value) {
				diagnostics = append(diagnostics, model.Diagnostic{
					Severity: model.SeverityWarning, Code: "module.argument-option",
					Message:  fmt.Sprintf("argument %q does not match a declared option", argument.Name),
					Document: model.DocSources, Line: line, Column: 1,
				})
			}
		}
		metadata.Arguments = append(metadata.Arguments, argument)
		args.declared[argument.Name] = argument
	}
	for _, key := range slices.Sorted(maps.Keys(supplied)) {
		if _, ok := args.declared[key]; !ok && key != "PROXY" {
			diagnostics = append(diagnostics, model.Diagnostic{
				Severity: model.SeverityWarning, Code: "module.unknown-argument",
				Message: fmt.Sprintf("argument %q is not declared by the module", key),
			})
		}
	}
	walkModuleLines(input, func(text string, remaining *int) outcome {
		key, value, ok := metadataLine(text)
		if !ok {
			return outcome{Supported, "module.metadata", "comment without a metadata value"}
		}
		return metadata.applyInfo(key, value, func(value string) (string, outcome) {
			return args.expand(value, remaining)
		})
	}, func(section, text string, remaining *int) (string, outcome) {
		if isSection(text) || section == "argument" || section == "script" || isLoonRewriteSection(section) && isLoonExpression(text) {
			// Script arguments and expressions are parsed before substitution to
			// preserve argument object keys and the expression grammar.
			if len(text) > *remaining {
				return "", loonExpansionLimit(remaining)
			}
			*remaining -= len(text)
			return text, outcome{}
		}
		return args.expand(text, remaining)
	}, func(line int, section, raw, expanded string, issue outcome, remaining *int) {
		row := loonLine{number: line, section: section, raw: raw, text: expanded, issue: issue}
		if section != "metadata" && !isSection(strings.TrimSpace(raw)) {
			row.script = section == "script"
			row.rewrite = isLoonRewriteSection(section) || section == "map local"
			if !issue.skips() && !isSection(expanded) {
				switch {
				case section == "argument":
					row.issue = declarations[line]
				case (row.script || row.rewrite && section != "map local") && isLoonExpression(expanded):
					row.parseExpression(args, remaining)
				case row.script:
					row.scriptSpec, row.scriptRef, row.issue = parseLoonScript(expanded, args, remaining)
				case section == "map local":
					result, ref, issue := parseMapLocal(expanded)
					row.mapLocal, row.mapRef, row.issue = &result, ref, issue
				case row.rewrite:
					row.parseRewrite()
				}
			} else if isSection(expanded) {
				row.script, row.rewrite = false, false
			}
		}
		visit(row, args)
	})
	return metadata, diagnostics
}

func isLoonRewriteSection(section string) bool {
	switch section {
	case "rewrite", "url rewrite", "header rewrite", "body rewrite":
		return true
	default:
		return false
	}
}

var loonArgumentName = regexp.MustCompile(`^[\p{L}_][\p{L}\p{N}_]*$`)
var loonReference = regexp.MustCompile(`\{\{\{([^{}\r\n]*)\}\}\}|\$\{([\p{L}_][\p{L}\p{N}_]*)\}|\{([\p{L}_][\p{L}\p{N}_]*)\}`)

func parseLoonArgument(text string) (Argument, outcome) {
	badArgument := unsupported("module.arguments", "invalid Loon argument declaration")
	name, list, ok := strings.Cut(text, "=")
	name = strings.TrimSpace(name)
	if !ok || !loonArgumentName.MatchString(name) {
		return Argument{}, badArgument
	}
	fields, ok := splitLoonList(list, false)
	if !ok || len(fields) == 0 {
		return Argument{}, badArgument
	}
	arg := Argument{Name: name}
	var values []string
	settings := make(map[string]bool)
	// An unquoted description that ends the line may contain commas.
	for i := 1; i < len(fields)-1; i++ {
		key, value, ok := strings.Cut(fields[i], "=")
		if ok && strings.EqualFold(strings.TrimSpace(key), "desc") && !strings.HasPrefix(strings.TrimSpace(value), `"`) {
			if rest := fields[i+1:]; !slices.ContainsFunc(rest, isLoonSetting) {
				fields = append(fields[:i:i], strings.Join(fields[i:], ","))
			}
			break
		}
	}
	for _, field := range fields[1:] {
		key, value, assignment := strings.Cut(field, "=")
		key = strings.ToLower(strings.TrimSpace(key))
		if assignment && (key == "tag" || key == "desc" || key == "type") {
			if settings[key] {
				return Argument{}, badArgument
			}
			settings[key] = true
			value, ok = loonValue(value)
			if !ok {
				return Argument{}, badArgument
			}
			if key == "desc" {
				arg.Description = value
			}
			continue
		}
		value, ok = loonValue(field)
		if !ok {
			return Argument{}, badArgument
		}
		values = append(values, value)
	}
	switch strings.ToLower(fields[0]) {
	case "input":
		if len(values) > 1 {
			return Argument{}, badArgument
		}
	case "select":
		if len(values) == 0 {
			return Argument{}, badArgument
		}
		arg.Options = values
	case "switch":
		if len(values) == 0 {
			return Argument{}, badArgument
		}
		for i, value := range values {
			values[i] = strings.ToLower(value)
			if values[i] != "true" && values[i] != "false" {
				return Argument{}, badArgument
			}
		}
		arg.Type = "switch"
	default:
		return Argument{}, badArgument
	}
	if len(values) != 0 {
		arg.Default, arg.Value = values[0], values[0]
	}
	return arg, outcome{}
}

func isLoonSetting(field string) bool {
	key, _, ok := strings.Cut(field, "=")
	key = strings.ToLower(strings.TrimSpace(key))
	return ok && (key == "tag" || key == "desc" || key == "type")
}

func loonValue(text string) (string, bool) {
	text = strings.TrimSpace(text)
	if text != "" && (text[0] == '"' || text[0] == '\'') {
		value, tail, ok := quoted(text)
		return value, ok && strings.TrimSpace(tail) == ""
	}
	return text, true
}

func (a loonArguments) expand(text string, remaining *int) (string, outcome) {
	if !strings.Contains(text, "{") {
		return substitute(text, nil, remaining)
	}
	var expanded strings.Builder
	for {
		indices := loonReference.FindStringSubmatchIndex(text)
		if indices == nil {
			break
		}
		start, end := indices[0], indices[1]
		value := text[start:end]
		if indices[2] >= 0 {
			name := strings.TrimSpace(text[indices[2]:indices[3]])
			var ok bool
			if value, ok = a.supplied[name]; !ok {
				argument, declared := a.declared[name]
				if !declared {
					return "", unsupported("module.undefined-argument", "undefined module argument")
				}
				value = argument.Value
			}
		} else {
			nameStart, nameEnd := indices[4], indices[5]
			if nameStart < 0 {
				nameStart, nameEnd = indices[6], indices[7]
			}
			if argument, declared := a.declared[text[nameStart:nameEnd]]; declared {
				value = argument.Value
			}
		}
		if start+len(value) > *remaining-expanded.Len() {
			return "", loonExpansionLimit(remaining)
		}
		expanded.WriteString(text[:start])
		expanded.WriteString(value)
		text = text[end:]
	}
	if len(text) > *remaining-expanded.Len() {
		return "", loonExpansionLimit(remaining)
	}
	expanded.WriteString(text)
	*remaining -= expanded.Len()
	return expanded.String(), outcome{}
}

// expandDeferred charges only the growth because the scanner already counted
// the original script or expression line.
func (a loonArguments) expandDeferred(text string, remaining *int) (string, outcome) {
	budget := *remaining + len(text)
	expanded, issue := a.expand(text, &budget)
	if issue.status == "" {
		*remaining = budget
	} else if issue.status == Error {
		*remaining = -1
	}
	return expanded, issue
}

func loonExpansionLimit(remaining *int) outcome {
	*remaining = -1
	return failed("module.arguments-size", "expanded module exceeds the document size limit")
}
