package module

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/MimoProxy/reka/internal/config/model"
	"github.com/MimoProxy/reka/internal/router"
)

func convertRule(raw, line string, resolve func(string) (string, bool)) (model.Rule, outcome) {
	return convertRuleWithTarget(raw, line, func(policy string) (string, bool, string) {
		return ruleTarget(policy, resolve)
	})
}

func convertRuleWithTarget(raw, line string, targetFor func(string) (string, bool, string)) (model.Rule, outcome) {
	var rule model.Rule
	kind, payload, ok := strings.Cut(line, ",")
	kind = strings.ToUpper(strings.TrimSpace(kind))
	if kind == "FINAL" || kind == "MATCH" {
		return rule, unsupported("module.final-rule", "modules cannot define the final rule")
	}
	if !ok {
		return rule, badRule()
	}
	var args []string
	if regexRule(kind) {
		// Regex values may contain commas, including commas inside quantifiers.
		var modifiers []string
		for {
			at := strings.LastIndexByte(payload, ',')
			if at < 0 {
				return rule, badRule()
			}
			last := strings.TrimSpace(payload[at+1:])
			if last != "no-resolve" && last != "extended-matching" && last != "pre-matching" {
				args = append([]string{strings.TrimSpace(payload[:at]), last}, modifiers...)
				break
			}
			modifiers = append(modifiers, last)
			payload = payload[:at]
		}
	} else {
		var err error
		args, err = router.SplitClash(payload)
		if err != nil || len(args) < 2 {
			return rule, badRule()
		}
		// A substituted policy may use commas when it is quoted in the rule.
		if rest := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(payload), args[0])); strings.HasPrefix(rest, ",") {
			rest = strings.TrimSpace(rest[1:])
			if strings.HasPrefix(rest, `"`) {
				policy, tail, ok := quoted(rest)
				tail = strings.TrimSpace(tail)
				if !ok || tail != "" && tail[0] != ',' {
					return rule, badRule()
				}
				args = []string{args[0], policy}
				if tail != "" {
					args = append(args, strings.Split(tail[1:], ",")...)
				}
			}
		}
	}
	match, issue := ruleCondition(kind, args[0], args[2:], 0)
	if issue.skips() {
		return rule, issue
	}
	target, approximate, failure := targetFor(args[1])
	if failure != "" {
		return rule, failed("module.rule-policy", failure)
	}
	if approximate {
		const message = "policy approximated by native reject"
		switch {
		case issue.status == Ignored:
			issue.message += ". " + message
		case issue.message != "":
			issue.code, issue.message = "module.policy-approximate", issue.message+". "+message
		default:
			issue = outcome{Supported, "module.policy-approximate", message}
		}
	}
	return model.Rule{Match: match, Outbound: target, Syntax: raw}, issue
}

func ruleCondition(kind, value string, modifiers []string, depth int) (model.Match, outcome) {
	var m model.Match
	if value == "" || depth > 32 {
		return m, badRule()
	}
	noResolve, ignoredModifier := false, false
	var notes []string
	for _, modifier := range modifiers {
		switch strings.ToLower(strings.TrimSpace(modifier)) {
		case "no-resolve":
			noResolve = true
		case "pre-matching", "":
			// Pre-matching only lets Surge apply a reject rule earlier; the
			// result of matching is the same.
		case "extended-matching":
			// Surge also matches the sniffed SNI or Host. The kernel already
			// routes connections to bare IPs by the sniffed name, so only a
			// connection whose own domain differs from its SNI matches
			// differently.
			notes = appendNote(notes, extendedMatchingNote)
		default:
			ignoredModifier = true
		}
	}
	if regexRule(kind) {
		if _, err := regexp.Compile(value); err != nil {
			return m, incompatibleRegexp()
		}
	}
	switch kind {
	case "AND", "OR", "NOT":
		if len(value) < 2 || value[0] != '(' || value[len(value)-1] != ')' {
			return m, badRule()
		}
		operands, err := router.SplitClash(value[1 : len(value)-1])
		if err != nil || kind == "NOT" && len(operands) != 1 {
			return m, badRule()
		}
		m.Kind = strings.ToLower(kind)
		for _, operand := range operands {
			if len(operand) < 2 || operand[0] != '(' || operand[len(operand)-1] != ')' {
				return m, badRule()
			}
			childKind, payload, ok := strings.Cut(operand[1:len(operand)-1], ",")
			if !ok {
				return m, badRule()
			}
			childKind = strings.ToUpper(strings.TrimSpace(childKind))
			var childModifiers []string
			if !regexRule(childKind) {
				fields, err := router.SplitClash(payload)
				if err != nil {
					return m, badRule()
				}
				payload, childModifiers = fields[0], fields[1:]
			}
			child, result := ruleCondition(childKind, strings.TrimSpace(payload), childModifiers, depth+1)
			if result.skips() {
				return m, result
			}
			ignoredModifier = ignoredModifier || result.status == Ignored
			for _, note := range result.notes() {
				notes = appendNote(notes, note)
			}
			m.Children = append(m.Children, child)
		}
	case "DOMAIN-WILDCARD":
		pattern, ok := domainWildcard(value)
		if !ok {
			return m, badRule()
		}
		m = model.Match{Kind: "domain-regex", Values: []string{pattern}}
	case "RULE-SET", "DOMAIN-SET":
		if strings.Contains(value, ":") || strings.HasPrefix(value, "/") {
			return m, unsupported("module.rule-resource", "modules cannot obtain rule sets from URLs or files")
		}
		m = model.Match{Kind: "rule-set", Values: []string{value}}
	case "PROTOCOL":
		switch strings.ToUpper(value) {
		case "TCP", "UDP":
			m = model.Match{Kind: "network", Values: []string{strings.ToLower(value)}}
		case "QUIC":
			// The kernel treats UDP port 443 as QUIC, as routing.block-quic does.
			m = model.Match{Kind: "and", Children: []model.Match{
				{Kind: "network", Values: []string{"udp"}},
				{Kind: "dst-port", Values: []string{"443"}},
			}}
			notes = appendNote(notes, quicProtocolNote)
		default:
			return m, unsupported("module.rule-condition", "invalid or unsupported rule condition")
		}
	case "FINAL", "MATCH", "SUB-RULE":
		return m, unsupported("module.rule-condition", "this condition cannot be used in a module rule")
	default:
		switch kind {
		case "SRC-IP":
			kind = "SRC-IP-CIDR"
		case "DEST-PORT":
			kind = "DST-PORT"
		}
		spec, err := router.ParseClashCondition(kind + "," + value)
		if err != nil {
			return m, unsupported("module.rule-condition", "invalid or unsupported rule condition")
		}
		m = model.Match{Kind: spec.Kind.String(), Values: spec.Values}
		switch kind {
		case "GEOIP", "GEOSITE":
			m.Kind, m.Values = strings.ToLower(kind), []string{strings.ToUpper(value)}
			if kind == "GEOSITE" {
				m.Values[0] = strings.ToLower(value)
			}
		case "IP-ASN":
			asn, err := strconv.ParseUint(strings.TrimPrefix(strings.ToUpper(value), "AS"), 10, 32)
			if err != nil {
				return m, badRule()
			}
			m.Kind, m.Values = "ip-asn", []string{strconv.FormatUint(asn, 10)}
		case "DOMAIN", "DOMAIN-SUFFIX":
			m.Values = []string{router.NormalizeDomain(strings.TrimPrefix(value, "."))}
		case "DOMAIN-KEYWORD":
			m.Values = []string{strings.ToLower(value)}
		}
	}
	if noResolve && !applyNoResolve(&m) {
		ignoredModifier = true
	}
	if ignoredModifier {
		issue := ignored("module.rule-modifier", "one or more rule modifiers were ignored")
		for _, note := range notes {
			issue.message += ". " + note
		}
		return m, issue
	}
	if len(notes) != 0 {
		return m, outcome{Supported, "module.rule-approximate", strings.Join(notes, ". ")}
	}
	return m, outcome{}
}

const (
	extendedMatchingNote = "extended-matching uses the sniffed name only for connections without a domain"
	quicProtocolNote     = "PROTOCOL,QUIC approximated by UDP port 443"
)

func appendNote(notes []string, note string) []string {
	for _, existing := range notes {
		if existing == note {
			return notes
		}
	}
	return append(notes, note)
}

// notes returns the approximation notes carried by a nested condition.
func (o outcome) notes() []string {
	var notes []string
	for _, note := range []string{extendedMatchingNote, quicProtocolNote} {
		if strings.Contains(o.message, note) {
			notes = append(notes, note)
		}
	}
	return notes
}

// Surge wildcards span labels and accept bracket classes, so the native
// label-based domain-pattern condition would change which hosts match.
func domainWildcard(pattern string) (string, bool) {
	pattern = strings.ToLower(strings.TrimSuffix(pattern, "."))
	var expression strings.Builder
	expression.WriteByte('^')
	for pattern != "" {
		at := strings.IndexAny(pattern, "*?[")
		if at < 0 {
			expression.WriteString(regexp.QuoteMeta(pattern))
			break
		}
		expression.WriteString(regexp.QuoteMeta(pattern[:at]))
		switch pattern[at] {
		case '*':
			expression.WriteString(".*")
		case '?':
			expression.WriteByte('.')
		case '[':
			class, _, ok := strings.Cut(pattern[at+1:], "]")
			if !ok || class == "" {
				return "", false
			}
			expression.WriteByte('[')
			if negative, ok := strings.CutPrefix(class, "!"); ok {
				expression.WriteByte('^')
				expression.WriteString(negative)
			} else {
				expression.WriteString(class)
			}
			expression.WriteByte(']')
			at += len(class) + 1
		}
		pattern = pattern[at+1:]
	}
	expression.WriteByte('$')
	result := expression.String()
	_, err := regexp.Compile(result)
	return result, err == nil
}

func applyNoResolve(m *model.Match) bool {
	switch m.Kind {
	case "ip-cidr", "src-ip-cidr", "rule-set", "geoip", "ip-asn", "geosite":
		m.NoResolve = true
		return true
	}
	applied := false
	for i := range m.Children {
		if applyNoResolve(&m.Children[i]) {
			applied = true
		}
	}
	return applied
}

func ruleTarget(policy string, resolve func(string) (string, bool)) (string, bool, string) {
	switch strings.ToUpper(policy) {
	case "DIRECT", "REJECT", "REJECT-DROP":
		return strings.ToLower(policy), false, ""
	case "REJECT-NO-DROP", "REJECT-TINYGIF":
		return "reject", true, ""
	}
	if resolve != nil && policy != "" {
		if id, ok := resolve(policy); ok && id != "" {
			return id, false, ""
		} else if !ok && id != "" {
			return "", false, id
		}
	}
	return "", false, "module rule policy was not found in the effective configuration"
}

func regexRule(kind string) bool {
	return kind == "DOMAIN-REGEX" || kind == "PROCESS-NAME-REGEX" || kind == "PROCESS-PATH-REGEX"
}

func badRule() outcome { return unsupported("module.rule-syntax", "invalid module rule syntax") }
