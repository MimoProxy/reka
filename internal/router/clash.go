package router

import (
	"fmt"
	"strings"
)

// SplitClash respects nested logical operands. It does not interpret values.
func SplitClash(s string) ([]string, error) {
	depth, start := 0, 0
	escaped, characterClass := false, false
	var out []string
	for i, r := range s {
		if escaped {
			escaped = false
			continue
		}
		if r == '\\' {
			escaped = true
			continue
		}
		if r == '[' {
			characterClass = true
			continue
		}
		if r == ']' {
			characterClass = false
			continue
		}
		if characterClass {
			continue
		}
		switch r {
		case '(':
			depth++
			if depth > 32 {
				return nil, fmt.Errorf("condition nesting exceeds 32")
			}
		case ')':
			depth--
			if depth < 0 {
				return nil, fmt.Errorf("unbalanced parentheses")
			}
		case ',':
			if depth == 0 {
				out = append(out, strings.TrimSpace(s[start:i]))
				start = i + 1
			}
		}
	}
	if depth != 0 {
		return nil, fmt.Errorf("unbalanced parentheses")
	}
	return append(out, strings.TrimSpace(s[start:])), nil
}

var clashKinds = map[string]Kind{"DOMAIN": KindDomain, "DOMAIN-SUFFIX": KindDomainSuffix, "DOMAIN-KEYWORD": KindDomainKeyword, "DOMAIN-REGEX": KindDomainRegex, "IP-CIDR": KindIPCIDR, "IP-CIDR6": KindIPCIDR, "SRC-IP-CIDR": KindSrcIPCIDR, "DST-PORT": KindDstPort, "SRC-PORT": KindSrcPort, "NETWORK": KindNetwork, "PROCESS-NAME": KindProcessName, "PROCESS-NAME-REGEX": KindProcessNameRegex, "MATCH": KindMatch, "FINAL": KindMatch, "AND": KindAnd, "OR": KindOr, "NOT": KindNot, "RULE-SET": KindRuleSet, "GEOIP": KindGeoIP, "GEOSITE": KindRuleSet, "IP-ASN": KindRuleSet,
	"PROCESS-PATH": KindProcessPath, "PROCESS-PATH-REGEX": KindProcessPathRegex, "PROCESS-NAME-WILDCARD": KindProcessNameWildcard, "PROCESS-PATH-WILDCARD": KindProcessPathWildcard,
	"IN-NAME": KindInboundName, "IN-TYPE": KindInboundType, "IN-PORT": KindInboundPort, "IN-USER": KindInboundUser, "UID": KindUID}

// ParseClashCondition parses an actionless classical rule or logical operand.
// External references remain unresolved for the configuration compiler.
func ParseClashCondition(s string) (RuleSpec, error) { return parseCondition(s, 0) }
func parseCondition(s string, depth int) (RuleSpec, error) {
	var r RuleSpec
	if depth > 32 {
		return r, fmt.Errorf("condition nesting exceeds 32")
	}
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "(") && strings.HasSuffix(s, ")") {
		inner := s[1 : len(s)-1]
		if _, err := SplitClash(inner); err == nil {
			s = inner
		}
	}
	// Regex payloads are opaque CSV tails, matching the locked reference.
	// Their commas, escaped parentheses and character classes are not rule
	// separators or logical-condition delimiters.
	if head, payload, ok := strings.Cut(s, ","); ok && opaqueRegexKind(head) != 0 {
		kind := opaqueRegexKind(head)
		r = RuleSpec{Kind: kind, Values: []string{strings.TrimSpace(payload)}}
		_, err := compileRule(0, r)
		return r, err
	}
	parts, err := SplitClash(s)
	if err != nil || len(parts) == 0 {
		return r, fmt.Errorf("invalid condition")
	}
	k, ok := clashKinds[strings.ToUpper(parts[0])]
	if !ok {
		return r, fmt.Errorf("unsupported condition %q", parts[0])
	}
	r.Kind = k
	args := parts[1:]
	if k == KindAnd || k == KindOr || k == KindNot {
		if len(args) == 1 && strings.HasPrefix(args[0], "((") && strings.HasSuffix(args[0], "))") {
			args, err = SplitClash(args[0][1 : len(args[0])-1])
			if err != nil {
				return r, err
			}
		}
		if len(args) == 0 || (k == KindNot && len(args) != 1) {
			return r, fmt.Errorf("invalid logical operands")
		}
		for _, a := range args {
			if !strings.HasPrefix(a, "(") || !strings.HasSuffix(a, ")") {
				return r, fmt.Errorf("logical operand needs parentheses")
			}
			child, e := parseCondition(a, depth+1)
			if e != nil {
				return r, e
			}
			if child.Kind == KindMatch {
				return r, fmt.Errorf("MATCH is not a logical operand")
			}
			r.Children = append(r.Children, child)
		}
		return r, nil
	}
	if len(args) > 0 && args[len(args)-1] == "no-resolve" {
		r.NoResolve = true
		args = args[:len(args)-1]
	}
	if k == KindMatch {
		if len(args) != 0 || r.NoResolve {
			return r, fmt.Errorf("MATCH takes no condition arguments")
		}
		return r, nil
	}
	if len(args) != 1 || args[0] == "" {
		return r, fmt.Errorf("condition requires one value")
	}
	r.Values = []string{args[0]}
	if strings.EqualFold(parts[0], "GEOSITE") {
		r.Values[0] = "geosite:" + strings.ToLower(args[0])
	}
	if strings.EqualFold(parts[0], "IP-ASN") {
		r.Values[0] = "asn:" + strings.TrimPrefix(strings.ToUpper(args[0]), "AS")
	}
	if k == KindGeoIP && !strings.EqualFold(args[0], "LAN") {
		r.Kind = KindRuleSet
		r.Values[0] = "geoip:" + strings.ToLower(args[0])
	}
	if k == KindNetwork {
		r.Values[0] = strings.ToLower(args[0])
	}
	if r.Kind == KindRuleSet {
		r.Set = &RuleSet{}
	} // syntax validation only; caller must resolve
	if _, err = compileRule(0, r); err != nil {
		return r, err
	}
	r.Set = nil
	return r, nil
}

// ParseClashRule splits a routing rule into its guard and action. For SUB-RULE,
// call is the named block and Target is empty.
func ParseClashRule(s string) (r RuleSpec, call string, err error) {
	if head, rest, ok := strings.Cut(strings.TrimSpace(s), ","); ok && opaqueRegexKind(head) != 0 {
		index := strings.LastIndexByte(rest, ',')
		if index < 0 {
			return r, "", fmt.Errorf("regex rule needs target")
		}
		r, err = ParseClashCondition(head + "," + rest[:index])
		r.Target = strings.TrimSpace(rest[index+1:])
		return r, "", err
	}
	p, e := SplitClash(s)
	if e != nil || len(p) < 2 {
		return r, "", fmt.Errorf("invalid routing rule")
	}
	if strings.EqualFold(p[0], "SUB-RULE") {
		if len(p) != 3 {
			return r, "", fmt.Errorf("SUB-RULE needs guard and block")
		}
		r, e = ParseClashCondition(p[1])
		return r, p[2], e
	}
	modifier := ""
	if p[len(p)-1] == "no-resolve" {
		modifier = ",no-resolve"
		p = p[:len(p)-1]
	}
	if len(p) < 2 {
		return r, "", fmt.Errorf("missing target")
	}
	target := p[len(p)-1]
	r, e = ParseClashCondition(strings.Join(p[:len(p)-1], ",") + modifier)
	r.Target = target
	return r, "", e
}

func opaqueRegexKind(name string) Kind {
	kind := clashKinds[strings.ToUpper(name)]
	if kind == KindDomainRegex || kind == KindProcessNameRegex || kind == KindProcessPathRegex {
		return kind
	}
	return 0
}
