package compile

import (
	"slices"
	"strings"

	"github.com/MimoProxy/reka/internal/config/model"
	"github.com/MimoProxy/reka/internal/router"
)

func geodataSelector(def model.RuleSet) string {
	switch def.Behavior {
	case "geoip", "geosite", "asn":
		if def.Code != "" {
			return def.Behavior + ":" + def.Code
		}
	}
	return ""
}

func (r *ruleCompiler) ruleSetSelectors() map[string]string {
	var selectors map[string]string
	for id, def := range r.defs {
		if selector := geodataSelector(def); selector != "" {
			if selectors == nil {
				selectors = make(map[string]string)
			}
			selectors[id] = selector
		}
	}
	return selectors
}

func (r *ruleCompiler) ruleDescription(rule model.Rule, spec router.RuleSpec) string {
	if rule.Syntax != "" {
		source, call, err := router.ParseClashRule(rule.Syntax)
		if err == nil && call == "" && r.sameRuleCondition(source, spec) {
			return rule.Syntax
		}
	}
	var text strings.Builder
	match := rule.Match
	match.NoResolve = false
	writeRuleMatch(&text, match)
	text.WriteByte(',')
	text.WriteString(spec.Target)
	if rule.Match.NoResolve {
		text.WriteString(",no-resolve")
	}
	return text.String()
}

// Check the saved syntax against the effective condition because an overlay
// can replace a rule's match while leaving its imported metadata in place.
func (r *ruleCompiler) sameRuleCondition(source, effective router.RuleSpec) bool {
	if source.Kind != effective.Kind || source.NoResolve != effective.NoResolve || len(source.Children) != len(effective.Children) {
		return false
	}
	if !slices.Equal(source.Values, effective.Values) {
		if source.Kind != router.KindRuleSet || len(source.Values) != 1 || len(effective.Values) != 1 {
			return false
		}
		def := r.defs[effective.Values[0]]
		if source.Values[0] != def.Name && !strings.EqualFold(source.Values[0], geodataSelector(def)) {
			return false
		}
	}
	for index, child := range source.Children {
		if !r.sameRuleCondition(child, effective.Children[index]) {
			return false
		}
	}
	return true
}

func writeRuleMatch(text *strings.Builder, match model.Match) {
	if match.Kind == "all" {
		text.WriteString("MATCH")
	} else {
		text.WriteString(strings.ToUpper(match.Kind))
	}
	if len(match.Values) > 0 {
		text.WriteByte(',')
		text.WriteString(strings.Join(match.Values, "|"))
	}
	for _, child := range match.Children {
		text.WriteString(",(")
		writeRuleMatch(text, child)
		text.WriteByte(')')
	}
	if match.NoResolve {
		text.WriteString(",no-resolve")
	}
}
