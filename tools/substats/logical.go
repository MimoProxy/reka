package main

import "strings"

// Logical rules nest sub-rules in parentheses. Three spellings occur in
// real subscriptions:
//
//	AND,((DST-PORT,443),(NETWORK,UDP)),TARGET     list wrapped once more
//	AND,(DST-PORT,443),(NETWORK,UDP),TARGET       items at the top level
//	(AND,(DST-PORT,443),(NETWORK,UDP))             nested: items follow TYPE
//
// The target is always the last field. logicalItems takes everything
// between the type and the target and returns its "(TYPE,...)" items.
func logicalItems(arg string) []string {
	arg = strings.TrimSpace(arg)
	items := splitRule(arg)
	if len(items) == 1 && strings.HasPrefix(arg, "((") && strings.HasSuffix(arg, "))") {
		items = splitRule(arg[1 : len(arg)-1])
	}
	return items
}

// subRule splits "(TYPE,REST)" into TYPE and REST.
func subRule(item string) (typ, rest string) {
	item = strings.TrimSpace(item)
	if strings.HasPrefix(item, "(") && strings.HasSuffix(item, ")") {
		item = item[1 : len(item)-1]
	}
	typ, rest, _ = strings.Cut(item, ",")
	return strings.ToUpper(strings.TrimSpace(typ)), rest
}

func isLogical(typ string) bool { return typ == "AND" || typ == "OR" || typ == "NOT" }

// logicalArg joins the fields between a logical rule's type and its target.
func logicalArg(parts []string) string {
	if len(parts) < 3 {
		return ""
	}
	return strings.Join(parts[1:len(parts)-1], ",")
}
