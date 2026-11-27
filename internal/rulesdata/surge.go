package rulesdata

import (
	"errors"
	"strings"

	"github.com/MimoProxy/reka/internal/router"
)

// Surge and Loon rule lists differ from Clash text providers in a few ways.
// A DOMAIN-SET line starting with "." also matches the domain itself, some
// rule types use other names, and lines the client cannot use are skipped
// rather than rejecting the whole list.
var surgeKinds = map[string]string{"DEST-PORT": "DST-PORT", "SRC-IP": "SRC-IP-CIDR"}

func surgeEntries(behavior string, entries []string) ([]string, error) {
	kept := entries[:0]
	switch behavior {
	case "domain":
		for _, entry := range entries {
			if strings.ContainsAny(entry, "*+") {
				continue
			}
			if rest, ok := strings.CutPrefix(entry, "."); ok {
				entry = "+." + rest
			}
			if router.ValidDomainPattern(entry) == nil {
				kept = append(kept, entry)
			}
		}
	case "classical":
		for _, entry := range entries {
			if entry, ok := surgeRule(entry); ok {
				kept = append(kept, entry)
			}
		}
	default:
		return nil, errors.New("Surge rule lists must use the domain or classical behavior")
	}
	return kept, nil
}

func surgeRule(entry string) (string, bool) {
	// Matching modifiers that change only how Surge finds the name.
	for {
		at := strings.LastIndexByte(entry, ',')
		if at < 0 {
			break
		}
		modifier := strings.ToLower(strings.TrimSpace(entry[at+1:]))
		if modifier != "extended-matching" && modifier != "pre-matching" {
			break
		}
		entry = strings.TrimSpace(entry[:at])
	}
	if kind, rest, ok := strings.Cut(entry, ","); ok {
		if alias, found := surgeKinds[strings.ToUpper(strings.TrimSpace(kind))]; found {
			entry = alias + "," + rest
		}
	}
	spec, err := router.ParseClashCondition(entry)
	if err != nil || !classicalCondition(spec) {
		return "", false
	}
	return entry, true
}
