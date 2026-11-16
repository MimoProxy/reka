// Package rulesdata decodes immutable rule resources before router activation.
package rulesdata

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/MimoProxy/reka/internal/config/model"
	"github.com/MimoProxy/reka/internal/router"
	"go.yaml.in/yaml/v3"
)

const MaxExpanded = 64 << 20
const MaxEntries = 1_000_000

func Decode(behavior, format, code string, data []byte) ([]router.RuleSpec, error) {
	if len(data) == 0 || len(data) > model.MaxDocumentSize {
		return nil, errors.New("resource size outside limit")
	}
	if behavior == "geoip" || behavior == "geosite" {
		if behavior == "geoip" && format == "mmdb" { return decodeMMDB(code,data) }
		if format != "dat" {
			return nil, errors.New("geodata format must be dat (or mmdb for GEOIP)")
		}
		return decodeGeo(behavior, code, data)
	}
	var entries []string
	var err error
	switch format {
	case "mrs":
		entries, err = decodeMRS(behavior, data)
	case "text":
		if !utf8.Valid(data) || bytes.IndexByte(data, 0) >= 0 {
			return nil, errors.New("invalid rule text")
		}
		scanner := bufio.NewScanner(bytes.NewReader(data))
		scanner.Buffer(make([]byte, 4096), 1<<20)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
				continue
			}
			entries = append(entries, line)
			if len(entries) > MaxEntries {
				return nil, errors.New("too many entries")
			}
		}
		err = scanner.Err()
	case "yaml":
		root, ds := model.ParseNode("ruleset", data)
		if ds.HasErrors() || root == nil {
			return nil, errors.New("invalid rule YAML")
		}
		if root.Kind != yaml.MappingNode || len(root.Content) != 2 || root.Content[0].Value != "payload" || root.Content[1].Kind != yaml.SequenceNode {
			return nil, errors.New("expected only payload list")
		}
		for _, n := range root.Content[1].Content {
			if n.Kind != yaml.ScalarNode || n.Tag != "!!str" {
				return nil, errors.New("payload entries must be strings")
			}
			entries = append(entries, n.Value)
		}
	default:
		return nil, errors.New("unknown rule resource format")
	}
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, errors.New("empty rule resource")
	}
	if len(entries) > MaxEntries {
		return nil, errors.New("too many entries")
	}
	switch behavior {
	case "domain":
		var exact, suffix, patterns []string
		for _, v := range entries {
			if err := router.ValidDomainPattern(v); err != nil {
				return nil, err
			}
			v = strings.ToLower(v)
			switch {
			case strings.HasPrefix(v, "+.") && !strings.Contains(v, "*"):
				suffix = append(suffix, v[2:])
			case strings.ContainsAny(v, "*+") || strings.HasPrefix(v, "."):
				patterns = append(patterns, v)
			default:
				exact = append(exact, v)
			}
		}
		var specs []router.RuleSpec
		for _, g := range []struct {
			k router.Kind
			v []string
		}{{router.KindDomain, exact}, {router.KindDomainSuffix, suffix}, {router.KindDomainPattern, patterns}} {
			if len(g.v) > 0 {
				specs = append(specs, router.RuleSpec{Kind: g.k, Values: g.v})
			}
		}
		return checked(specs)
	case "ipcidr":
		if len(entries) == 0 {
			return nil, nil
		}
		return checked([]router.RuleSpec{{Kind: router.KindIPCIDR, Values: entries}})
	case "classical":
		var specs []router.RuleSpec
		for i, v := range entries {
			r, e := router.ParseClashCondition(v)
			if e != nil {
				return nil, fmt.Errorf("entry %d: %w", i, e)
			}
			if !classicalCondition(r) {
				return nil, fmt.Errorf("entry %d: MATCH and RULE-SET forbidden in classical rules", i)
			}
			specs = append(specs, r)
		}
		return specs, nil // external references resolved by compiler
	default:
		return nil, errors.New("unknown rule behavior")
	}
}
func checked(specs []router.RuleSpec) ([]router.RuleSpec, error) {
	_, err := router.CompileRules(specs)
	return specs, err
}

func classicalCondition(r router.RuleSpec) bool {
	if r.Kind == router.KindMatch {
		return false
	}
	if r.Kind == router.KindRuleSet && !strings.HasPrefix(r.Values[0], "geoip:") && !strings.HasPrefix(r.Values[0], "geosite:") {
		return false
	}
	for _, ch := range r.Children {
		if !classicalCondition(ch) {
			return false
		}
	}
	return true
}
