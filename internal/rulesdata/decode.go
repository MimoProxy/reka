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
	"github.com/MimoProxy/reka/internal/resource"
	"github.com/MimoProxy/reka/internal/router"
	"go.yaml.in/yaml/v3"
)

const MaxExpanded = 128 << 20
const MaxEntries = 1_000_000

// Decode returns specs for callers that need to inspect or convert rules.
// GeoSite values are batched by kind, like domain provider values.
func Decode(behavior, format, code string, data []byte) ([]router.RuleSpec, error) {
	var specs []router.RuleSpec
	domainGroups := make(map[router.Kind]int)
	visit := func(spec router.RuleSpec) error {
		specs = append(specs, spec)
		return nil
	}
	err := walk(behavior, format, code, data, visit, func(kind router.Kind, value string) error {
		i, exists := domainGroups[kind]
		if !exists {
			i = len(specs)
			domainGroups[kind] = i
			specs = append(specs, router.RuleSpec{Kind: kind})
		}
		specs[i].Values = append(specs[i].Values, value)
		return nil
	}, nil, nil, router.ParseClashCondition)
	if err != nil {
		return nil, err
	}
	if behavior != "classical" || format == "srs" {
		_, err = router.CompileRules(specs)
	}
	return specs, err
}

// Walk decodes a resource for compilation. GeoSite domains arrive as single
// values so the caller can store them without allocating RuleSpecs. The
// caller validates conditions and resolves references before using the set.
// reserve receives the size of unfiltered GeoSite categories, if set.
func Walk(behavior, format, code string, data []byte, visit func(router.RuleSpec) error, domain func(router.Kind, string) error, reserve func(int)) error {
	return WalkWithBudget(behavior, format, code, data, visit, domain, reserve, nil)
}

// WalkWithBudget also charges entries to a shared budget across resources.
func WalkWithBudget(behavior, format, code string, data []byte, visit func(router.RuleSpec) error, domain func(router.Kind, string) error, reserve func(int), account func(int) error) error {
	return walk(behavior, format, code, data, visit, domain, reserve, account, router.ParseClashSetCondition)
}

func walk(behavior, format, code string, data []byte, visit func(router.RuleSpec) error, domain func(router.Kind, string) error, reserve func(int), account func(int) error, parseClassical func(string) (router.RuleSpec, error)) error {
	if len(data) == 0 || len(data) > resource.MaxSize {
		return errors.New("resource size outside limit")
	}
	if format == "srs" {
		return walkSRS(behavior, data, visit, account)
	}
	if account != nil {
		add, addDomain := visit, domain
		visit = func(spec router.RuleSpec) error {
			if err := account(1 + len(spec.Values)); err != nil {
				return err
			}
			return add(spec)
		}
		domain = func(kind router.Kind, value string) error {
			if err := account(2); err != nil {
				return err
			}
			return addDomain(kind, value)
		}
	}
	if behavior == "asn" {
		var err error
		code, err = asnCode(code)
		if err != nil {
			return err
		}
	}
	if behavior == "geoip" || behavior == "geosite" || behavior == "asn" {
		if behavior != "geosite" && format == "mmdb" {
			specs, err := decodeNetworkDB(behavior, code, data)
			if err != nil {
				return err
			}
			for _, spec := range specs {
				if err := visit(spec); err != nil {
					return err
				}
			}
			return nil
		}
		if format != "dat" {
			return errors.New("geodata format must be dat, srs for GeoSite or GeoIP, or mmdb for GeoIP or ASN")
		}
		return decodeGeo(behavior, code, data, visit, domain, reserve)
	}
	var entries []string
	var err error
	switch format {
	case "mrs":
		entries, err = decodeMRS(behavior, data)
	case "text", "surge":
		if !utf8.Valid(data) || bytes.IndexByte(data, 0) >= 0 {
			return errors.New("invalid rule text")
		}
		scanner := bufio.NewScanner(bytes.NewReader(data))
		scanner.Buffer(make([]byte, 4096), 1<<20)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") ||
				format == "surge" && strings.HasPrefix(line, ";") {
				continue
			}
			entries = append(entries, line)
			if len(entries) > MaxEntries {
				return errors.New("too many entries")
			}
		}
		err = scanner.Err()
	case "yaml":
		root, ds := model.ParseNode("ruleset", data)
		if ds.HasErrors() || root == nil {
			return errors.New("invalid rule YAML")
		}
		if root.Kind != yaml.MappingNode || len(root.Content) != 2 || root.Content[0].Value != "payload" || root.Content[1].Kind != yaml.SequenceNode {
			return errors.New("expected only payload list")
		}
		for _, n := range root.Content[1].Content {
			if n.Kind != yaml.ScalarNode || n.Tag != "!!str" {
				return errors.New("payload entries must be strings")
			}
			entries = append(entries, n.Value)
		}
	default:
		return errors.New("unknown rule resource format")
	}
	if err != nil {
		return err
	}
	if format == "surge" {
		if entries, err = surgeEntries(behavior, entries); err != nil {
			return err
		}
	}
	if len(entries) == 0 {
		return errors.New("empty rule resource")
	}
	if len(entries) > MaxEntries {
		return errors.New("too many entries")
	}
	switch behavior {
	case "domain":
		var exact, suffix, patterns []string
		for _, v := range entries {
			if err := router.ValidDomainPattern(v); err != nil {
				return err
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
		for _, g := range []struct {
			k router.Kind
			v []string
		}{{router.KindDomain, exact}, {router.KindDomainSuffix, suffix}, {router.KindDomainPattern, patterns}} {
			if len(g.v) > 0 {
				if err := visit(router.RuleSpec{Kind: g.k, Values: g.v}); err != nil {
					return err
				}
			}
		}
		return nil
	case "ipcidr":
		return visit(router.RuleSpec{Kind: router.KindIPCIDR, Values: entries})
	case "classical":
		for i, v := range entries {
			r, e := parseClassical(v)
			if e != nil {
				return fmt.Errorf("entry %d: %w", i, e)
			}
			if !classicalCondition(r) {
				return fmt.Errorf("entry %d: MATCH and RULE-SET forbidden in classical rules", i)
			}
			if err := visit(r); err != nil {
				return err
			}
		}
		return nil // external references resolved by compiler
	default:
		return errors.New("unknown rule behavior")
	}
}

func classicalCondition(r router.RuleSpec) bool {
	if r.Kind == router.KindMatch {
		return false
	}
	if r.Kind == router.KindRuleSet && !strings.HasPrefix(r.Values[0], "geoip:") && !strings.HasPrefix(r.Values[0], "geosite:") && !strings.HasPrefix(r.Values[0], "asn:") {
		return false
	}
	for _, ch := range r.Children {
		if !classicalCondition(ch) {
			return false
		}
	}
	return true
}
