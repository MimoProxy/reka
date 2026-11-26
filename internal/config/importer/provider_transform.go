package importer

import (
	"errors"
	"strings"
	"time"

	"github.com/MimoProxy/reka/internal/compat/providerexpr"
	"github.com/MimoProxy/reka/internal/config/model"
	"github.com/dlclark/regexp2"
	"go.yaml.in/yaml/v3"
)

type providerTransform struct {
	filters, excludes []*regexp2.Regexp
	excludeTypes      []string
	values            map[string]*yaml.Node
	names             []providerNameReplace
	prefix, suffix    string
	expressions       []providerexpr.OverrideExpr
}
type providerNameReplace struct {
	pattern *regexp2.Regexp
	target  string
}

func providerRegex(text string) (*regexp2.Regexp, error) {
	r, err := regexp2.Compile(text, regexp2.None)
	if err != nil {
		return nil, errors.New("provider_regex_invalid")
	}
	r.MatchTimeout = 50 * time.Millisecond
	return r, nil
}
func parseProviderTransform(n *yaml.Node) (*providerTransform, error) {
	p := &providerTransform{values: map[string]*yaml.Node{}}
	for _, key := range []string{"filter", "exclude-filter"} {
		text := text(get(n, key))
		if key == "exclude-filter" && text == "" {
			continue
		}
		for _, part := range strings.Split(text, "`") {
			r, err := providerRegex(part)
			if err != nil {
				return nil, err
			}
			if key == "filter" {
				p.filters = append(p.filters, r)
			} else {
				p.excludes = append(p.excludes, r)
			}
		}
	}
	p.excludeTypes = strings.Split(text(get(n, "exclude-type")), "|")
	o := get(n, "override")
	if o == nil {
		return p, nil
	}
	if o.Kind != yaml.MappingNode {
		return nil, errors.New("provider_override_invalid")
	}
	for i := 0; i+1 < len(o.Content); i += 2 {
		key, value := o.Content[i].Value, deref(o.Content[i+1])
		switch key {
		case "additional-prefix", "additional-suffix":
			if value.Kind != yaml.ScalarNode || value.Tag != "!!str" {
				return nil, errors.New("provider_override_invalid")
			}
			if key == "additional-prefix" {
				p.prefix = value.Value
			} else {
				p.suffix = value.Value
			}
		case "tfo", "mptcp", "udp", "udp-over-tcp", "up", "down", "dialer-proxy", "skip-cert-verify", "name-cert-verify", "interface-name", "routing-mark", "ip-version":
			if value.Kind != yaml.ScalarNode {
				return nil, errors.New("provider_override_invalid")
			}
			p.values[key] = copyNode(value)
		case "proxy-name":
			if value.Kind != yaml.SequenceNode {
				return nil, errors.New("provider_override_invalid")
			}
			for _, item := range value.Content {
				r, err := providerRegex(text(get(item, "pattern")))
				if err != nil {
					return nil, err
				}
				for j := 0; j+1 < len(item.Content); j += 2 {
					if item.Content[j].Value != "pattern" && item.Content[j].Value != "target" {
						return nil, errors.New("provider_override_invalid")
					}
				}
				p.names = append(p.names, providerNameReplace{r, text(get(item, "target"))})
			}
		case "override-expr":
			if value.Kind != yaml.SequenceNode || len(value.Content) > 64 {
				return nil, errors.New("provider_override_invalid")
			}
			for _, item := range value.Content {
				if item.Kind != yaml.ScalarNode || item.Tag != "!!str" || len(item.Value) > 8192 {
					return nil, errors.New("provider_override_expression_invalid")
				}
				expr, err := providerexpr.NewOverrideExpr(item.Value)
				if err != nil {
					return nil, errors.New("provider_override_expression_invalid")
				}
				p.expressions = append(p.expressions, expr)
			}
		default:
			return nil, errors.New("provider_override_option_unsupported")
		}
	}
	return p, nil
}
func (p *providerTransform) apply(nodes []*yaml.Node) ([]*yaml.Node, error) {
	result := []*yaml.Node{}
	seen := map[string]bool{}
	for _, filter := range p.filters {
		for _, node := range nodes {
			name := text(get(node, "name"))
			if seen[name] {
				continue
			}
			excluded := false
			for _, typ := range p.excludeTypes {
				if strings.EqualFold(typ, text(get(node, "type"))) {
					excluded = true
				}
			}
			for _, r := range p.excludes {
				ok, err := r.MatchString(name)
				if err != nil {
					return nil, errors.New("provider_regex_timeout")
				}
				excluded = excluded || ok
			}
			if excluded {
				continue
			}
			ok, err := filter.MatchString(name)
			if err != nil {
				return nil, errors.New("provider_regex_timeout")
			}
			if !ok {
				continue
			}
			seen[name] = true
			n := copyNode(node)
			hysteria := text(get(n, "type")) == "hysteria"
			for key, value := range p.values {
				if hysteria {
					// Update the payload's spelling so an override cannot create a duplicate alias.
					for i := 0; i+1 < len(n.Content); i += 2 {
						if sourceKey := n.Content[i].Value; strings.ReplaceAll(sourceKey, "_", "-") == key {
							key = sourceKey
							break
						}
					}
				}
				putField(n, key, copyNode(value))
			}
			for _, replace := range p.names {
				name, err = replace.pattern.Replace(name, replace.target, 0, -1)
				if err != nil {
					return nil, errors.New("provider_regex_timeout")
				}
			}
			putField(n, "name", &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: p.prefix + name + p.suffix})
			if len(p.expressions) > 0 {
				mapping := map[string]any{}
				if err = n.Decode(&mapping); err != nil {
					return nil, errors.New("provider_override_invalid")
				}
				for _, expr := range p.expressions {
					if err = expr.Apply(mapping); err != nil {
						return nil, errors.New("provider_override_expression_failed")
					}
				}
				n = &yaml.Node{}
				if err = n.Encode(mapping); err != nil || len(model.Format(n)) > model.MaxDocumentSize {
					return nil, errors.New("provider_override_output_invalid")
				}
			}
			result = append(result, n)
		}
	}
	return result, nil
}
