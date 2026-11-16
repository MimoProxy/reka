package importer

import (
	"encoding/json"
	"errors"
	"github.com/MimoProxy/reka/internal/policy"
	"github.com/MimoProxy/reka/internal/resource"
	"github.com/MimoProxy/reka/internal/router"
	"github.com/MimoProxy/reka/internal/rulesdata"
	"net/textproto"
	"strconv"
	"strings"

	"github.com/MimoProxy/reka/internal/config/model"
	"go.yaml.in/yaml/v3"
)

type Provider struct {
	Path, Proxy string
	transform   *providerTransform
	Fallback    []byte
	ID          string
	Name        string
	Kind        string
	Type        string
	URL         string
	Interval    int
	Headers     map[string][]string
	Format      string
	Behavior    string
	Health      object
	Inline      []byte
}

func checkedDocument(data []byte) (*yaml.Node, error) {
	root, ds := model.ParseNode("clash", data)
	c := &converter{report: Report{Format: "clash"}}
	if ds.HasErrors() || root == nil || !c.validateTree(root) {
		return nil, errors.New("provider_document_invalid")
	}
	return root, nil
}

// Providers lists only referenced resources. Nodes-only explicitly selects all
// proxy providers. No URLs, files or payloads are fetched here.
func Providers(req Request) ([]Provider, error) {
	format := req.Format
	if format == "" || format == "auto" {
		format = detectFormat(req.Data)
	}
	if format == "links" {
		return nil, nil
	}
	if format != "clash" {
		return nil, errors.New("provider_format_invalid")
	}
	root, err := checkedDocument([]byte(req.Data))
	if err != nil {
		return nil, err
	}
	usedProxy, usedRule := map[string]bool{}, map[string]bool{}
	if req.NodesOnly {
		if defs := get(root, "proxy-providers"); !empty(defs) {
			if defs.Kind != yaml.MappingNode {
				return nil, errors.New("provider_definition_invalid")
			}
			for i := 0; i+1 < len(defs.Content); i += 2 {
				usedProxy[defs.Content[i].Value] = true
			}
		}
	} else {
		if groups := get(root, "proxy-groups"); !empty(groups) {
			if groups.Kind != yaml.SequenceNode {
				return nil, errors.New("provider_group_invalid")
			}
			for _, g := range groups.Content {
				if text(get(g, "include-all")) == "true" || text(get(g, "include-all-providers")) == "true" {
					defs := get(root, "proxy-providers")
					if defs != nil {
						for i := 0; i+1 < len(defs.Content); i += 2 {
							usedProxy[defs.Content[i].Value] = true
						}
					}
				}
				if use := get(g, "use"); !empty(use) {
					if use.Kind != yaml.SequenceNode {
						return nil, errors.New("provider_use_invalid")
					}
					for _, name := range use.Content {
						if deref(name).Tag != "!!str" {
							return nil, errors.New("provider_use_invalid")
						}
						usedProxy[text(name)] = true
					}
				}
			}
		}
		var collect func(router.RuleSpec)
		collect = func(r router.RuleSpec) {
			if r.Kind == router.KindRuleSet && len(r.Values) == 1 && !strings.HasPrefix(r.Values[0], "geoip:") && !strings.HasPrefix(r.Values[0], "geosite:") && !strings.HasPrefix(r.Values[0], "asn:") {
				usedRule[r.Values[0]] = true
			}
			for _, ch := range r.Children {
				collect(ch)
			}
		}
		lists := []*yaml.Node{get(root, "rules")}
		if defs := get(root, "sub-rules"); !empty(defs) {
			if defs.Kind != yaml.MappingNode {
				return nil, errors.New("sub_rule_invalid")
			}
			for i := 1; i < len(defs.Content); i += 2 {
				lists = append(lists, deref(defs.Content[i]))
			}
		}
		for _, rules := range lists {
			if empty(rules) {
				continue
			}
			if rules.Kind != yaml.SequenceNode {
				return nil, errors.New("provider_rule_invalid")
			}
			for _, n := range rules.Content {
				r, _, e := router.ParseClashRule(text(n))
				if e == nil {
					collect(r)
				}
			}
		}

		if cfg := get(root, "dns"); cfg != nil && text(get(cfg, "enable")) != "false" {
			if policies := get(cfg, "nameserver-policy"); policies != nil {
				for i := 0; i+1 < len(policies.Content); i += 2 {
					key := policies.Content[i].Value
					if strings.HasPrefix(key, "rule-set:") {
						usedRule[strings.TrimPrefix(key, "rule-set:")] = true
					}
				}
			}
		}
	}
	result := []Provider{}
	for _, kind := range []string{"proxy", "rule"} {
		used := usedProxy
		if kind == "rule" {
			used = usedRule
		}
		defs := get(root, kind+"-providers")
		for name := range used {
			if get(defs, name) == nil {
				return nil, errors.New("provider_missing")
			}
		}
		if empty(defs) {
			continue
		}
		if defs.Kind != yaml.MappingNode {
			return nil, errors.New("provider_definition_invalid")
		}
		for i := 0; i+1 < len(defs.Content); i += 2 {
			name := defs.Content[i].Value
			if !used[name] {
				continue
			}
			n := deref(defs.Content[i+1])
			if n.Kind != yaml.MappingNode {
				return nil, errors.New("provider_definition_invalid")
			}
			p := Provider{
				ID:       StableID(kind, name),
				Name:     name,
				Kind:     kind,
				Type:     text(get(n, "type")),
				URL:      text(get(n, "url")),
				Interval: 3600,
				Format:   "yaml",
				Headers:  map[string][]string{},
			}
			for j := 0; j+1 < len(n.Content); j += 2 {
				key := n.Content[j].Value
				allowed := key == "type" || key == "url" || key == "interval" || key == "path" || key == "header" || key == "payload" || key == "proxy" || kind == "proxy" && (key == "filter" || key == "exclude-filter" || key == "exclude-type" || key == "override") || kind == "rule" && (key == "behavior" || key == "format")
				if key == "health-check" && kind == "proxy" {
					allowed = true
					health := get(n, key)
					if health.Kind != yaml.MappingNode {
						return nil, errors.New("provider_health_invalid")
					}
					reader := &converter{}
					r := proxyReader{c: reader, n: health, path: "/health-check"}
					enabled := r.boolean("enable", false)
					if _, err := policy.ParseExpectedStatus(r.str("expected-status")); err != nil {
						return nil, errors.New("provider_health_status_invalid")
					}
					for k := 0; k+1 < len(health.Content); k += 2 {
						key := health.Content[k].Value
						if key != "enable" && key != "url" && key != "interval" && key != "timeout" && key != "lazy" && key != "expected-status" {
							return nil, errors.New("provider_health_option_unsupported")
						}
					}
					if enabled {
						p.Health = object{
							"name":            "provider-health-" + p.ID,
							"type":            "url-test",
							"url":             r.str("url"),
							"interval":        r.number("interval", 300),
							"timeout":         r.number("timeout", 5000),
							"lazy":            r.boolean("lazy", true),
							"expected-status": r.str("expected-status"),
						}
					}
					if r.bad {
						return nil, errors.New("provider_health_invalid")
					}
				}

				if !allowed {
					return nil, errors.New("provider_option_unsupported")
				}
			}
			if interval := get(n, "interval"); interval != nil {
				value, e := strconv.Atoi(text(interval))
				if e != nil || value < 0 || value > 604800 || value > 0 && value < 30 {
					return nil, errors.New("provider_interval_invalid")
				}
				if value > 0 {
					p.Interval = value
				}
			}
			if headers := get(n, "header"); !empty(headers) {
				if headers.Kind != yaml.MappingNode {
					return nil, errors.New("provider_header_invalid")
				}
				for j := 0; j+1 < len(headers.Content); j += 2 {
					key, val := headers.Content[j].Value, deref(headers.Content[j+1])
					values := []string{}
					switch strings.ToLower(key) {
					case "host", "content-length", "connection", "transfer-encoding", "if-none-match", "if-modified-since":
						return nil, errors.New("provider_header_invalid")
					}
					if val.Kind == yaml.ScalarNode && val.Tag == "!!str" {
						values = append(values, val.Value)
					} else if val.Kind == yaml.SequenceNode {
						for _, v := range val.Content {
							v = deref(v)
							if v.Kind != yaml.ScalarNode || v.Tag != "!!str" {
								return nil, errors.New("provider_header_invalid")
							}
							values = append(values, v.Value)
						}
					} else {
						return nil, errors.New("provider_header_invalid")
					}
					canonical := textproto.CanonicalMIMEHeaderKey(key)
					if _, exists := p.Headers[canonical]; exists {
						return nil, errors.New("provider_header_invalid")
					}
					p.Headers[canonical] = values
				}
			}
			if kind == "rule" {
				p.Behavior = text(get(n, "behavior"))
				if p.Behavior != "domain" && p.Behavior != "ipcidr" && p.Behavior != "classical" {
					return nil, errors.New("provider_behavior_invalid")
				}
				if v := get(n, "format"); v != nil {
					p.Format = text(v)
				}
				if p.Format != "yaml" && p.Format != "text" && p.Format != "mrs" {
					return nil, errors.New("provider_format_invalid")
				}
			}
			p.Path, p.Proxy = text(get(n, "path")), text(get(n, "proxy"))
			if kind == "proxy" {
				p.transform, err = parseProviderTransform(n)
				if err != nil {
					return nil, err
				}
			}
			if payload := get(n, "payload"); !empty(payload) && len(payload.Content) > 0 {
				if payload.Kind != yaml.SequenceNode || kind == "rule" && p.Format != "yaml" {
					return nil, errors.New("provider_payload_invalid")
				}
				key := "proxies"
				if kind == "rule" {
					key = "payload"
				}
				wrapper := &yaml.Node{Kind: yaml.MappingNode, Content: []*yaml.Node{{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, payload}}
				p.Fallback = model.Format(wrapper)
			}
			switch p.Type {
			case "http":
				if p.URL == "" {
					return nil, errors.New("provider_url_invalid")
				}

			case "file":
				if p.Path == "" {
					return nil, errors.New("provider_path_invalid")
				}
			case "inline":
				payload := get(n, "payload")
				if payload == nil || payload.Kind != yaml.SequenceNode || len(payload.Content) == 0 {
					return nil, errors.New("provider_payload_invalid")
				}
				key := "proxies"
				if kind == "rule" {
					key = "payload"
					if p.Format != "yaml" {
						return nil, errors.New("provider_inline_format_invalid")
					}
				}
				wrapper := &yaml.Node{Kind: yaml.MappingNode, Content: []*yaml.Node{{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, payload}}
				p.Inline = model.Format(wrapper)
			default:
				return nil, errors.New("provider_type_unsupported")
			}
			result = append(result, p)
			if len(result) > 16 {
				return nil, errors.New("provider_limit")
			}
		}
	}
	return result, nil
}
func ValidateProvider(p Provider, data []byte) error {
	if len(data) == 0 || len(data) > model.MaxDocumentSize {
		return errors.New("provider_payload_invalid")
	}
	if p.Kind == "rule" {
		_, err := rulesdata.Decode(p.Behavior, p.Format, "", data)
		return err
	}

	root, err := checkedDocument(data)
	if err != nil {
		return err
	}
	if p.Kind == "proxy" {
		nodes := get(root, "proxies")
		if nodes == nil || nodes.Kind != yaml.SequenceNode || len(nodes.Content) == 0 {
			return errors.New("provider_payload_invalid")
		}
		for _, key := range []string{"proxy-providers", "rule-providers", "proxy-groups", "rules"} {
			if value := get(root, key); !empty(value) && len(value.Content) > 0 {
				return errors.New("provider_nested_unsupported")
			}
		}
	} else {
		payload := get(root, "payload")
		if payload == nil || payload.Kind != yaml.SequenceNode || len(payload.Content) == 0 {
			return errors.New("provider_payload_invalid")
		}
		for _, v := range payload.Content {
			if deref(v).Kind != yaml.ScalarNode || deref(v).Tag != "!!str" {
				return errors.New("provider_payload_invalid")
			}
		}
	}
	return nil
}
func copyNode(n *yaml.Node) *yaml.Node {
	n = deref(n)
	v := *n
	v.Alias = nil
	v.Anchor = ""
	v.Content = nil
	for _, ch := range n.Content {
		v.Content = append(v.Content, copyNode(ch))
	}
	return &v
}
func putField(n *yaml.Node, key string, value *yaml.Node) {
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			n.Content[i+1] = value
			return
		}
	}
	n.Content = append(n.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, value)
}
func removeField(n *yaml.Node, key string) {
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			n.Content = append(n.Content[:i], n.Content[i+2:]...)
			return
		}
	}
}
func invalidBundle(req Request, err error) Result {
	return Result{Report: Report{
		SourceID:    req.SourceID,
		Format:      "clash",
		Diagnostics: model.Diagnostics{{Severity: model.SeverityError, Code: "import.provider", Document: "clash", Path: "/", Message: err.Error()}},
	}}
}

// ImportProviders is pure: payloads must already be downloaded and locked by
// the caller. Each provider gets its own node identities within this source.
func ImportProviders(req Request, payloads map[string][]byte) Result {
	providers, err := Providers(req)
	if err != nil {
		return invalidBundle(req, err)
	}
	if len(providers) == 0 {
		format := req.Format
		if format == "" || format == "auto" {
			format = detectFormat(req.Data)
		}
		if format != "clash" {
			return importDirect(req)
		}
	}
	root, err := checkedDocument([]byte(req.Data))
	if err != nil {
		return invalidBundle(req, err)
	}
	originalRoot := root
	root = copyNode(root)
	nodes := get(root, "proxies")
	if nodes == nil {
		nodes = &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
		putField(root, "proxies", nodes)
	}
	if nodes.Kind != yaml.SequenceNode {
		return invalidBundle(req, errors.New("provider_payload_invalid"))
	}
	aliases := map[string][]string{}
	originals := map[string]struct{ provider, name string }{}
	for _, p := range providers {
		data := payloads[p.ID]
		if err := ValidateProvider(p, data); err != nil {
			return invalidBundle(req, err)
		}
		if p.Kind != "proxy" {
			continue
		}
		payload, _ := checkedDocument(data)
		providerNodes := get(payload, "proxies").Content
		if p.transform != nil {
			providerNodes, err = p.transform.apply(providerNodes)
			if err != nil {
				return invalidBundle(req, err)
			}
		}
		for _, node := range providerNodes {
			n := copyNode(node)
			name := text(get(n, "name"))
			if strings.TrimSpace(name) == "" {
				return invalidBundle(req, errors.New("provider_name_invalid"))
			}
			alias := p.Name + "/" + name
			originals[alias] = struct{ provider, name string }{p.Name, name}
			aliases[p.Name] = append(aliases[p.Name], alias)
			putField(n, "name", &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: alias})
			nodes.Content = append(nodes.Content, n)
		}
	}
	if groups := get(root, "proxy-groups"); groups != nil && groups.Kind == yaml.SequenceNode {
		for _, g := range groups.Content {
			use := get(g, "use")
			if use == nil {
				continue
			}
			members := get(g, "proxies")
			if members == nil {
				members = &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
				putField(g, "proxies", members)
			}
			if members.Kind != yaml.SequenceNode {
				return invalidBundle(req, errors.New("provider_group_invalid"))
			}
			for _, ref := range use.Content {
				for _, alias := range aliases[text(ref)] {
					members.Content = append(members.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: alias})
				}
			}
			removeField(g, "use")
		}
	}
	if !req.NodesOnly {
		for _, p := range providers {
			if p.Health == nil || len(aliases[p.Name]) == 0 {
				continue
			}
			health := object{}
			for k, v := range p.Health {
				health[k] = v
			}
			health["proxies"] = aliases[p.Name]
			n := &yaml.Node{}
			_ = n.Encode(health)
			groups := get(root, "proxy-groups")
			if groups == nil {
				groups = &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
				putField(root, "proxy-groups", groups)
			}
			groups.Content = append(groups.Content, n)
		}
	}
	removeField(root, "proxy-providers")
	removeField(root, "rule-providers")
	req.ruleSets = append([]object{}, req.ruleSets...)
	if req.resourceNames == nil {
		req.resourceNames = map[string]string{}
	}
	for _, p := range providers {
		if p.Kind == "rule" {
			data := payloads[p.ID]
			req.resourceNames[p.Name] = p.ID
			refs := []object{}
			keys := map[string]bool{}
			for name := range req.resourceNames {
				keys[name] = true
			}
			for _, name := range sortedNames(keys) {
				refs = append(refs, object{"name": name, "to": req.resourceNames[name]})
			}
			req.ruleSets = append(req.ruleSets, object{"id": p.ID, "behavior": p.Behavior, "format": p.Format, "hash": resource.Hash(data), "references": refs})
		}
	}
	var checkRefs func(router.RuleSpec) bool
	checkRefs = func(s router.RuleSpec) bool {
		if s.Kind == router.KindRuleSet && len(s.Values) == 1 && req.resourceNames[s.Values[0]] == "" {
			return false
		}
		for _, ch := range s.Children {
			if !checkRefs(ch) {
				return false
			}
		}
		return true
	}
	for _, p := range providers {
		if p.Kind == "rule" && p.Behavior == "classical" {
			specs, e := rulesdata.Decode(p.Behavior, p.Format, "", payloads[p.ID])
			if e != nil {
				return invalidBundle(req, e)
			}
			for _, s := range specs {
				if !checkRefs(s) {
					return invalidBundle(req, errors.New("geodata_resource_missing"))
				}
			}
		}
	}
	req.displayNames = map[string]string{}
	for alias, original := range originals {
		req.displayNames[alias] = original.name
	}
	converted := req
	converted.Data = string(model.Format(root))
	converted.Format = "clash"
	result := importDirect(converted)
	for _, kind := range []string{"proxy", "rule"} {
		defs := get(originalRoot, kind+"-providers")
		if defs != nil && defs.Kind == yaml.MappingNode {
			for i := 0; i+1 < len(defs.Content); i += 2 {
				name := defs.Content[i].Value
				used := false
				for _, p := range providers {
					if p.Kind == kind && p.Name == name {
						used = true
						break
					}
				}
				path := model.JoinPath("/"+kind+"-providers", name)
				if !used {
					result.Report.Ignored = append(result.Report.Ignored, path)
				} else if get(defs.Content[i+1], "path") != nil {
					result.Report.Ignored = append(result.Report.Ignored, path+"/path")
				}
			}
		}
	}
	if len(result.Source) > 0 {
		var source map[string]json.RawMessage
		_ = json.Unmarshal(result.Source, &source)
		var outbounds []map[string]any
		_ = json.Unmarshal(source["outbounds"], &outbounds)
		for _, out := range outbounds {
			if original, ok := originals[out["name"].(string)]; ok {
				out["name"] = original.name
			}
		}
		source["outbounds"], _ = json.Marshal(outbounds)
		result.Source, _ = json.Marshal(source)
	}
	for i, binding := range result.Report.Bindings {
		if original, ok := originals[binding.Name]; ok {
			result.Report.Bindings[i].Name = original.name
			result.Report.Bindings[i].Provider = original.provider
		}
	}
	return result
}

// Import also resolves inline providers without network or filesystem access.
// HTTP providers require ImportProviders and an already locked resource bundle.
func Import(req Request) Result {
	format := req.Format
	if format == "" || format == "auto" {
		format = detectFormat(req.Data)
	}
	if format == "clash" {
		if ps, err := Providers(req); err == nil && len(ps) > 0 {
			payloads := map[string][]byte{}
			all := true
			for _, p := range ps {
				if p.Type != "inline" {
					all = false
					break
				}
				payloads[p.ID] = p.Inline
			}
			if all {
				result := ImportProviders(req, payloads)
				if len(result.Source) > 0 {
					var src object
					_ = json.Unmarshal(result.Source, &src)
					var defs []object
					for _, p := range ps {
						if p.Kind != "rule" {
							continue
						}
						specs, err := rulesdata.Decode(p.Behavior, p.Format, "", p.Inline)
						if err != nil {
							return invalidBundle(req, err)
						}
						entries := []object{}
						for _, s := range specs {
							entries = append(entries, nativeMatch(s))
						}
						defs = append(defs, object{"id": p.ID, "entries": entries})
					}
					src["rule-sets"] = defs
					result.Source, _ = json.Marshal(src)
				}
				return result
			}
		}
	}
	return importDirect(req)
}
