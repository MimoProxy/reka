package importer

import (
	"encoding/json"
	"github.com/MimoProxy/reka/internal/config/model"
	RD "github.com/MimoProxy/reka/internal/dns"
	"go.yaml.in/yaml/v3"
	"strings"
)

func (c *converter) convertDNS(root *yaml.Node) {
	n := get(root, "dns")
	if empty(n) {
		return
	}
	if get(n, "enable") == nil || text(get(n, "enable")) == "false" {
		c.report.Ignored = append(c.report.Ignored, "/dns")
		return
	}
	if n.Kind != yaml.MappingNode {
		c.unsupported(n, "/dns", "import.dns", "DNS must be a mapping")
		return
	}
	normalized := copyNode(n)
	removeField(normalized, "enable")
	for _, key := range []string{"listen", "prefer-h3"} {
		if get(normalized, key) != nil {
			if key == "listen" || text(get(normalized, key)) == "false" {
				c.report.Ignored = append(c.report.Ignored, "/dns/"+key)
				removeField(normalized, key)
			}
		}
	}
	if get(normalized, "use-hosts") == nil {
		putField(normalized, "use-hosts", &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!bool", Value: "true"})
	}
	if get(normalized, "use-system-hosts") == nil {
		putField(normalized, "use-system-hosts", &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!bool", Value: "true"})
	}
	if get(normalized, "fake-ip-ttl") == nil {
		putField(normalized, "fake-ip-ttl", &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!int", Value: "1"})
	} else if text(get(normalized, "fake-ip-ttl")) == "0" {
		c.unsupported(n, "/dns/fake-ip-ttl", "import.dns", "zero fake-IP TTL is unavailable")
		return
	}
	if get(normalized, "fake-ip-filter") == nil {
		filters := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
		for _, domain := range []string{"dns.msftnsci.com", "www.msftnsci.com", "www.msftconnecttest.com"} {
			filters.Content = append(filters.Content, stringNode(domain))
		}
		putField(normalized, "fake-ip-filter", filters)
	}
	if fallback := get(normalized, "fallback"); fallback != nil && len(fallback.Content) > 0 {
		filter := get(normalized, "fallback-filter")
		if filter == nil {
			filter = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
			putField(normalized, "fallback-filter", filter)
		}
		if get(filter, "geoip") == nil {
			putField(filter, "geoip", &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!bool", Value: "true"})
		}
	}
	if policies := get(normalized, "nameserver-policy"); policies != nil && policies.Kind == yaml.MappingNode {
		list := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
		for i := 0; i+1 < len(policies.Content); i += 2 {
			pattern := policies.Content[i].Value
			server := copyNode(policies.Content[i+1])
			if server.Kind == yaml.ScalarNode {
				server = &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq", Content: []*yaml.Node{server}}
			}
			item := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
			putField(item, "id", stringNode(StableID("dns", pattern)))
			putField(item, "pattern", stringNode(pattern))
			putField(item, "servers", server)
			list.Content = append(list.Content, item)
		}
		putField(normalized, "nameserver-policy", list)
	}
	if hosts := get(root, "hosts"); hosts != nil && hosts.Kind == yaml.MappingNode {
		list := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
		for i := 0; i+1 < len(hosts.Content); i += 2 {
			values := copyNode(hosts.Content[i+1])
			if values.Kind == yaml.ScalarNode {
				values = &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq", Content: []*yaml.Node{values}}
			}
			item := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
			putField(item, "id", copyNode(hosts.Content[i]))
			putField(item, "addresses", values)
			list.Content = append(list.Content, item)
		}
		putField(normalized, "hosts", list)
	}
	missingGeo := false
	var remapPattern func(*yaml.Node)
	remapPattern = func(node *yaml.Node) {
		if node.Kind == yaml.ScalarNode && strings.HasPrefix(node.Value, "geosite:") {
			id := c.req.resourceNames[strings.ToLower(node.Value)]
			if id == "" {
				missingGeo = true
			} else {
				node.Value = "rule-set:" + id
			}
		} else if node.Kind == yaml.ScalarNode && strings.HasPrefix(node.Value, "rule-set:") {
			if id := c.req.resourceNames[strings.TrimPrefix(node.Value, "rule-set:")]; id != "" {
				node.Value = "rule-set:" + id
			}
		}
		for _, v := range node.Content {
			remapPattern(v)
		}
	}
	remapPattern(normalized)
	if filter := get(normalized, "fallback-filter"); filter != nil && text(get(filter, "geoip")) == "true" {
		if fallback := get(normalized, "fallback"); fallback != nil && len(fallback.Content) > 0 {
			code := strings.ToLower(text(get(filter, "geoip-code")))
			if code == "" {
				code = "cn"
			}
			id := c.req.resourceNames["geoip:"+code]
			if id == "" {
				missingGeo = true
			} else {
				putField(filter, "geoip-set", stringNode(id))
			}
		}
	}
	if missingGeo {
		c.unsupported(n, "/dns", "import.dns-reference", "DNS selectors require explicit locked geodata")
		return
	}
	var remap func(*yaml.Node)
	remap = func(node *yaml.Node) {
		if node.Kind == yaml.ScalarNode && strings.Contains(node.Value, "#") {
			endpoint, ref, _ := strings.Cut(node.Value, "#")
			if id, ok := c.target(ref); ok {
				node.Value = endpoint + "#" + id
			}
		}
		for _, v := range node.Content {
			remap(v)
		}
	}
	remap(normalized)
	profile := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	putField(profile, "schema-version", &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!int", Value: "1"})
	putField(profile, "dns", normalized)
	decoded, _, ds := model.ParseProfile(model.Format(profile))
	if ds.HasErrors() {
		for _, d := range ds {
			c.unsupported(n, d.Path, "import.dns-field", d.Message)
		}
		return
	}
	if err := RD.Validate(decoded.DNS); err != nil {
		c.unsupported(n, "/dns", "import.dns", err.Error())
		return
	}
	var result any
	_ = normalized.Decode(&result)
	b, _ := json.Marshal(result)
	var o object
	_ = json.Unmarshal(b, &o)
	c.dns = o
}
func stringNode(s string) *yaml.Node {
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: s}
}
