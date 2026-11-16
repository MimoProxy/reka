package importer

import (
	"github.com/MimoProxy/reka/internal/router"
	"go.yaml.in/yaml/v3"
	"strings"
)

func ensureGlobalGroup(root *yaml.Node, proxies, groups []*yaml.Node) []*yaml.Node {
	for _, g := range groups {
		if text(get(g, "name")) == "GLOBAL" {
			return groups
		}
	}
	used := false
	var walk func(*yaml.Node)
	walk = func(n *yaml.Node) {
		if n == nil {
			return
		}
		n = deref(n)
		if n.Kind == yaml.ScalarNode {
			if n.Value == "GLOBAL" || strings.HasSuffix(n.Value, "#GLOBAL") {
				used = true
			}
			if rule, _, err := router.ParseClashRule(n.Value); err == nil && rule.Target == "GLOBAL" {
				used = true
			}
		}
		for _, ch := range n.Content {
			walk(ch)
		}
	}
	walk(root)
	if !used {
		return groups
	}
	members := []string{"DIRECT", "REJECT"}
	for _, p := range proxies {
		members = append(members, text(get(p, "name")))
	}
	for _, g := range groups {
		members = append(members, text(get(g, "name")))
	}
	generated := &yaml.Node{}
	_ = generated.Encode(object{"name": "GLOBAL", "type": "select", "proxies": members})
	return append(groups, generated)
}
