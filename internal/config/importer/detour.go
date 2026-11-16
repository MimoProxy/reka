package importer

import (
	"encoding/json"
	"github.com/MimoProxy/reka/internal/config/compile"
	"go.yaml.in/yaml/v3"
)

func (c *converter) validateDetourGraph() {
	data, _ := json.Marshal(object{"schema-version": 1, "outbounds": c.nodes, "groups": c.groups})
	_, ds := compile.Compile(data, nil, compile.Options{ProcessLookup: true})
	for _, d := range ds {
		if d.Code == "outbound.detour" {
			c.diag(nil, "/proxies", "import.dialer-proxy", "invalid or cyclic dialer dependency graph", true)
			return
		}
	}
}
func detourOnlyGroups(root *yaml.Node, proxies []*yaml.Node) []*yaml.Node {
	input := get(root, "proxy-groups")
	var content []*yaml.Node
	if input != nil && input.Kind == yaml.SequenceNode {
		content = input.Content
	}
	all := ensureGlobalGroup(root, proxies, content)
	byName := map[string]*yaml.Node{}
	for _, g := range all {
		byName[text(get(g, "name"))] = g
	}
	needed := map[string]bool{}
	var visit func(string)
	visit = func(name string) {
		g := byName[name]
		if g == nil || needed[name] {
			return
		}
		needed[name] = true
		members := get(g, "proxies")
		if members != nil {
			for _, member := range members.Content {
				visit(text(member))
			}
		}
	}
	for _, p := range proxies {
		visit(text(get(p, "dialer-proxy")))
	}
	result := []*yaml.Node{}
	for _, g := range all {
		if needed[text(get(g, "name"))] {
			result = append(result, g)
		}
	}
	return result
}
