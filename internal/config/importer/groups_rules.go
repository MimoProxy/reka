package importer

import (
	"encoding/json"
	"fmt"
	"github.com/dlclark/regexp2"
	"slices"
	"strings"

	"github.com/MimoProxy/reka/internal/policy"
	"github.com/MimoProxy/reka/internal/router"
	"go.yaml.in/yaml/v3"
)

func (c *converter) target(name string) (string, bool) {
	switch name {
	case "DIRECT", "COMPATIBLE":
		return "direct", true
	case "REJECT":
		return "reject", true
	case "PASS":
		return "pass", true
	case "REJECT-DROP":
		return "reject-drop", true
	}
	return c.names[name], c.available[name]
}
func (c *converter) convertGroups(input []*yaml.Node) {
	type group struct {
		node       *yaml.Node
		path, name string
		members    []string
		native     object
		bad        bool
	}
	groups := make([]*group, 0, len(input))
	byName := map[string]*group{}
	for i, n := range input {
		n = deref(n)
		path := fmt.Sprintf("/proxy-groups/#%d", i)
		r := proxyReader{c: c, n: n, path: path}
		name := r.str("name")
		g := &group{node: n, path: path, name: name, native: object{"id": c.names[name], "name": name, "type": r.str("type")}}
		groups = append(groups, g)
		byName[name] = g
		if !slices.Contains([]string{"select", "url-test", "fallback", "load-balance"}, r.str("type")) {
			message := "unsupported group type"
			if r.str("type") == "relay" {
				message = "relay was removed from the pinned reference; use dialer-proxy on nodes"
			}
			r.fail("type", "import.group-type", message)
		}
		for j := 0; j+1 < len(n.Content); j += 2 {
			key := n.Content[j].Value
			if !slices.Contains([]string{"name", "type", "proxies", "icon", "url", "interval", "timeout", "tolerance", "lazy", "strategy", "filter", "exclude-filter", "include-all", "include-all-proxies", "include-all-providers", "disable-udp", "expected-status"}, key) {
				r.fail(key, "import.unsupported-field", "group option is not supported")
			}
		}
		if icon := get(n, "icon"); icon != nil {
			g.native["icon"] = r.str("icon")
		}
		for _, key := range []string{"url", "interval", "timeout", "tolerance", "lazy", "strategy", "disable-udp", "expected-status"} {
			if v := get(n, key); v != nil {
				var raw any
				_ = v.Decode(&raw)
				g.native[key] = raw
			}
		}
		if _, err := policy.ParseExpectedStatus(r.str("expected-status")); err != nil {
			r.fail("expected-status", "import.group-health", "invalid HTTP status ranges")
		}
		if r.str("expected-status") == "" {
			g.native["expected-status"] = "*"
		}
		members := get(n, "proxies")
		includeRoot := r.boolean("include-all", false) || r.boolean("include-all-proxies", false)
		includeProviders := r.boolean("include-all", false) || r.boolean("include-all-providers", false)
		include := includeRoot || includeProviders
		if empty(members) && include {
			members = &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
		}

		if members == nil || members.Kind != yaml.SequenceNode {
			r.fail("proxies", "import.group-members", "group requires an explicit list of members")
		} else {
			seen := map[string]bool{}
			for _, m := range members.Content {
				m = deref(m)
				if m.Kind != yaml.ScalarNode || m.Tag != "!!str" {
					r.fail("proxies", "import.type", "group members must be names")
					continue
				}
				if seen[m.Value] {
					continue
				}
				seen[m.Value] = true
				g.members = append(g.members, m.Value)
				if _, exists := c.names[m.Value]; !exists && m.Value != "DIRECT" && m.Value != "REJECT" && m.Value != "PASS" && m.Value != "COMPATIBLE" && m.Value != "REJECT-DROP" {
					r.fail("proxies", "import.group-reference", "unknown group member")
				}
			}
		}
		if include {
			for _, out := range c.nodes {
				name := out["name"].(string)
				_, provider := c.req.displayNames[name]
				if provider && !includeProviders || !provider && !includeRoot {
					continue
				}
				if !slices.Contains(g.members, name) {
					g.members = append(g.members, name)
				}
			}
		}

		var filters, excludes []*regexp2.Regexp
		for _, field := range []string{"filter", "exclude-filter"} {
			value := r.str(field)
			if value == "" {
				continue
			}
			for _, part := range strings.Split(value, "`") {
				pattern, err := providerRegex(part)
				if err != nil {
					r.fail(field, "import.group-filter", "invalid filter regex")
					continue
				}
				if field == "filter" {
					filters = append(filters, pattern)
				} else {
					excludes = append(excludes, pattern)
				}
			}
		}
		if len(filters) == 0 {
			filters = append(filters, nil)
		}
		selected := []string{}
		seen := map[string]bool{}
		for _, filter := range filters {
			for _, name := range g.members {
				if seen[name] {
					continue
				}
				display := name
				if original := c.req.displayNames[name]; original != "" {
					display = original
				}
				excluded := false
				for _, pattern := range excludes {
					matched, err := pattern.MatchString(display)
					if err != nil {
						r.fail("exclude-filter", "import.group-filter", "filter match budget exceeded")
						excluded = true
					}
					excluded = excluded || matched
				}
				if excluded {
					continue
				}
				if filter != nil {
					matched, err := filter.MatchString(display)
					if err != nil {
						r.fail("filter", "import.group-filter", "filter match budget exceeded")
					}
					if err != nil || !matched {
						continue
					}
				}
				seen[name] = true
				selected = append(selected, name)
			}
		}
		g.members = selected

		g.bad = r.bad
	}
	// Identify cycles before pruning; never choose a cyclic group's other
	// member to hide an invalid reference graph.
	state := map[string]int{}
	stack := []*group{}
	var visit func(*group)
	visit = func(g *group) {
		if state[g.name] == 2 {
			return
		}
		if state[g.name] == 1 {
			for i := len(stack) - 1; i >= 0; i-- {
				stack[i].bad = true
				c.unsupported(stack[i].node, stack[i].path, "import.group-cycle", "group participates in a reference cycle")
				if stack[i] == g {
					break
				}
			}
			return
		}
		state[g.name] = 1
		stack = append(stack, g)
		for _, name := range g.members {
			if next := byName[name]; next != nil {
				visit(next)
			}
		}
		stack = stack[:len(stack)-1]
		state[g.name] = 2
	}
	for _, g := range groups {
		visit(g)
	}
	for _, g := range groups {
		if !g.bad {
			c.available[g.name] = true
		}
	}
	// Empty groups can make their parents empty too. This fixed point only
	// removes availability, independent of input order.
	for changed := true; changed; {
		changed = false
		for _, g := range groups {
			if !c.available[g.name] {
				continue
			}
			count := 0
			for _, m := range g.members {
				if _, ok := c.target(m); ok {
					count++
				}
			}
			if count == 0 {
				delete(c.available, g.name)
				changed = true
			}
		}
	}
	for _, g := range groups {
		available := c.available[g.name]
		c.report.Bindings = append(c.report.Bindings, Binding{Kind: "group", Name: g.name, ID: c.names[g.name], Available: available})
		if !available {
			if !g.bad {
				c.unsupported(g.node, g.path, "import.group-empty", "group has no supported members")
			}
			continue
		}
		members := []string{}
		for _, name := range g.members {
			if id, ok := c.target(name); ok {
				members = append(members, id)
			} else {
				c.unsupported(get(g.node, "proxies"), g.path+"/proxies", "import.member-unavailable", "unsupported member was excluded; review the resulting group before applying")
			}
		}
		g.native["members"] = members
		if g.native["type"] == "select" {
			g.native["selected"] = members[0]
		}
		c.groups = append(c.groups, g.native)
	}
}

func splitRule(s string) ([]string, bool) {
	p, err := router.SplitClash(s)
	return p, err == nil
}

func nativeMatch(spec router.RuleSpec) object {
	m := object{}
	if spec.Kind == router.KindMatch {
		m["all"] = true
	} else if spec.Kind == router.KindAnd || spec.Kind == router.KindOr || spec.Kind == router.KindNot {
		children := []object{}
		for _, ch := range spec.Children {
			children = append(children, nativeMatch(ch))
		}
		m[spec.Kind.String()] = children
	} else {
		m[spec.Kind.String()] = spec.Values
	}
	if spec.NoResolve {
		m["no-resolve"] = true
	}
	return m
}
func (c *converter) resolveRule(spec *router.RuleSpec) error {
	if spec.Kind == router.KindRuleSet {
		id := c.req.resourceNames[spec.Values[0]]
		if id == "" {
			return fmt.Errorf("rule-set or geodata resource is not available")
		}
		spec.Values = []string{id}
	}
	for i := range spec.Children {
		if err := c.resolveRule(&spec.Children[i]); err != nil {
			return err
		}
	}
	return nil
}
func (c *converter) convertRuleList(input []*yaml.Node, path string) []object {
	duplicates := map[string]int{}
	var rules []object
	for i, node := range input {
		n := deref(node)
		p := fmt.Sprintf("%s/#%d", path, i)
		fail := func(code, msg string) { c.unsupported(n, p, code, msg) }
		if n.Kind != yaml.ScalarNode || n.Tag != "!!str" {
			fail("import.rule-type", "rule must be a string")
			continue
		}
		spec, call, err := router.ParseClashRule(n.Value)
		if err != nil {
			fail("import.rule-unsupported", err.Error())
			continue
		}
		if err = c.resolveRule(&spec); err != nil {
			fail("import.rule-reference", err.Error())
			continue
		}
		rule := object{"match": nativeMatch(spec)}
		if call != "" {
			id := c.blockNames[call]
			if id == "" {
				fail("import.sub-rule-reference", "unknown sub-rule block")
				continue
			}
			rule["call"] = id
		} else {
			target, ok := c.target(spec.Target)
			if !ok {
				fail("import.rule-target", "rule target is unknown or unavailable")
				continue
			}
			rule["outbound"] = target
		}
		canonical, _ := json.Marshal(rule)
		id := StableID("r", string(canonical))
		duplicates[id]++
		if duplicates[id] > 1 {
			id += fmt.Sprintf("-%d", duplicates[id])
		}
		rule["id"] = id
		rules = append(rules, rule)
	}
	return rules
}
func (c *converter) convertRuleBlocks(root *yaml.Node, input []*yaml.Node) {
	c.blockNames = map[string]string{}
	defs := get(root, "sub-rules")
	if !empty(defs) {
		if defs.Kind != yaml.MappingNode {
			c.diag(defs, "/sub-rules", "import.sub-rule-type", "sub-rules must be a mapping", true)
			return
		}
		for i := 0; i+1 < len(defs.Content); i += 2 {
			c.blockNames[defs.Content[i].Value] = StableID("sub", defs.Content[i].Value)
		}
		for i := 0; i+1 < len(defs.Content); i += 2 {
			name, n := defs.Content[i].Value, deref(defs.Content[i+1])
			if n.Kind != yaml.SequenceNode {
				c.diag(n, "/sub-rules", "import.sub-rule-type", "sub-rule block must be a list", true)
				continue
			}
			rules := c.convertRuleList(n.Content, "/sub-rules/"+name)
			c.subRules = append(c.subRules, object{"id": c.blockNames[name], "rules": rules})
		}
		blocks := map[string][]object{}
		for _, b := range c.subRules {
			blocks[b["id"].(string)] = b["rules"].([]object)
		}
		state := map[string]int{}
		heights := map[string]int{}
		var visit func(string, int) bool
		visit = func(id string, depth int) bool {
			if state[id] == 1 || depth > 32 {
				return false
			}
			if state[id] == 2 {
				return depth+heights[id] <= 32
			}
			state[id] = 1
			height := 1
			for _, r := range blocks[id] {
				if call, ok := r["call"].(string); ok {
					if !visit(call, depth+1) {
						return false
					}
					height = max(height, 1+heights[call])
				}
			}
			heights[id] = height
			state[id] = 2
			return height <= 32
		}
		for _, b := range c.subRules {
			if !visit(b["id"].(string), 0) {
				c.diag(defs, "/sub-rules", "import.sub-rule-cycle", "sub-rule cycle or depth exceeds limit", true)
				break
			}
		}
	}
	c.rules = c.convertRuleList(input, "/rules")
}
