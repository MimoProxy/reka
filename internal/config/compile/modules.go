package compile

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/MimoProxy/reka/internal/config/model"
	"github.com/MimoProxy/reka/internal/config/module"
	"github.com/MimoProxy/reka/internal/resource"
	"go.yaml.in/yaml/v3"
)

type moduleLayer struct {
	result   *module.Result
	rules    []*yaml.Node
	rewrites map[string][]*yaml.Node
}

type moduleResourceKey struct{ kind, value string }

func validateModuleSnapshot(src model.Source, node *yaml.Node) error {
	for i := 0; i+1 < len(node.Content); i += 2 {
		switch key := node.Content[i].Value; key {
		case "id", "module", "lock":
		default:
			return fmt.Errorf("module source cannot define %s", key)
		}
	}
	if !model.ValidModuleFormat(src.Module.Format) || !resource.ValidHash(src.Module.Request) {
		return errors.New("invalid module format or request identity")
	}
	if src.Lock == nil || !resource.ValidHash(src.Lock.Root) || len(src.Lock.Resources) > model.MaxModuleResources+model.MaxModuleScripts {
		return errors.New("invalid module resource lock")
	}
	requests := map[moduleResourceKey]bool{}
	ids := map[moduleResourceKey]bool{}
	counts := map[string]int{}
	for _, locked := range src.Lock.Resources {
		request := moduleResourceKey{locked.Kind, locked.Request}
		id := moduleResourceKey{locked.Kind, locked.ID}
		if (locked.Kind != "map-local" && locked.Kind != "script") || !idRE.MatchString(locked.ID) || !strings.HasPrefix(locked.Request, locked.ID) ||
			!resource.ValidHash(locked.Request) || !resource.ValidHash(locked.Hash) || requests[request] || ids[id] {
			return errors.New("invalid or duplicate module resource lock")
		}
		requests[request] = true
		ids[id] = true
		counts[locked.Kind]++
	}
	if counts["map-local"] > model.MaxModuleResources || counts["script"] > model.MaxModuleScripts {
		return errors.New("invalid module resource lock")
	}
	return nil
}

type modulePolicies struct {
	ids       map[string]bool
	names     map[string]string
	ambiguous map[string]bool
}

func newModulePolicies() *modulePolicies {
	return &modulePolicies{
		ids:       map[string]bool{"direct": true, "reject": true, "reject-drop": true, "pass": true},
		names:     map[string]string{},
		ambiguous: map[string]bool{},
	}
}

func (p *modulePolicies) add(id, name string) {
	p.ids[id] = true
	if name != "" {
		if other, ok := p.names[name]; ok && other != id {
			p.ambiguous[name] = true
		}
		p.names[name] = id
	}
}

func (p *modulePolicies) resolve(policy string) (string, bool) {
	if p.ids[policy] {
		return policy, true
	}
	if p.ambiguous[policy] {
		return fmt.Sprintf("ambiguous policy name %q; use a stable ID", policy), false
	}
	id, ok := p.names[policy]
	return id, ok
}

// ModulePolicyResolver resolves module policy names against this configuration.
func (e *Effective) ModulePolicyResolver() func(string) (string, bool) {
	p := newModulePolicies()
	for _, o := range e.Outbounds {
		p.add(o.ID, o.Name)
	}
	for _, g := range e.Groups {
		p.add(g.ID, e.GroupMetadata[g.ID].Name)
	}
	return p.resolve
}

func (c *compiler) convertModules(sources map[string]model.Source, targets map[string]*yaml.Node) map[string]moduleLayer {
	if len(c.profile.Modules) == 0 {
		return nil
	}
	policies := newModulePolicies()
	for _, key := range []string{"outbounds", "groups"} {
		for _, node := range targets[key].Content {
			if id := field(node, "id"); id != nil {
				var name string
				if label := field(node, "name"); label != nil {
					name = label.Value
				}
				policies.add(id.Value, name)
			}
		}
	}
	layers := map[string]moduleLayer{}
	for _, def := range c.profile.Modules {
		if !def.IsEnabled() {
			continue
		}
		path := c.modulePaths[def.ID]
		src := sources[def.ID]
		if !def.MatchesSnapshot(src.Module) {
			c.errorf(model.DocProfile, path, "module.download", "module snapshot is missing or the location or format has changed. Refresh the module")
			continue
		}
		if c.opts.ReadResource == nil {
			c.errorf(model.DocProfile, path, "module.resource", "module requires a locked resource reader")
			continue
		}
		text, err := c.opts.ReadResource(src.Lock.Root)
		if err != nil || len(text) > model.MaxDocumentSize || resource.Hash(text) != src.Lock.Root {
			c.errorf(model.DocProfile, path, "module.resource", "locked module text is missing, oversized or corrupt; refresh the module")
			continue
		}
		locked := make(map[moduleResourceKey]string, len(src.Lock.Resources))
		for _, entry := range src.Lock.Resources {
			locked[moduleResourceKey{entry.Kind, entry.Request}] = entry.Hash
		}
		result, report := module.Convert(text, module.Options{
			ID: def.ID, Format: src.Module.Format, Arguments: def.Arguments, Resolve: policies.resolve,
			ResourceForKind: func(kind, url string) (string, bool) {
				hash, ok := locked[moduleResourceKey{kind, resource.Hash([]byte(url))}]
				return hash, ok
			},
		})
		for _, d := range report.Diagnostics {
			if d.Line > 0 {
				d.Message = fmt.Sprintf("module line %d: %s", d.Line, d.Message)
			}
			c.add(d.Severity, model.DocProfile, path, d.Code, "%s", d.Message)
		}
		if !report.CanApply || result == nil {
			continue
		}
		if c.opts.OmitProvenance {
			report.Lines = nil
		}
		if c.moduleReports == nil {
			c.moduleReports = map[string]module.Report{}
		}
		c.moduleReports[def.ID] = report

		identity, _ := json.Marshal(struct {
			ID        string
			Module    *model.ModuleSnapshot
			Lock      *model.SourceLock
			Arguments map[string]string
		}{def.ID, src.Module, src.Lock, def.Arguments})
		digest := resource.Hash(identity)
		c.moduleDigests = append(c.moduleDigests, digest)
		if c.sourceHashes != nil {
			c.sourceHashes[def.ID] = digest
		}
		layers[def.ID] = c.moduleNodes(def.ID, result)
		for _, ref := range result.TailscaleReferences {
			var node yaml.Node
			if err := node.Encode(ref); err != nil {
				c.errorf(model.DocProfile, path, "module.proxy", "cannot encode Tailscale reference")
				continue
			}
			id := def.ID + "/" + ref.ID
			put(&node, "id", scalar(id))
			put(&node, "type", scalar(model.OutboundTailscale))
			targets["outbounds"].Content = append(targets["outbounds"].Content, &node)
			c.scopedIDs[id] = true
			c.origins[model.JoinPath("/outbounds", id)] = moduleOrigin(def.ID, ref.Line)
			policies.add(id, ref.Name)
		}
	}
	return layers
}

func moduleOrigin(id string, line int) Origin {
	return Origin{Layer: LayerModule, Document: model.DocSources, Path: model.JoinPath("/sources", id, "module"), Source: id, Line: line, Column: 1}
}

func (c *compiler) moduleNodes(id string, result *module.Result) moduleLayer {
	layer := moduleLayer{result: result, rewrites: map[string][]*yaml.Node{}}
	record := func(kind, itemID string, n *yaml.Node) {
		scoped := id + "/" + itemID
		put(n, "id", scalar(scoped))
		c.scopedIDs[scoped] = true
		c.origins[model.JoinPath("", kind, scoped)] = moduleOrigin(id, result.ItemLines[itemID])
	}
	for _, rule := range result.Rules {
		n := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		record("rules", rule.ID, n)
		put(n, "syntax", scalar(rule.Syntax))
		put(n, "outbound", scalar(rule.Outbound))
		put(n, "match", moduleMatchNode(rule.Match))
		layer.rules = append(layer.rules, n)
	}
	appendRewrite := func(kind, itemID string, value any) {
		var node yaml.Node
		if err := node.Encode(value); err != nil {
			c.errorf(model.DocProfile, c.modulePaths[id], "module.rewrite", "cannot encode module rewrite")
			return
		}
		record(kind, itemID, &node)
		layer.rewrites[kind] = append(layer.rewrites[kind], &node)
	}
	for _, item := range result.HTTPRewrites {
		appendRewrite("http-rewrites", item.ID, item)
	}
	for _, item := range result.HeaderRewrites {
		appendRewrite("header-rewrites", item.ID, item)
	}
	for _, item := range result.BodyRewrites {
		appendRewrite("body-rewrites", item.ID, item)
	}
	for _, item := range result.MapLocal {
		appendRewrite("map-local", item.ID, item)
	}
	for _, item := range result.Scripts {
		appendRewrite("scripts", item.ID, item)
	}
	return layer
}

func moduleMatchNode(match model.Match) *yaml.Node {
	node := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	values := sequence()
	for _, value := range match.Values {
		values.Content = append(values.Content, scalar(value))
	}
	for _, child := range match.Children {
		values.Content = append(values.Content, moduleMatchNode(child))
	}
	if match.Kind == "all" {
		put(node, "all", &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!bool", Value: "true"})
	} else {
		put(node, match.Kind, values)
	}
	if match.NoResolve {
		put(node, "no-resolve", &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!bool", Value: "true"})
	}
	return node
}
