package compile

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/MimoProxy/reka/internal/config/model"
	"go.yaml.in/yaml/v3"
)

const mitmHostnamePath = "/mitm/hostnames"

var mitmOverrides = []string{"h2", "skip-server-cert-verify", "quic-block", "client-source-address"}

func (c *compiler) mergeRewrites(root *yaml.Node, sources map[string]*yaml.Node, imports []string, positions model.Positions, modules map[string]moduleLayer, importItem func(string, string, *yaml.Node) *yaml.Node) {
	for _, kind := range rewriteKinds {
		merged := sequence()
		index := map[string]int{}
		for _, def := range c.profile.Modules {
			for _, item := range modules[def.ID].rewrites[kind] {
				index[field(item, "id").Value] = len(merged.Content)
				merged.Content = append(merged.Content, item)
			}
		}
		for _, src := range imports {
			if list := field(sources[src], kind); list != nil {
				for _, item := range list.Content {
					imported := importItem(src, kind, item)
					index[field(imported, "id").Value] = len(merged.Content)
					merged.Content = append(merged.Content, imported)
				}
			}
		}
		if len(merged.Content) == 0 {
			continue
		}
		if local := field(root, kind); local != nil {
			for _, item := range local.Content {
				id := field(item, "id")
				if id != nil {
					if at, ok := index[id.Value]; ok {
						path := model.JoinPath("", kind, id.Value)
						c.overrideRewriteOrigins(path, merged.Content[at], item)
						merged.Content[at] = item
						delete(index, id.Value)
						continue
					}
				}
				merged.Content = append(merged.Content, item)
			}
		}
		put(root, kind, merged)
	}
	c.mergeMITM(root, sources, imports, positions, modules)
}

func (c *compiler) overrideRewriteOrigins(path string, imported, local *yaml.Node) {
	previous := map[string]Origin{}
	walkNodePaths(imported, path, func(p string) {
		if origin, ok := c.origins[p]; ok {
			previous[p] = origin
			delete(c.origins, p)
		}
	})
	walkNodePaths(local, path, func(p string) {
		pos := c.ppos[p]
		o := Origin{Layer: LayerProfile, Document: model.DocProfile, Path: p, Line: pos.Line, Column: pos.Column}
		if old, ok := originAt(previous, p); ok {
			o.Overrides = &old
		}
		c.origins[p] = o
	})
}

func walkNodePaths(node *yaml.Node, path string, visit func(string)) {
	visit(path)
	switch node.Kind {
	case yaml.MappingNode:
		for i := 0; i+1 < len(node.Content); i += 2 {
			walkNodePaths(node.Content[i+1], model.JoinPath(path, node.Content[i].Value), visit)
		}
	case yaml.SequenceNode:
		for i, child := range node.Content {
			walkNodePaths(child, model.JoinPath(path, model.ElementSegment(child, i)), visit)
		}
	}
}

func (c *compiler) mergeMITM(root *yaml.Node, sources map[string]*yaml.Node, imports []string, positions model.Positions, modules map[string]moduleLayer) {
	local := field(root, "mitm")
	merged := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	hosts := sequence()
	profileHosts := field(local, "hostnames")
	profileHostOrigins := c.hostnameOrigins(profileHosts)
	for i := range len(profileHostOrigins) {
		delete(c.origins, model.JoinPath(mitmHostnamePath, "#"+strconv.Itoa(i)))
	}
	appendHost := func(entry *yaml.Node, origin Origin) {
		if _, ok := c.origins[mitmHostnamePath]; !ok {
			c.origins[mitmHostnamePath] = origin
		}
		dest := model.JoinPath(mitmHostnamePath, "#"+strconv.Itoa(len(hosts.Content)))
		c.origins[dest] = origin
		hosts.Content = append(hosts.Content, entry)
	}
	for _, def := range c.profile.Modules {
		if m := modules[def.ID].result; m != nil {
			for _, host := range m.InsertHostnames {
				appendHost(scalar(host.Value), moduleOrigin(def.ID, host.Line))
			}
		}
	}
	if profileHosts != nil {
		for _, entry := range profileHosts.Content {
			appendHost(entry, profileHostOrigins[entry])
		}
	}
	setSwitch := func(name string, value *yaml.Node, origin Origin) {
		path := model.JoinPath("/mitm", name)
		if field(merged, name) != nil {
			previous := c.origins[path]
			origin.Overrides = &previous
		}
		c.origins[path] = origin
		put(merged, name, value)
	}
	sourceOrigin := func(id, path string) Origin {
		p := model.JoinPath("/sources", id) + path
		pos := positions[p]
		return Origin{Layer: LayerSource, Source: id, Document: model.DocSources, Path: p, Line: pos.Line, Column: pos.Column}
	}
	for _, id := range imports {
		mitm := field(sources[id], "mitm")
		if mitm == nil || mitm.Kind != yaml.MappingNode {
			continue
		}
		if _, ok := c.origins["/mitm"]; !ok {
			c.origins["/mitm"] = sourceOrigin(id, "/mitm")
		}
		if list := field(mitm, "hostnames"); list != nil && list.Kind == yaml.SequenceNode {
			if _, ok := c.origins[mitmHostnamePath]; !ok {
				c.origins[mitmHostnamePath] = sourceOrigin(id, mitmHostnamePath)
			}
			for i, entry := range list.Content {
				path := model.JoinPath(mitmHostnamePath, "#"+strconv.Itoa(i))
				appendHost(entry, sourceOrigin(id, path))
			}
		}
		for _, name := range mitmOverrides {
			value := field(mitm, name)
			if value == nil || value.Tag == "!!null" {
				continue
			}
			path := model.JoinPath("/mitm", name)
			setSwitch(name, value, sourceOrigin(id, path))
		}
	}
	for _, def := range c.profile.Modules {
		m := modules[def.ID].result
		if m == nil {
			continue
		}
		for _, host := range m.AppendHostnames {
			appendHost(scalar(host.Value), moduleOrigin(def.ID, host.Line))
		}
		for _, opt := range []struct {
			name  string
			value *bool
		}{{"h2", m.MITM.H2}, {"skip-server-cert-verify", m.MITM.SkipServerCertVerify}} {
			if opt.value != nil {
				origin := moduleOrigin(def.ID, m.MITMLines[opt.name])
				value := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!bool", Value: strconv.FormatBool(*opt.value)}
				setSwitch(opt.name, value, origin)
			}
		}
	}
	for _, name := range mitmOverrides {
		if value := field(local, name); value != nil && value.Tag != "!!null" {
			path := model.JoinPath("/mitm", name)
			pos := c.ppos[path]
			setSwitch(name, value, Origin{Layer: LayerProfile, Document: model.DocProfile, Path: path, Line: pos.Line, Column: pos.Column})
		}
	}
	if _, ok := c.origins[mitmHostnamePath]; ok {
		put(merged, "hostnames", hosts)
	}
	if origin := c.origins[mitmClientSourcePath]; origin.Layer == LayerSource {
		walkNodePaths(field(merged, "client-source-address"), mitmClientSourcePath, func(path string) {
			if path != mitmClientSourcePath {
				c.origins[path] = sourceOrigin(origin.Source, path)
			}
		})
	}
	if len(merged.Content) != 0 {
		if _, ok := c.origins["/mitm"]; !ok {
			if o, ok := c.origins[mitmHostnamePath]; ok {
				c.origins["/mitm"] = o
			} else {
				for _, name := range mitmOverrides {
					if o, ok := c.origins[model.JoinPath("/mitm", name)]; ok {
						c.origins["/mitm"] = o
						break
					}
				}
			}
		}
		put(root, "mitm", merged)
	}
}

func validateMITMOverlay(op model.Op, path []string) error {
	if op.Op == "insert" {
		if op.Path != mitmHostnamePath {
			return fmt.Errorf("MITM insert targets %s", mitmHostnamePath)
		}
		value, err := model.JSONToNode(op.Value)
		if err != nil || value.Kind != yaml.ScalarNode || value.Tag != "!!str" {
			return fmt.Errorf("inserted MITM hostname must be a string")
		}
		return nil
	}
	if len(path) <= 2 {
		return nil
	}
	if len(path) == 3 && path[1] == "hostnames" {
		if index, ok := strings.CutPrefix(path[2], "#"); ok {
			if i, err := strconv.Atoi(index); err == nil && i >= 0 && strconv.Itoa(i) == index {
				return nil
			}
		}
	}
	return fmt.Errorf("MITM overlays edit a setting or identify a hostname by its #index")
}

func (c *compiler) hostnameOrigins(list *yaml.Node) map[*yaml.Node]Origin {
	origins := map[*yaml.Node]Origin{}
	if list != nil && list.Kind == yaml.SequenceNode {
		for i, node := range list.Content {
			origins[node] = c.origins[model.JoinPath(mitmHostnamePath, "#"+strconv.Itoa(i))]
		}
	}
	return origins
}

// Positional overlays shift later hostnames. Keep their origins tied to the
// original nodes so diagnostics still point to the correct document and line.
func (c *compiler) reindexHostnameOrigins(list *yaml.Node, old map[*yaml.Node]Origin) string {
	for i := range len(old) {
		delete(c.origins, model.JoinPath(mitmHostnamePath, "#"+strconv.Itoa(i)))
	}
	var inserted string
	for i, node := range list.Content {
		path := model.JoinPath(mitmHostnamePath, "#"+strconv.Itoa(i))
		if origin, ok := old[node]; ok {
			c.origins[path] = origin
		} else {
			inserted = path
		}
	}
	return inserted
}
