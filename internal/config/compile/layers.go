package compile

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/MimoProxy/reka/internal/config/model"
	RD "github.com/MimoProxy/reka/internal/dns"
	"github.com/MimoProxy/reka/internal/resource"
	"go.yaml.in/yaml/v3"
)

const (
	LayerSource  = "source"
	LayerOverlay = "overlay"
)

func nodeCopy(n *yaml.Node) *yaml.Node {
	if n.Kind == yaml.AliasNode {
		return nodeCopy(n.Alias)
	}
	v := *n
	v.Alias = nil
	v.Content = nil
	for _, ch := range n.Content {
		v.Content = append(v.Content, nodeCopy(ch))
	}
	return &v
}

func field(n *yaml.Node, key string) *yaml.Node {
	if n == nil {
		return nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1]
		}
	}
	return nil
}

func put(n *yaml.Node, key string, value *yaml.Node) {
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			n.Content[i+1] = value
			return
		}
	}
	n.Content = append(n.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, value)
}

func scalar(s string) *yaml.Node { return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: s} }
func sequence() *yaml.Node       { return &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"} }

// layers constructs a private node tree. The four input documents are never
// mutated, and all runtime validation still goes through the profile compiler.
func (c *compiler) layers(profile []byte) {
	sources, spos, sd := model.ParseSources(c.opts.Sources)
	overlay, opos, od := model.ParseOverlay(c.opts.Overlay)
	c.diags = append(c.diags, sd...)
	c.diags = append(c.diags, od...)
	if c.diags.HasErrors() {
		return
	}
	c.origins = map[string]Origin{}
	c.scopedIDs = map[string]bool{}
	for p, pos := range c.ppos {
		c.origins[p] = Origin{Layer: LayerProfile, Document: model.DocProfile, Path: p, Line: pos.Line, Column: pos.Column}
	}
	addDiag := func(doc, path, code, message string, positions model.Positions) {
		pos := positions[path]
		c.diags = append(c.diags, model.Diagnostic{
			Severity: model.SeverityError,
			Code:     code,
			Document: doc,
			Path:     path,
			Line:     pos.Line,
			Column:   pos.Column,
			Message:  message,
		})
	}
	sourceDoc, _ := model.LoadDoc(model.DocSources, c.opts.Sources)
	doc, _ := model.LoadDoc(model.DocProfile, profile)
	*doc.Mapping() = *nodeCopy(doc.Mapping())
	byID := map[string]*yaml.Node{}
	c.sourceHashes = map[string]string{}
	resourcePositions := map[string]model.Positions{}
	for path, pos := range spos {
		parts, err := model.SplitPath(path)
		if err != nil || len(parts) < 4 || parts[0] != "sources" {
			continue
		}
		prefix := model.JoinPath("", parts[:4]...)
		if resourcePositions[prefix] == nil {
			resourcePositions[prefix] = model.Positions{}
		}
		resourcePositions[prefix][path] = pos
	}
	localTargets := map[string]map[string]bool{}
	for i, src := range sources.Sources {
		path := model.JoinPath("/sources", seg(src.ID, i))
		if !idRE.MatchString(src.ID) {
			addDiag(model.DocSources, path+"/id", "source.id", "source id must be a native stable ID", spos)
			continue
		}
		if byID[src.ID] != nil {
			addDiag(model.DocSources, path+"/id", "source.duplicate", "duplicate source id", spos)
			continue
		}
		if err := model.ValidSubscription(src.Subscription); err != nil {
			addDiag(model.DocSources, path+"/subscription", "source.subscription", err.Error(), spos)
		}
		if src.Lock != nil {
			seen := map[string]bool{}
			rootFound := false
			if !resource.ValidHash(src.Lock.Root) || len(src.Lock.Resources) > 20 {
				addDiag(model.DocSources, path+"/lock", "source.lock", "invalid resource lock", spos)
			}
			for _, lock := range src.Lock.Resources {
				if lock.ID == "root" && lock.Hash == src.Lock.Root {
					rootFound = true
				}
				if lock.ID == "" || seen[lock.ID] || !resource.ValidHash(lock.Hash) || !resource.ValidHash(lock.Request) {
					addDiag(model.DocSources, path+"/lock", "source.lock", "invalid or duplicate resource lock", spos)
				}
				seen[lock.ID] = true
			}
			if !rootFound {
				addDiag(model.DocSources, path+"/lock", "source.lock", "root resource is not locked", spos)
			}
		}
		n := nodeCopy(sourceDoc.Get(model.JoinPath("/sources", seg("", i))))
		byID[src.ID] = n
		localTargets[src.ID] = map[string]bool{}
		sum := sha256.Sum256(model.Format(n))
		c.sourceHashes[src.ID] = hex.EncodeToString(sum[:])
		// Require stable IDs before namespacing. Anonymous source rules would
		// otherwise change identity whenever the subscription reorders them.
		for _, kind := range []string{"outbounds", "groups", "rules", "rule-sets", "sub-rules"} {
			items := field(n, kind)
			if items == nil {
				continue
			}
			seen := map[string]bool{}
			for i, item := range items.Content {
				id := field(item, "id")
				p := model.JoinPath(path, kind, model.ElementSegment(item, i))
				if id == nil || !idRE.MatchString(id.Value) {
					addDiag(model.DocSources, p, "source.id", "source resources require native stable IDs", spos)
					continue
				}
				if seen[id.Value] {
					addDiag(model.DocSources, p+"/id", "schema.duplicate-id", "duplicate source resource id", spos)
				}
				seen[id.Value] = true
				if kind == "outbounds" || kind == "groups" {
					localTargets[src.ID][id.Value] = true
				}
				if field(item, "source") != nil {
					addDiag(model.DocSources, p+"/source", "source.nested", "a normalized source cannot import another source", spos)
				}
			}
		}
	}
	if c.diags.HasErrors() {
		return
	}
	copyOrigins := func(srcID, kind, oldID, newID string) {
		old := model.JoinPath("/sources", srcID, kind, oldID)
		dest := model.JoinPath("", kind, newID)
		for p, pos := range resourcePositions[old] {
			if p == old || strings.HasPrefix(p, old+"/") {
				c.origins[dest+strings.TrimPrefix(p, old)] = Origin{
					Layer:    LayerSource,
					Source:   srcID,
					Document: model.DocSources,
					Path:     p,
					Line:     pos.Line,
					Column:   pos.Column,
				}
			}
		}
	}
	// A source reference is always local to that source, except for built-in
	// direct/reject when the snapshot does not declare them explicitly.
	scoped := func(srcID, ref string) string {
		if ref == "" {
			return ""
		}
		declared := localTargets[srcID][ref]
		if !declared && (ref == "direct" || ref == "reject" || ref == "pass" || ref == "reject-drop") {
			return ref
		}
		return srcID + "/" + ref
	}
	var rewrite func(string, *yaml.Node)
	rewrite = func(srcID string, n *yaml.Node) {
		if n.Kind == yaml.MappingNode {
			for i := 0; i+1 < len(n.Content); i += 2 {
				key, val := n.Content[i].Value, n.Content[i+1]
				switch key {
				case "rule-set":
					if val.Kind == yaml.ScalarNode {
						val.Value = srcID + "/" + val.Value
					} else {
						for _, v := range val.Content {
							v.Value = srcID + "/" + v.Value
						}
					}
				case "call", "to":
					val.Value = srcID + "/" + val.Value
				case "proxy":
					val.Value = scoped(srcID, val.Value)
				case "outbound":
					val.Value = scoped(srcID, val.Value)
				default:
					rewrite(srcID, val)
				}
			}
		} else {
			for _, ch := range n.Content {
				rewrite(srcID, ch)
			}
		}
	}
	importItem := func(srcID, kind string, item *yaml.Node) *yaml.Node {
		n := nodeCopy(item)
		oldID := field(n, "id").Value
		id := srcID + "/" + oldID
		put(n, "id", scalar(id))
		c.scopedIDs[id] = true
		switch kind {
		case "outbounds":
			if dialer := field(n, "dialer"); dialer != nil {
				if proxy := field(dialer, "proxy"); proxy != nil {
					proxy.Value = scoped(srcID, proxy.Value)
				}
			}
		case "groups":
			if members := field(n, "members"); members != nil {
				for _, m := range members.Content {
					m.Value, m.Tag = scoped(srcID, m.Value), "!!str"
				}
			}
			if selected := field(n, "selected"); selected != nil {
				selected.Value, selected.Tag = scoped(srcID, selected.Value), "!!str"
			}
		case "rules", "rule-sets", "sub-rules":
			rewrite(srcID, n)
		}
		copyOrigins(srcID, kind, oldID, id)
		return n
	}
	resourceImports := map[string]bool{}
	includeResources := func(srcID string, ruleSets, subRules bool) {
		src := byID[srcID]
		if src == nil {
			return
		}
		for _, kind := range []string{"rule-sets", "sub-rules"} {
			key := srcID + "/" + kind
			if resourceImports[key] || kind == "rule-sets" && !ruleSets || kind == "sub-rules" && !subRules {
				continue
			}
			resourceImports[key] = true
			dest := field(doc.Mapping(), kind)
			if dest == nil {
				dest = sequence()
				put(doc.Mapping(), kind, dest)
			}
			if items := field(src, kind); items != nil {
				for _, item := range items.Content {
					imported := importItem(srcID, kind, item)
					id := field(imported, "id").Value
					overridden := false
					for _, local := range dest.Content {
						if v := field(local, "id"); v != nil && v.Value == id {
							overridden = true
							break
						}
					}
					if overridden {
						prefix := model.JoinPath("", kind, id)
						previous := map[string]Origin{}
						for path, o := range c.origins {
							if path == prefix || strings.HasPrefix(path, prefix+"/") {
								previous[path] = o
								delete(c.origins, path)
							}
						}
						for path, pos := range c.ppos {
							if path == prefix || strings.HasPrefix(path, prefix+"/") {
								old := previous[path]
								c.origins[path] = Origin{Layer: LayerProfile, Document: model.DocProfile, Path: path, Line: pos.Line, Column: pos.Column, Overrides: &old}
							}
						}
					} else {
						dest.Content = append(dest.Content, imported)
					}
				}
			}
		}
	}
	if cfg := field(doc.Mapping(), "dns"); cfg != nil {
		if from := field(cfg, "from"); from != nil {
			src := byID[from.Value]
			sourceDNS := field(src, "dns")
			if sourceDNS == nil {
				addDiag(model.DocProfile, "/dns/from", "dns.source", "source has no DNS snapshot", c.ppos)
			} else {
				mergedDNS := nodeCopy(sourceDNS)
				sourcePrefix := model.JoinPath("/sources", from.Value, "dns")
				for path := range c.origins {
					if path == "/dns" || strings.HasPrefix(path, "/dns/") {
						delete(c.origins, path)
					}
				}
				for path, pos := range spos {
					if path == sourcePrefix || strings.HasPrefix(path, sourcePrefix+"/") {
						c.origins["/dns"+strings.TrimPrefix(path, sourcePrefix)] = Origin{
							Layer:    LayerSource,
							Document: model.DocSources,
							Source:   from.Value,
							Path:     path,
							Line:     pos.Line,
							Column:   pos.Column,
						}
					}
				}

				var scopeDNS func(*yaml.Node)
				scopeDNS = func(n *yaml.Node) {
					if n.Kind == yaml.ScalarNode {
						if strings.HasPrefix(n.Value, "rule-set:") {
							n.Value = "rule-set:" + from.Value + "/" + strings.TrimPrefix(n.Value, "rule-set:")
						}
						if strings.Contains(n.Value, "#") {
							n.Value = RD.RemapEndpointTarget(n.Value, func(ref string) string { return scoped(from.Value, ref) })
						}
					}
					if n.Kind == yaml.MappingNode {
						if ref := field(n, "geoip-set"); ref != nil {
							ref.Value = from.Value + "/" + ref.Value
						}
					}
					for _, ch := range n.Content {
						scopeDNS(ch)
					}
				}
				scopeDNS(mergedDNS)
				for i := 0; i+1 < len(cfg.Content); i += 2 {
					if cfg.Content[i].Value != "from" {
						put(mergedDNS, cfg.Content[i].Value, nodeCopy(cfg.Content[i+1]))
						prefix := model.JoinPath("/dns", cfg.Content[i].Value)
						previous := map[string]Origin{}
						for p, o := range c.origins {
							if p == prefix || strings.HasPrefix(p, prefix+"/") {
								previous[p] = o
								delete(c.origins, p)
							}
						}
						for path, pos := range c.ppos {
							if path == prefix || strings.HasPrefix(path, prefix+"/") {
								o := Origin{Layer: LayerProfile, Document: model.DocProfile, Path: path, Line: pos.Line, Column: pos.Column}
								if old, ok := originAt(previous, path); ok {
									o.Overrides = &old
								}
								c.origins[path] = o
							}
						}

					}
				}
				put(doc.Mapping(), "dns", mergedDNS)
				includeResources(from.Value, true, false)
			}
		}
	}
	merged := map[string]*yaml.Node{"outbounds": sequence(), "groups": sequence()}
	seenImports := map[string]bool{}
	for i, imp := range c.profile.Imports {
		path := model.JoinPath("/imports", "#"+strconv.Itoa(i))
		src := byID[imp.Source]
		if src == nil {
			addDiag(model.DocProfile, path+"/source", "source.missing", "unknown source "+imp.Source, c.ppos)
			continue
		}
		if seenImports[imp.Source] {
			addDiag(model.DocProfile, path+"/source", "source.duplicate-import", "source is imported more than once", c.ppos)
			continue
		}
		seenImports[imp.Source] = true
		includeResources(imp.Source, imp.RuleSets, imp.SubRules)
		if !imp.Outbounds && !imp.Groups && !imp.RuleSets && !imp.SubRules {
			addDiag(model.DocProfile, path, "source.empty-import", "select outbounds, groups, rule-sets or sub-rules to import", c.ppos)
		}
		for _, kind := range []string{"outbounds", "groups"} {
			if (kind == "outbounds" && !imp.Outbounds) || (kind == "groups" && !imp.Groups) {
				continue
			}
			if items := field(src, kind); items != nil {
				for _, item := range items.Content {
					merged[kind].Content = append(merged[kind].Content, importItem(imp.Source, kind, item))
				}
			}
		}
	}
	// Profile objects explicitly replace matching imported objects by stable ID.
	for _, kind := range []string{"outbounds", "groups"} {
		seen := map[string]bool{}
		if items := field(doc.Mapping(), kind); items != nil {
			for _, item := range items.Content {
				id := field(item, "id")
				replaced := false
				if id != nil && !seen[id.Value] {
					for j, prev := range merged[kind].Content {
						if field(prev, "id").Value == id.Value {
							merged[kind].Content[j] = nodeCopy(item)
							prefix := model.JoinPath("", kind, id.Value)
							previous := map[string]Origin{}
							for p, o := range c.origins {
								if p == prefix || strings.HasPrefix(p, prefix+"/") {
									previous[p] = o
								}
							}
							for p := range c.origins {
								if p == prefix || strings.HasPrefix(p, prefix+"/") {
									delete(c.origins, p)
								}
							}
							for p, pos := range c.ppos {
								if p == prefix || strings.HasPrefix(p, prefix+"/") {
									o := Origin{Layer: LayerProfile, Document: model.DocProfile, Path: p, Line: pos.Line, Column: pos.Column}
									if old, ok := originAt(previous, p); ok {
										o.Overrides = &old
									}
									c.origins[p] = o
								}
							}
							replaced = true
							break
						}
					}
				}
				if !replaced {
					merged[kind].Content = append(merged[kind].Content, nodeCopy(item))
				}
				if id != nil {
					seen[id.Value] = true
				}
			}
		}
		put(doc.Mapping(), kind, merged[kind])
	}
	rules := sequence()
	for p := range c.origins {
		if strings.HasPrefix(p, "/rules/") {
			delete(c.origins, p)
		}
	}
	originalRules := field(doc.Mapping(), "rules")
	if originalRules != nil {
		seenRules := map[string]bool{}
		for i, r := range c.profile.Rules {
			path := model.JoinPath("/rules", seg(r.ID, i))
			if r.ID != "" {
				if seenRules[r.ID] {
					addDiag(model.DocProfile, path+"/id", "schema.duplicate-id", "duplicate profile rule or source marker ID", c.ppos)
				}
				seenRules[r.ID] = true
				if r.Source != "" && !idRE.MatchString(r.ID) {
					addDiag(model.DocProfile, path+"/id", "schema.id", "source marker ID must be a native stable ID", c.ppos)
				}
			}
			item := originalRules.Content[i]
			if r.Source == "" {
				old := model.JoinPath("/rules", seg(r.ID, i))
				dest := model.JoinPath("/rules", seg(r.ID, len(rules.Content)))
				for p, pos := range c.ppos {
					if p == old || strings.HasPrefix(p, old+"/") {
						c.origins[dest+strings.TrimPrefix(p, old)] = Origin{Layer: LayerProfile, Document: model.DocProfile, Path: p, Line: pos.Line, Column: pos.Column}
					}
				}
				rules.Content = append(rules.Content, nodeCopy(item))
				continue
			}
			if field(item, "match") != nil || field(item, "outbound") != nil {
				addDiag(model.DocProfile, path, "source.rule", "a source rule marker cannot also match or route", c.ppos)
				continue
			}
			src := byID[r.Source]
			if src == nil {
				addDiag(model.DocProfile, path+"/source", "source.missing", "unknown source "+r.Source, c.ppos)
				continue
			}
			includeResources(r.Source, true, true)
			if items := field(src, "rules"); items != nil {
				for _, rule := range items.Content {
					rules.Content = append(rules.Content, importItem(r.Source, "rules", rule))
				}
			}
		}
	}
	put(doc.Mapping(), "rules", rules)
	if doc.Get("/imports") != nil {
		_ = doc.Apply(model.Op{Op: "remove", Path: "/imports"})
	}
	if c.diags.HasErrors() {
		return
	}
	for i, op := range overlay.Patches {
		path := model.JoinPath("/patches", "#"+strconv.Itoa(i))
		fail := func(err error) { addDiag(model.DocOverlay, path, "overlay.path", err.Error(), opos) }
		segs, err := model.SplitPath(op.Path)
		if err != nil || len(segs) == 0 {
			fail(fmt.Errorf("invalid overlay target"))
			continue
		}
		kind := segs[0]
		if kind != "outbounds" && kind != "groups" && kind != "rules" && kind != "rule-sets" && kind != "sub-rules" && kind != "dns" {
			fail(fmt.Errorf("overlay may only edit outbounds, groups, rules, rule-sets, sub-rules and dns"))
			continue
		}
		if op.Before != "" && op.After != "" {
			fail(fmt.Errorf("choose before or after, not both"))
			continue
		}
		dest := op.Path
		if kind == "dns" {
			if op.Op != "set" && op.Op != "remove" {
				fail(fmt.Errorf("DNS overlays support set/remove"))
				continue
			}
			if len(segs) < 2 || doc.Get("/dns") == nil {
				fail(fmt.Errorf("DNS target does not exist"))
				continue
			}
		} else if op.Op == "insert" {
			if len(segs) != 1 {
				fail(fmt.Errorf("insert targets a resource list"))
				continue
			}
			value, e := model.JSONToNode(op.Value)
			if e != nil {
				fail(fmt.Errorf("invalid inserted resource"))
				continue
			}
			id := field(value, "id")
			if id == nil || !idRE.MatchString(id.Value) {
				fail(fmt.Errorf("inserted resource requires a native stable ID"))
				continue
			}
			dest = model.JoinPath(op.Path, id.Value)
		} else {
			if len(segs) < 2 || strings.HasPrefix(segs[1], "#") {
				fail(fmt.Errorf("overlay targets a resource by stable ID"))
				continue
			}
			root := model.JoinPath("", kind, segs[1])
			if doc.Get(root) == nil {
				fail(fmt.Errorf("target %s no longer exists", root))
				continue
			}
			if len(segs) >= 3 && segs[2] == "id" {
				fail(fmt.Errorf("resource identity cannot be changed"))
				continue
			}
			if op.Op == "set" && len(segs) == 2 {
				v, e := model.JSONToNode(op.Value)
				if e != nil || field(v, "id") == nil || field(v, "id").Value != segs[1] {
					fail(fmt.Errorf("replacement must keep the resource id"))
					continue
				}
			}
		}
		if err := doc.Apply(op); err != nil {
			fail(err)
			continue
		}
		old, hadOld := originAt(c.origins, dest)
		for p := range c.origins {
			if p == dest || strings.HasPrefix(p, dest+"/") {
				delete(c.origins, p)
			}
		}
		if op.Op != "remove" {
			pos := opos[path+"/value"]
			origin := Origin{Layer: LayerOverlay, Document: model.DocOverlay, Path: path + "/value", Line: pos.Line, Column: pos.Column}
			if hadOld {
				origin.Overrides = &old
			}
			// Record leaves as well, so an overridden object cannot retain stale
			// source provenance for any of its descendants.
			var record func(*yaml.Node, string, string)
			record = func(n *yaml.Node, p, original string) {
				o := origin
				o.Path = original
				if at, ok := opos[original]; ok {
					o.Line, o.Column = at.Line, at.Column
				}
				c.origins[p] = o
				switch n.Kind {
				case yaml.MappingNode:
					for j := 0; j+1 < len(n.Content); j += 2 {
						record(n.Content[j+1], model.JoinPath(p, n.Content[j].Value), model.JoinPath(original, n.Content[j].Value))
					}
				case yaml.SequenceNode:
					for j, ch := range n.Content {
						s := model.ElementSegment(ch, j)
						record(ch, model.JoinPath(p, s), model.JoinPath(original, s))
					}
				}
			}
			record(doc.Get(dest), dest, path+"/value")
		}
	}
	if c.diags.HasErrors() {
		return
	}
	var diags model.Diagnostics
	c.profile, c.ppos, diags = model.ParseProfile(doc.Bytes())
	for i, r := range c.profile.Rules {
		if r.Source != "" {
			c.errorf(model.DocProfile, model.JoinPath("/rules", seg(r.ID, i), "source"), "source.rule", "overlay cannot introduce source markers")
		}
	}
	// Parser positions from generated YAML are not user locations.
	for _, d := range diags {
		if o, ok := originAt(c.origins, d.Path); ok {
			d.Document, d.Path, d.Line, d.Column = o.Document, o.Path, o.Line, o.Column
		}
		c.diags = append(c.diags, d)
	}
}

func originAt(origins map[string]Origin, path string) (Origin, bool) {
	for p := path; p != ""; {
		if o, ok := origins[p]; ok {
			return o, true
		}
		i := strings.LastIndexByte(p, '/')
		if i < 0 {
			break
		}
		p = p[:i]
	}
	return Origin{}, false
}
