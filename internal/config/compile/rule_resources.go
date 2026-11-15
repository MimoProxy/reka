package compile

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/MimoProxy/reka/internal/config/model"
	"github.com/MimoProxy/reka/internal/resource"
	"github.com/MimoProxy/reka/internal/router"
	"github.com/MimoProxy/reka/internal/rulesdata"
)

type compiledResource struct {
	set  *router.RuleSet
	hash string
}
type ruleCompiler struct {
	c        *compiler
	defs     map[string]model.RuleSet
	done     map[string]compiledResource
	visiting map[string]bool
	blobs    map[string][]byte
	bytes    int
	entries  int
}

func (r *ruleCompiler) condition(m model.Match, depth int) (router.RuleSpec, error) {
	k, ok := router.ParseKind(m.Kind)
	if !ok {
		return router.RuleSpec{}, fmt.Errorf("unsupported condition %q", m.Kind)
	}
	spec := router.RuleSpec{Kind: k, Values: m.Values, NoResolve: m.NoResolve}
	for _, ch := range m.Children {
		s, err := r.condition(ch, depth+1)
		if err != nil {
			return spec, err
		}
		spec.Children = append(spec.Children, s)
	}
	return r.resolve(spec, depth)
}
func (r *ruleCompiler) resolve(spec router.RuleSpec, depth int) (router.RuleSpec, error) {
	if depth > 32 {
		return spec, errors.New("rule reference depth exceeds 32")
	}
	if spec.Kind == router.KindRuleSet {
		if len(spec.Values) != 1 {
			return spec, errors.New("rule-set needs one reference")
		}
		ref, err := r.resource(spec.Values[0], depth+1)
		if err != nil {
			return spec, err
		}
		spec.Set = ref.set
		spec.ResourceHash = ref.hash
	}
	for i, ch := range spec.Children {
		s, err := r.resolve(ch, depth+1)
		if err != nil {
			return spec, err
		}
		spec.Children[i] = s
	}
	return spec, nil
}
func (r *ruleCompiler) resource(id string, depth int) (compiledResource, error) {
	if depth > 32 {
		return compiledResource{}, errors.New("rule reference depth exceeds 32")
	}
	if v, ok := r.done[id]; ok {
		return v, nil
	}
	if r.visiting[id] {
		return compiledResource{}, fmt.Errorf("rule-set reference cycle at %q", id)
	}
	def, ok := r.defs[id]
	if !ok {
		return compiledResource{}, fmt.Errorf("unknown rule-set %q", id)
	}
	r.visiting[id] = true
	defer delete(r.visiting, id)
	var specs []router.RuleSpec
	if def.Hash != "" {
		if len(def.Entries) > 0 || !resource.ValidHash(def.Hash) || r.c.opts.ReadResource == nil {
			return compiledResource{}, errors.New("rule-set requires one locked resource or inline entries")
		}
		data := r.blobs[def.Hash]
		if data == nil {
			var err error
			data, err = r.c.opts.ReadResource(def.Hash)
			if err != nil {
				return compiledResource{}, fmt.Errorf("locked rule resource unavailable: %w", err)
			}
			if resource.Hash(data) != def.Hash {
				return compiledResource{}, errors.New("rule resource hash mismatch")
			}
			r.bytes += len(data)
			if r.bytes > rulesdata.MaxExpanded {
				return compiledResource{}, errors.New("total rule resource bytes exceed 64 MiB")
			}
			r.blobs[def.Hash] = data
		}
		var err error
		specs, err = rulesdata.Decode(def.Behavior, def.Format, def.Code, data)
		if err != nil {
			return compiledResource{}, err
		}
	} else {
		if def.Behavior != "" || def.Format != "" || def.Code != "" || len(def.References) > 0 {
			return compiledResource{}, errors.New("inline rule-set cannot specify resource metadata")
		}
		for _, m := range def.Entries {
			s, err := r.condition(m, depth+1)
			if err != nil {
				return compiledResource{}, err
			}
			specs = append(specs, s)
		}
	}
	aliases := map[string]string{}
	for _, ref := range def.References {
		_, exists := r.defs[ref.To]
		if ref.Name == "" || !exists || aliases[ref.Name] != "" {
			return compiledResource{}, errors.New("invalid resource reference mapping")
		}
		aliases[ref.Name] = ref.To
	}
	var mapRefs func(*router.RuleSpec)
	mapRefs = func(s *router.RuleSpec) {
		if s.Kind == router.KindRuleSet && len(s.Values) == 1 {
			if to := aliases[s.Values[0]]; to != "" {
				s.Values = []string{to}
			}
		}
		for i := range s.Children {
			mapRefs(&s.Children[i])
		}
	}
	for i := range specs {
		mapRefs(&specs[i])
	}
	for i, s := range specs {
		v, err := r.resolve(s, depth+1)
		if err != nil {
			return compiledResource{}, err
		}
		specs[i] = v
	}
	for _, s := range specs {
		r.entries += 1 + len(s.Values)
		if r.entries > rulesdata.MaxEntries*2 {
			return compiledResource{}, errors.New("total rule entries exceed limit")
		}
	}
	set, err := router.CompileRules(specs)
	if err != nil {
		return compiledResource{}, err
	}
	b, _ := json.Marshal(struct {
		Definition model.RuleSet
		Specs      []router.RuleSpec
	}{def, specs})
	sum := sha256.Sum256(b)
	v := compiledResource{set, hex.EncodeToString(sum[:])}
	r.done[id] = v
	return v, nil
}
func (c *compiler) prepareRuleResources() *ruleCompiler {
	r := &ruleCompiler{c: c, defs: map[string]model.RuleSet{}, done: map[string]compiledResource{}, visiting: map[string]bool{}, blobs: map[string][]byte{}}
	for i, def := range c.profile.RuleSets {
		path := model.JoinPath("/rule-sets", seg(def.ID, i))
		if !idRE.MatchString(def.ID) && !c.scopedIDs[def.ID] {
			c.errorf(model.DocProfile, path, "rule-set.id", "invalid rule-set ID")
		}
		if _, ok := r.defs[def.ID]; ok {
			c.errorf(model.DocProfile, path, "schema.duplicate-id", "duplicate rule-set ID")
		}
		r.defs[def.ID] = def
	}
	for _, def := range c.profile.RuleSets {
		if _, err := r.resource(def.ID, 0); err != nil {
			c.errorf(model.DocProfile, model.JoinPath("/rule-sets", def.ID), "rule-set.resource", "%s", err)
		}
	}
	return r
}

// Sub-rules preserve ordered fallthrough by conjoining each child with the
// caller's guard. Expansions are bounded even for acyclic diamond graphs.
func (c *compiler) expandSubRules() {
	if c.scopedIDs == nil {
		c.scopedIDs = map[string]bool{}
	}
	if len(c.profile.SubRules) == 0 {
		hasCall := false
		for _, r := range c.profile.Rules {
			hasCall = hasCall || r.Call != ""
		}
		if !hasCall {
			return
		}
	}
	blocks := map[string][]model.Rule{}
	blockIDs := map[string]bool{}
	for i, b := range c.profile.SubRules {
		path := model.JoinPath("/sub-rules", seg(b.ID, i))
		if (!idRE.MatchString(b.ID) && !c.scopedIDs[b.ID]) || blockIDs[b.ID] {
			c.errorf(model.DocProfile, path, "sub-rule.id", "invalid or duplicate sub-rule block ID")
		}
		blocks[b.ID] = b.Rules
		blockIDs[b.ID] = true
	}
	check := func(rules []model.Rule, path string) {
		seen := map[string]bool{}
		for i, r := range rules {
			p := model.JoinPath(path, seg(r.ID, i))
			if r.Source != "" || (r.Call != "" && r.Outbound != "") || (r.Call == "" && r.Outbound == "") {
				c.errorf(model.DocProfile, p, "sub-rule.action", "rule requires exactly one outbound or call")
			}
			if r.ID != "" {
				if seen[r.ID] || (!idRE.MatchString(r.ID) && !c.scopedIDs[r.ID]) {
					c.errorf(model.DocProfile, p, "sub-rule.id", "invalid or duplicate rule ID")
				}
				seen[r.ID] = true
			}
			if r.Call != "" {
				if _, ok := blocks[r.Call]; !ok {
					c.errorf(model.DocProfile, p, "sub-rule.reference", "unknown sub-rule block %q", r.Call)
				}
			}
		}
	}
	check(c.profile.Rules, "/rules")
	for _, b := range c.profile.SubRules {
		check(b.Rules, model.JoinPath("/sub-rules", b.ID, "rules"))
	}
	state := map[string]int{}
	heights := map[string]int{}
	var visit func(string, int)
	visit = func(id string, depth int) {
		if state[id] == 1 || depth > 32 {
			c.errorf(model.DocProfile, model.JoinPath("/sub-rules", id), "sub-rule.cycle", "sub-rule cycle or nesting deeper than 32")
			return
		}
		if state[id] == 2 {
			if depth+heights[id] > 32 {
				c.errorf(model.DocProfile, model.JoinPath("/sub-rules", id), "sub-rule.limit", "sub-rule nesting exceeds 32")
			}
			return
		}
		state[id] = 1
		height := 1
		for _, r := range blocks[id] {
			if r.Call != "" {
				visit(r.Call, depth+1)
				height = max(height, 1+heights[r.Call])
			}
		}
		heights[id] = height
		if height > 32 {
			c.errorf(model.DocProfile, model.JoinPath("/sub-rules", id), "sub-rule.limit", "sub-rule nesting exceeds 32")
		}
		state[id] = 2
	}
	for _, b := range c.profile.SubRules {
		visit(b.ID, 0)
	}
	if c.diags.HasErrors() {
		return
	}
	if c.origins == nil {
		c.origins = map[string]Origin{}
		for path, pos := range c.ppos {
			c.origins[path] = Origin{Layer: LayerProfile, Document: model.DocProfile, Path: path, Line: pos.Line, Column: pos.Column}
		}
	}
	originalOrigins := map[string]Origin{}
	for p, o := range c.origins {
		originalOrigins[p] = o
	}
	copyOrigin := func(from, to string) {
		for p, o := range originalOrigins {
			if p == from || strings.HasPrefix(p, from+"/") {
				c.origins[to+strings.TrimPrefix(p, from)] = o
			}
		}
	}
	type guard struct {
		match model.Match
		path  string
	}
	var out []model.Rule
	var expand func([]model.Rule, []guard, string, string, int)
	expand = func(rules []model.Rule, guards []guard, prefix, path string, depth int) {
		if depth > 32 {
			c.errorf(model.DocProfile, path, "sub-rule.limit", "sub-rule nesting exceeds 32")
			return
		}
		if len(out) >= 100000 {
			return
		}
		for i, r := range rules {
			original := model.JoinPath(path, seg(r.ID, i))
			id := r.ID
			if id == "" {
				id = fmt.Sprintf("#%d", i)
			}
			if prefix != "" {
				r.ID = prefix + "/" + id
				c.scopedIDs[r.ID] = true
			}
			if r.Call != "" {
				next := append(append([]guard{}, guards...), guard{r.Match, original + "/match"})
				caller := r.ID
				if caller == "" {
					caller = fmt.Sprintf("call-%d", i)
				}
				children := blocks[r.Call]
				if len(children) == 0 {
					children = []model.Rule{{ID: "empty", Match: model.Match{Kind: "not", Children: []model.Match{{Kind: "all"}}}, Outbound: "direct"}}
				}
				expand(children, next, caller+"/"+r.Call, model.JoinPath("/sub-rules", r.Call, "rules"), depth+1)
				continue
			}
			if len(guards) > 0 {
				dest := model.JoinPath("/rules", r.ID)
				copyOrigin(original, dest)
				for p := range c.origins {
					if strings.HasPrefix(p, dest+"/match/") {
						delete(c.origins, p)
					}
				}
				matches := []model.Match{}
				for j, g := range guards {
					matches = append(matches, g.match)
					copyOrigin(g.path, model.JoinPath(dest, "match", "and", fmt.Sprintf("#%d", j)))
				}
				copyOrigin(original+"/match", model.JoinPath(dest, "match", "and", fmt.Sprintf("#%d", len(guards))))
				r.Match = model.Match{Kind: "and", Children: append(matches, r.Match)}
			}
			out = append(out, r)
			if len(out) >= 100000 {
				return
			}
		}
	}
	expand(c.profile.Rules, nil, "", "/rules", 0)
	if len(out) >= 100000 {
		c.errorf(model.DocProfile, "/sub-rules", "sub-rule.limit", "expanded rule count exceeds limit")
		return
	}
	c.profile.Rules = out
}

func (c *compiler) validateSubRules(rc *ruleCompiler, eff *Effective) {
	if len(c.profile.SubRules) == 0 {
		has := false
		for _, r := range c.profile.Rules {
			has = has || r.Call != ""
		}
		if !has {
			return
		}
	}
	targets := map[string]bool{}
	for _, o := range eff.Outbounds {
		targets[o.ID] = true
	}
	for _, g := range c.profile.Groups {
		targets[g.ID] = true
	}
	check := func(rules []model.Rule, path string) {
		for i, r := range rules {
			p := model.JoinPath(path, seg(r.ID, i))
			spec, err := rc.condition(r.Match, 0)
			if err == nil {
				_, err = router.CompileRules([]router.RuleSpec{spec})
			}
			if err != nil {
				c.errorf(model.DocProfile, p+"/match", "rule.match", "%s", err)
			}
			if r.Outbound != "" && !targets[r.Outbound] {
				c.errorf(model.DocProfile, p+"/outbound", "rule.outbound", "unknown outbound or group %q", r.Outbound)
			}
		}
	}
	check(c.profile.Rules, "/rules")
	for _, b := range c.profile.SubRules {
		check(b.Rules, model.JoinPath("/sub-rules", b.ID, "rules"))
	}
}
