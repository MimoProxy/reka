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

const maxRuleResourceBytes = 384 << 20

type ruleCompiler struct {
	c              *compiler
	defs           map[string]model.RuleSet
	done           map[string]compiledResource
	visiting       map[string]bool
	blobs          map[string][]byte
	precompiled    map[string]int
	coveredGeosite map[string]bool
	pendingGeosite []model.GeoDatabase
	bytes          int
	entries        int
}

func (r *ruleCompiler) condition(m model.Match, depth int) (router.RuleSpec, error) {
	if m.Kind == "geosite" || m.Kind == "ip-asn" || m.Kind == "geoip" && !(len(m.Values) == 1 && strings.EqualFold(m.Values[0], "LAN")) {
		var children []router.RuleSpec
		for _, value := range m.Values {
			if m.Kind == "geoip" && strings.EqualFold(value, "LAN") {
				children = append(children, router.RuleSpec{Kind: router.KindGeoIP, Values: []string{"LAN"}, NoResolve: m.NoResolve})
				continue
			}
			kind := m.Kind
			if kind == "ip-asn" {
				kind = "asn"
				value = strings.TrimPrefix(strings.ToUpper(value), "AS")
			}
			spec, err := r.resolve(router.RuleSpec{Kind: router.KindRuleSet, Values: []string{kind + ":" + strings.ToLower(value)}, NoResolve: m.NoResolve}, depth+1)
			if err != nil {
				return spec, err
			}
			children = append(children, spec)
		}
		if len(children) == 0 {
			return router.RuleSpec{}, errors.New("geodata condition requires values")
		}
		if len(children) == 1 {
			return children[0], nil
		}
		return router.RuleSpec{Kind: router.KindOr, Children: children}, nil
	}
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
		kind, code, found := strings.Cut(id, ":")
		if found && (kind == "geoip" || kind == "geosite" || kind == "asn") {
			for _, db := range r.c.profile.Geodata {
				if db.ID == kind {
					def = model.RuleSet{ID: id, Behavior: kind, Format: db.Format, Hash: db.Hash, Code: code}
					r.defs[id] = def
					ok = true
					break
				}
			}
		}
	}
	if !ok {
		return compiledResource{}, fmt.Errorf("unknown rule-set %q", id)
	}
	r.visiting[id] = true
	defer delete(r.visiting, id)
	if def.Hash != "" {
		if len(def.Entries) > 0 || !resource.ValidHash(def.Hash) || r.c.opts.ReadResource == nil {
			return compiledResource{}, errors.New("rule-set requires one locked resource or inline entries")
		}
	} else if def.Behavior != "" || def.Format != "" || def.Code != "" || len(def.References) > 0 {
		return compiledResource{}, errors.New("inline rule-set cannot specify resource metadata")
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
	definition := def
	definition.Download = nil
	encoded, _ := json.Marshal(definition)
	digest := sha256.New()
	digest.Write(encoded)
	// The definition covers inline values and the locked resource digest.
	// Include resolved dependencies so a nested resource update is visible.
	var hashRefs func(router.RuleSpec)
	hashRefs = func(spec router.RuleSpec) {
		if spec.ResourceHash != "" {
			digest.Write([]byte(spec.ResourceHash))
		}
		for _, child := range spec.Children {
			hashRefs(child)
		}
	}
	addEntries := func(n int) error {
		if n > rulesdata.MaxEntries*2-r.entries {
			return errors.New("total rule entries exceed limit")
		}
		r.entries += n
		return nil
	}
	resolve := func(spec router.RuleSpec) (router.RuleSpec, error) {
		resolved, err := r.resolve(spec, depth+1)
		if err == nil {
			hashRefs(resolved)
		}
		return resolved, err
	}
	remember := func(set *router.RuleSet, cacheKey string, data []byte) compiledResource {
		v := compiledResource{set, hex.EncodeToString(digest.Sum(nil))}
		r.done[id] = v
		if record := r.c.opts.RecordPrecompiledRuleSet; record != nil && len(data) > 0 {
			record(cacheKey, data)
		}
		return v
	}

	var cacheKey string
	if r.c.opts.ReadPrecompiledRuleSet != nil || r.c.opts.RecordPrecompiledRuleSet != nil {
		cacheKey = resource.Hash(encoded)
	}
	if read := r.c.opts.ReadPrecompiledRuleSet; read != nil {
		cached, data := read(cacheKey)
		if cached != nil && (cached.SourceSize > 0) == (def.Hash != "") && r.acceptCachedSize(def.Hash, cached.SourceSize) {
			if err := addEntries(cached.Entries); err != nil {
				return compiledResource{}, err
			}
			set, err := cached.Build(func(index int, spec router.RuleSpec) (router.RuleSpec, error) {
				if def.Hash == "" {
					if index >= len(def.Entries) {
						return spec, errors.New("invalid cached inline rule index")
					}
					var err error
					spec, err = r.condition(def.Entries[index], depth+1)
					if err != nil {
						return spec, err
					}
				}
				return resolve(spec)
			})
			if err != nil {
				return compiledResource{}, err
			}
			if strings.HasPrefix(id, "geosite:") && def.Behavior == "geosite" && def.Format == "dat" {
				r.coveredGeosite[def.Hash] = true
			}
			return remember(set, cacheKey, data), nil
		}
	}
	var builder router.ConditionSetBuilder
	add := func(spec router.RuleSpec) error {
		if err := addEntries(1 + len(spec.Values)); err != nil {
			return err
		}
		mapRefs(&spec)
		spec, err := resolve(spec)
		if err != nil {
			return err
		}
		return builder.Add(spec)
	}
	var sourceSize int
	if def.Hash != "" {
		data, err := r.readBlob(def.Hash)
		if err != nil {
			return compiledResource{}, err
		}
		sourceSize = len(data)
		err = rulesdata.Walk(def.Behavior, def.Format, def.Code, data, add, func(kind router.Kind, value string) error {
			if err := addEntries(2); err != nil {
				return err
			}
			return builder.AddDomain(kind, value)
		}, func(count int) {
			builder.GrowDomains(min(count, (rulesdata.MaxEntries*2-r.entries)/2))
		})
		if err != nil {
			return compiledResource{}, err
		}
	} else {
		for _, m := range def.Entries {
			spec, err := r.condition(m, depth+1)
			if err == nil {
				err = add(spec)
			}
			if err != nil {
				return compiledResource{}, err
			}
		}
	}
	set, err := builder.Build()
	if err != nil {
		return compiledResource{}, err
	}
	var encodedSet []byte
	if r.c.opts.RecordPrecompiledRuleSet != nil {
		encodedSet, _ = set.MarshalPrecompiledRuleSet(sourceSize)
	}
	return remember(set, cacheKey, encodedSet), nil
}

func (r *ruleCompiler) acceptCachedSize(hash string, size int) bool {
	if hash == "" {
		return true
	}
	if data := r.blobs[hash]; data != nil {
		return len(data) == size
	}
	if n, ok := r.precompiled[hash]; ok {
		return n == size
	}
	if size > maxRuleResourceBytes-r.bytes {
		return false
	}
	r.precompiled[hash] = size
	r.bytes += size
	return true
}

func (r *ruleCompiler) readBlob(hash string) ([]byte, error) {
	if data := r.blobs[hash]; data != nil {
		return data, nil
	}
	data, err := r.c.opts.ReadResource(hash)
	if err != nil {
		return nil, fmt.Errorf("locked rule resource unavailable: %w", err)
	}
	if resource.Hash(data) != hash {
		return nil, errors.New("rule resource hash mismatch")
	}
	size := len(data) - r.precompiled[hash]
	if size > maxRuleResourceBytes-r.bytes {
		return nil, errors.New("total rule resource bytes exceed 384 MiB")
	}
	r.bytes += size
	delete(r.precompiled, hash)
	r.blobs[hash] = data
	return data, nil
}

func (r *ruleCompiler) validateDatabase(db model.GeoDatabase) {
	data, err := r.readBlob(db.Hash)
	if err == nil {
		err = rulesdata.ValidateDatabase(db.ID, db.Format, data)
	}
	if err != nil {
		r.c.errorf(model.DocProfile, model.JoinPath("/geodata", db.ID), "geodata.resource", "%s", err)
	}
}

func (r *ruleCompiler) validateDeferredGeosite() {
	for _, db := range r.pendingGeosite {
		// Preparation already validated the DAT. Check it again if it was
		// needed for fallback or no cached selector covered the database.
		if !r.coveredGeosite[db.Hash] || r.blobs[db.Hash] != nil {
			r.validateDatabase(db)
		}
	}
}

func (c *compiler) prepareRuleResources() *ruleCompiler {
	if c.ruleResources != nil {
		return c.ruleResources
	}
	r := &ruleCompiler{c: c, defs: map[string]model.RuleSet{}, done: map[string]compiledResource{}, visiting: map[string]bool{}, blobs: map[string][]byte{}}
	if c.opts.ReadPrecompiledRuleSet != nil {
		r.precompiled = make(map[string]int)
		r.coveredGeosite = make(map[string]bool)
	}
	c.ruleResources = r
	seenDB := map[string]bool{}
	for _, db := range c.profile.Geodata {
		path := model.JoinPath("/geodata", db.ID)
		if seenDB[db.ID] {
			c.errorf(model.DocProfile, path, "geodata.duplicate", "duplicate database kind")
		}
		seenDB[db.ID] = true
		if err := validateDownload(db.Download); err != nil {
			c.errorf(model.DocProfile, path, "resource.download", "%s", err)
		}
		if !resource.ValidHash(db.Hash) || c.opts.ReadResource == nil {
			c.errorf(model.DocProfile, path, "geodata.resource", "locked database required")
			continue
		}
		if c.opts.ReadPrecompiledRuleSet != nil && db.ID == "geosite" && db.Format == "dat" {
			r.pendingGeosite = append(r.pendingGeosite, db)
		} else {
			r.validateDatabase(db)
		}
	}
	for i, def := range c.profile.RuleSets {
		if err := validateDownload(def.Download); err != nil {
			c.errorf(model.DocProfile, model.JoinPath("/rule-sets", def.ID), "resource.download", "%s", err)
		} else if def.Download != nil && def.Hash == "" {
			c.errorf(model.DocProfile, model.JoinPath("/rule-sets", def.ID), "resource.download", "a downloadable rule set requires an initial locked hash")
		}
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

func validateDownload(d *model.ResourceDownload) error {
	if d == nil {
		return nil
	}
	return model.ValidResourceDownload(*d)
}
