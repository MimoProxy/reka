package generation

import (
	"hash/fnv"
	"sync/atomic"

	"github.com/MimoProxy/reka/internal/router"
)

// RuleHits reports how many flows each saved rule decided since the counts
// were last reset. Rules lists only rules with hits, in rule order.
type RuleHits struct {
	Generation uint64    `json:"generation"`
	RuleCount  int       `json:"rule_count"`
	Rules      []RuleHit `json:"rules"`
	// Final counts flows no rule matched.
	Final uint64 `json:"final"`
}

type RuleHit struct {
	Index int    `json:"index"`
	ID    string `json:"id,omitempty"`
	// Anonymous is the 1-based position among rules without an ID, so a
	// client can match it to the profile rule it lists in the same order.
	Anonymous int    `json:"anonymous,omitempty"`
	Hits      uint64 `json:"hits"`
}

// inheritRuleHits allocates one counter per saved rule and one for the final
// target. Counts carry over from prev for the same profile, matched by rule
// content, so reloading a profile keeps the counts of unchanged rules.
func (g *generation) inheritRuleHits(prev *generation) {
	eff := g.eff
	if eff == nil || eff.Router == nil {
		return
	}
	n := len(eff.Rules)
	g.ruleHits = make([]atomic.Uint64, n+1)
	if prev == nil || prev.ruleHits == nil || prev.eff == nil || prev.historyScope.ProfileID != g.historyScope.ProfileID {
		return
	}
	g.ruleHits[n].Store(prev.ruleHits[len(prev.ruleHits)-1].Load())
	if prev.eff == eff {
		for i := range n {
			g.ruleHits[i].Store(prev.ruleHits[i].Load())
		}
		return
	}
	old := map[uint64][]uint64{}
	for i := range prev.eff.Rules {
		if hits := prev.ruleHits[i].Load(); hits != 0 {
			key := ruleKey(prev.eff.Rules[i])
			old[key] = append(old[key], hits)
		}
	}
	for i := 0; i < n && len(old) != 0; i++ {
		key := ruleKey(eff.Rules[i])
		if hits := old[key]; len(hits) != 0 {
			g.ruleHits[i].Store(hits[0])
			if len(hits) == 1 {
				delete(old, key)
			} else {
				old[key] = hits[1:]
			}
		}
	}
}

func ruleKey(spec router.RuleSpec) uint64 {
	h := fnv.New64a()
	h.Write([]byte(spec.ID))
	h.Write([]byte{0})
	h.Write([]byte(spec.String()))
	h.Write([]byte{0})
	h.Write([]byte(spec.Target))
	return h.Sum64()
}

// countRule records the saved rule or final target that decided a flow.
// Temporary rules, other routing modes and flows rejected before any rule
// decided are not counted.
func (g *generation) countRule(dec router.Decision) {
	if g == nil || g.ruleHits == nil || dec.Temporary || g.router != g.eff.Router {
		return
	}
	i := dec.RuleIndex
	if i < 0 {
		if dec.Target == "" {
			return
		}
		i = len(g.ruleHits) - 1
	}
	if i < len(g.ruleHits) {
		g.ruleHits[i].Add(1)
	}
}

// RuleHits returns the active profile's rule hit counts.
func (e *Engine) RuleHits() RuleHits {
	s, g := e.current()
	out := RuleHits{Generation: s.Generation, Rules: []RuleHit{}}
	if g.ruleHits == nil {
		return out
	}
	n := len(g.ruleHits) - 1
	out.RuleCount = n
	out.Final = g.ruleHits[n].Load()
	anonymous := 0
	for i := range n {
		id := g.eff.Rules[i].ID
		hit := RuleHit{Index: i, ID: id, Hits: g.ruleHits[i].Load()}
		if id == "" {
			anonymous++
			hit.Anonymous = anonymous
		}
		if hit.Hits != 0 {
			out.Rules = append(out.Rules, hit)
		}
	}
	return out
}

// ResetRuleHits clears the active profile's rule hit counts.
func (e *Engine) ResetRuleHits() {
	_, g := e.current()
	for i := range g.ruleHits {
		g.ruleHits[i].Store(0)
	}
}
