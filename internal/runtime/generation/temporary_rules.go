package generation

import (
	"errors"
	"fmt"
	"time"

	"github.com/MimoProxy/reka/internal/api"
	"github.com/MimoProxy/reka/internal/router"
)

type temporaryRules struct {
	profile string
	rules   []router.TimedRule // newest first
}

func (e *Engine) AddTemporaryRule(request api.TemporaryRuleRequest) (api.TemporaryRule, error) {
	if request.TTLSeconds == 0 {
		request.TTLSeconds = 300
	}
	if request.TTLSeconds < 1 || request.TTLSeconds > 86400 {
		return api.TemporaryRule{}, errors.New("temporary rule TTL must be 1..86400 seconds")
	}
	if len(request.Rule) == 0 || len(request.Rule) > 4096 {
		return api.TemporaryRule{}, errors.New("temporary rule must contain 1..4096 bytes")
	}
	spec, call, err := router.ParseClashRule(request.Rule)
	if err != nil {
		return api.TemporaryRule{}, err
	}
	if call != "" || spec.Target == "" || spec.Target == "pass" {
		return api.TemporaryRule{}, errors.New("temporary rule requires an outbound or policy group")
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	_, g := e.current()
	if e.closed || g.router == nil || !g.router.HasTarget(spec.Target) {
		return api.TemporaryRule{}, errors.New("unknown outbound or policy group")
	}
	now := time.Now()
	old := e.activeTemporaryRules(g)
	live := make([]router.TimedRule, 0, min(len(old)+1, 32))
	for _, rule := range old {
		if now.Before(rule.ExpiresAt) {
			live = append(live, rule)
		}
	}
	if len(live) >= 32 {
		return api.TemporaryRule{}, errors.New("at most 32 temporary rules can be active")
	}
	e.temporarySequence++
	spec.ID = fmt.Sprintf("temp-%d", e.temporarySequence)
	match, err := router.CompileRules([]router.RuleSpec{spec})
	if err != nil {
		return api.TemporaryRule{}, err
	}
	entry := router.TimedRule{Match: match, ExpiresAt: now.Add(time.Duration(request.TTLSeconds) * time.Second)}
	e.temporary.Store(&temporaryRules{profile: g.historyScope.ProfileID, rules: append([]router.TimedRule{entry}, live...)})
	return temporaryRuleView(g, entry), nil
}

func (e *Engine) ListTemporaryRules() []api.TemporaryRule {
	_, g := e.current()
	now := time.Now()
	result := []api.TemporaryRule{}
	for _, rule := range e.activeTemporaryRules(g) {
		if now.Before(rule.ExpiresAt) {
			result = append(result, temporaryRuleView(g, rule))
		}
	}
	return result
}

func (e *Engine) RemoveTemporaryRule(id string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	_, g := e.current()
	old := e.activeTemporaryRules(g)
	var kept []router.TimedRule
	removed := false
	now := time.Now()
	for _, rule := range old {
		if !now.Before(rule.ExpiresAt) {
			continue
		}
		if rule.Match.Rule(0).ID == id {
			removed = true
			continue
		}
		kept = append(kept, rule)
	}
	if removed {
		e.temporary.Store(&temporaryRules{profile: g.historyScope.ProfileID, rules: kept})
	}
	return removed
}

func (e *Engine) activeTemporaryRules(g *generation) []router.TimedRule {
	if value := e.temporary.Load(); value != nil && value.profile == g.historyScope.ProfileID {
		return value.rules
	}
	return nil
}

func temporaryRuleView(g *generation, entry router.TimedRule) api.TemporaryRule {
	spec := entry.Match.Rule(0)
	return api.TemporaryRule{ID: spec.ID, Rule: spec.String(), Outbound: spec.Target, ExpiresAt: entry.ExpiresAt.UTC(),
		Active: g.eff != nil && g.eff.Routing.Mode == "rule" && g.router.HasTarget(spec.Target)}
}

type routingState struct {
	scene     string
	temporary []router.TimedRule
	at        time.Time
}

func (e *Engine) routingState(g *generation) routingState {
	state := routingState{scene: e.activeNetworkScene(g)}
	if g.eff != nil && g.eff.Routing.Mode == "rule" {
		state.temporary = e.activeTemporaryRules(g)
		if len(state.temporary) != 0 {
			state.at = time.Now()
		}
	}
	return state
}
