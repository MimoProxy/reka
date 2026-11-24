package router

import (
	"context"
	"time"
)

// PreMatchOptions describe what is known about a flow before its first byte
// is accepted.
type PreMatchOptions struct {
	// DomainPending is set when md has no domain yet but one may be learned
	// later, for example by sniffing.
	DomainPending bool
	// Overrides and At are the temporary rules checked before the saved
	// rules, as in ExplainWithOverrides.
	Overrides []TimedRule
	At        time.Time
	// Peek resolves a target through groups without side effects. ok is
	// false unless the choice will hold after the flow's metadata is known.
	// Nil uses the static group selection (Router.Resolve).
	Peek func(target string) (outbound string, chain []string, ok bool)
}

// PreMatchResult is a routing decision made from the first packet alone.
type PreMatchResult struct {
	Decided  bool
	Decision Decision
}

// PreMatch routes md using only what the first packet of a flow carries. It
// never resolves a domain, asks for the owning process or changes group state.
func (r *Router) PreMatch(ctx context.Context, md Metadata, opts PreMatchOptions) PreMatchResult {
	undecided := PreMatchResult{Decision: Decision{RuleIndex: -1, LookupRule: -1}}
	e := &evaluation{
		ctx: ctx, md: md, lookupRule: -1, packetOnly: true,
		domainPending: opts.DomainPending && md.Domain == "",
	}
	for _, override := range opts.Overrides {
		if !r.OverrideActive(override, opts.At) {
			continue
		}
		if e.domainPending && override.Match.MatchesDomain() {
			return undecided
		}
		index := override.Match.first(e)
		if e.stopped {
			return undecided
		}
		if index < 0 {
			continue
		}
		spec := override.Match.Rule(0)
		d := r.decisionForTarget(e, -1, spec, spec.Target)
		d.Temporary = true
		if !r.peekDecision(&d, opts.Peek) {
			return undecided
		}
		if d.Outbound != "pass" {
			return PreMatchResult{Decided: true, Decision: d}
		}
	}

	if r.rules == nil {
		return undecided
	}
	ruleCount := len(r.rules.rules)
	limit := ruleCount
	if e.domainPending {
		limit = r.rules.firstDomain
	}
	index := r.rules.first(e)
	if e.stopped || index >= limit || (index < 0 && limit < ruleCount) {
		return undecided
	}
	for {
		d := r.decisionForRule(e, index)
		if !r.peekDecision(&d, opts.Peek) {
			return undecided
		}
		if !d.passes(index) {
			return PreMatchResult{Decided: true, Decision: d}
		}
		var ok bool
		index, ok = r.rules.nextAfterPass(e, index, limit)
		if !ok {
			return undecided
		}
	}
}

func (r *Router) peekDecision(d *Decision, peek func(string) (string, []string, bool)) bool {
	if peek == nil {
		r.resolveDecision(d)
		return true
	}
	var ok bool
	d.Outbound, d.Chain, ok = peek(d.Target)
	return ok
}
