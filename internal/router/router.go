package router

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
)

// RuleSet is a compiled, immutable rule list with its domain index. It can
// be shared by routers that differ only in group selections.
type RuleSet struct {
	maxDepth int
	rules    []*rule
	// exact and suffix map a normalized domain to the first rule position
	// that lists it. Only the first matters: a later rule with the same
	// key can never win.
	exact        map[string]int
	suffix       map[string]int
	strictSuffix map[string]int
	// others lists, in order, the positions of rules the index does not
	// cover; they are checked one by one, but only up to the best indexed
	// candidate.
	others []int

	hasProcess bool
}

// CompileRules compiles specs in order.
func CompileRules(specs []RuleSpec) (*RuleSet, error) {
	rs := &RuleSet{
		rules:        make([]*rule, 0, len(specs)),
		exact:        make(map[string]int),
		suffix:       make(map[string]int),
		strictSuffix: make(map[string]int),
	}
	var errs []error
	for i, spec := range specs {
		r, err := compileRule(i, spec)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		rs.rules = append(rs.rules, r)
		rs.maxDepth = max(rs.maxDepth, ruleDepth(r))
		switch spec.Kind {
		case KindDomain:
			for _, d := range r.strs {
				if _, ok := rs.exact[d]; !ok {
					rs.exact[d] = i
				}
			}
		case KindDomainPattern:
			for _, d := range r.strs {
				if _, ok := rs.strictSuffix[d]; !ok {
					rs.strictSuffix[d] = i
				}
			}
			if len(r.regexps) > 0 {
				rs.others = append(rs.others, i)
			}
		case KindDomainSuffix:
			for _, d := range r.strs {
				if _, ok := rs.suffix[d]; !ok {
					rs.suffix[d] = i
				}
			}
		default:
			rs.others = append(rs.others, i)
			if needsProcess(r) {
				rs.hasProcess = true
			}
		}
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return rs, nil
}

// Len is the number of rules.
func (rs *RuleSet) Len() int { return len(rs.rules) }

// Rule returns the spec at position i.
func (rs *RuleSet) Rule(i int) RuleSpec { return rs.rules[i].spec }

// NeedsProcess reports whether any rule matches on the process name.
func (rs *RuleSet) NeedsProcess() bool { return rs.hasProcess }

// Metadata describes a connection for matching.
type Metadata struct {
	Inbound string
	Network string // "tcp" or "udp"
	Source  netip.AddrPort
	// Domain is set when the destination is a name. Use NormalizeDomain.
	Domain string
	// Addr is set when the destination is an address.
	Addr netip.Addr
	Port uint16
}

// Env supplies what matching may need beyond Metadata. Both lookups are
// lazy: they run only if evaluation reaches a rule that needs them, and at
// most once per evaluation.
type Env interface {
	// Resolve looks up the destination domain for ip-cidr rules.
	Resolve(ctx context.Context, domain string) ([]netip.Addr, error)
	// Process returns the owning process path or name. ok is false when the
	// platform cannot tell.
	Process(ctx context.Context) (path string, ok bool)
}

// ErrNoLookup can be returned by Env.Resolve to stop evaluation instead of
// treating the lookup as failed; Explain uses it to avoid network requests.
var ErrNoLookup = errors.New("router: lookup not allowed")

type evaluation struct {
	noResolve bool
	ctx       context.Context
	md        *Metadata
	env       Env

	resolved    bool
	addrs       []netip.Addr
	dialAddr    netip.Addr
	resolveErr  error
	processDone bool
	process     string
	processOK   bool
	stopped     bool // a lookup returned ErrNoLookup
	stoppedAt   int
}

func (e *evaluation) destinationAddr(index int) (netip.Addr, bool) {
	if e.md.Addr.IsValid() {
		return e.md.Addr, true
	}
	if e.md.Domain == "" {
		return netip.Addr{}, false
	}
	if !e.resolved {
		e.resolved = true
		if e.env == nil {
			e.resolveErr = errors.New("no resolver")
		} else {
			e.addrs, e.resolveErr = e.env.Resolve(e.ctx, e.md.Domain)
		}
		if errors.Is(e.resolveErr, ErrNoLookup) {
			e.stopped, e.stoppedAt = true, index
			return netip.Addr{}, false
		}
		e.dialAddr = pickAddr(e.addrs)
	}
	return e.dialAddr, e.dialAddr.IsValid()
}

// pickAddr chooses the address ip rules see, as Clash does: the first
// IPv4 answer, else the first IPv6 one.
func pickAddr(addrs []netip.Addr) netip.Addr {
	for _, a := range addrs {
		if a.Unmap().Is4() {
			return a.Unmap()
		}
	}
	if len(addrs) > 0 {
		return addrs[0]
	}
	return netip.Addr{}
}

func (e *evaluation) processName(index int) (string, bool) {
	if !e.processDone {
		e.processDone = true
		if e.env != nil {
			e.process, e.processOK = e.env.Process(e.ctx)
		}
	}
	return e.process, e.processOK
}

func (e *evaluation) match(index int, r *rule) bool {
	md := e.md
	switch r.spec.Kind {
	case KindAnd, KindOr, KindNot:
		for _, child := range r.children {
			hit := e.match(index, child)
			if e.stopped {
				return false
			}
			if r.spec.Kind == KindNot {
				return !hit
			}
			if r.spec.Kind == KindAnd && !hit {
				return false
			}
			if r.spec.Kind == KindOr && hit {
				return true
			}
		}
		return r.spec.Kind == KindAnd
	case KindRuleSet:
		old := e.noResolve
		e.noResolve = old || r.spec.NoResolve
		matched := r.spec.Set.first(e) >= 0
		e.noResolve = old
		if e.stopped {
			e.stoppedAt = index
		}
		return matched && !e.stopped
	case KindGeoIP:
		if (r.spec.NoResolve || e.noResolve) && !md.Addr.IsValid() && (!e.resolved || len(e.addrs) == 0) {
			return false
		}
		a, ok := e.destinationAddr(index)
		return ok && (a.IsPrivate() || a.IsUnspecified() || a.IsLoopback() || a.IsMulticast() || a.IsLinkLocalUnicast())
	case KindMatch:
		return true
	case KindDomain:
		return md.Domain != "" && slices.Contains(r.strs, md.Domain)
	case KindDomainSuffix:
		if md.Domain == "" {
			return false
		}
		for _, s := range r.strs {
			if md.Domain == s || strings.HasSuffix(md.Domain, "."+s) {
				return true
			}
		}
		return false
	case KindDomainKeyword:
		if md.Domain == "" {
			return false
		}
		for _, s := range r.strs {
			if strings.Contains(md.Domain, s) {
				return true
			}
		}
		return false
	case KindDomainRegex, KindDomainPattern:
		for _, s := range r.strs {
			if strings.HasSuffix(md.Domain, "."+s) {
				return true
			}
		}
		if md.Domain == "" {
			return false
		}
		for _, re := range r.regexps {
			if re.MatchString(md.Domain) {
				return true
			}
		}
		return false
	case KindIPCIDR:
		if (r.spec.NoResolve || e.noResolve) && !md.Addr.IsValid() && (!e.resolved || len(e.addrs) == 0) {
			return false
		}
		a, ok := e.destinationAddr(index)
		return ok && (r.ipset.Contains(a.Unmap()) != r.spec.IPInverse)
	case KindSrcIPCIDR:
		return r.ipset.Contains(md.Source.Addr().Unmap())
	case KindDstPort:
		return matchPorts(r.ports, md.Port)
	case KindSrcPort:
		return matchPorts(r.ports, md.Source.Port())
	case KindNetwork:
		return slices.Contains(r.strs, md.Network)
	case KindProcessName:
		p, ok := e.processName(index)
		if !ok {
			return false
		}
		name := processBase(p)
		for _, s := range r.strs {
			if strings.EqualFold(name, s) {
				return true
			}
		}
		return false
	case KindProcessNameRegex:
		p, ok := e.processName(index)
		if !ok {
			return false
		}
		name := processBase(p)
		for _, re := range r.processRegexps {
			if matched, err := re.MatchString(name); err == nil && matched {
				return true
			}
		}
		return false
	}
	return false
}

// processBase returns the file name of a process path on any platform.
func processBase(p string) string {
	if i := strings.LastIndexAny(p, `/\`); i >= 0 {
		return p[i+1:]
	}
	return filepath.Base(p)
}

// first returns the position of the first matching rule, or -1.
func (rs *RuleSet) first(e *evaluation) int {
	best := len(rs.rules)
	if d := e.md.Domain; d != "" {
		if i, ok := rs.exact[d]; ok {
			best = i
		}
		for s := d; ; {
			if s != d {
				if i, ok := rs.strictSuffix[s]; ok && i < best {
					best = i
				}
			}
			if i, ok := rs.suffix[s]; ok && i < best {
				best = i
			}
			dot := strings.IndexByte(s, '.')
			if dot < 0 {
				break
			}
			s = s[dot+1:]
		}
	}
	for _, i := range rs.others {
		if i >= best {
			break
		}
		if e.match(i, rs.rules[i]) {
			return i
		}
		if e.stopped {
			return -1
		}
	}
	if best == len(rs.rules) {
		return -1
	}
	return best
}

// firstLinear is the reference implementation the index must agree with.
func (rs *RuleSet) firstLinear(e *evaluation) int {
	for i, r := range rs.rules {
		if e.match(i, r) {
			return i
		}
		if e.stopped {
			return -1
		}
	}
	return -1
}

// Group is a select group: it routes to its selected member, which is an
// outbound or another group.
type Group struct {
	ID       string
	Members  []string
	Selected string
}

// Router is an immutable routing table: rules, groups and the fallback.
type Router struct {
	rules     *RuleSet
	groups    map[string]Group
	outbounds map[string]bool
	final     string
}

// Options configure New.
type Options struct {
	// Outbounds are the IDs rules and groups may end at.
	Outbounds []string
	Groups    []Group
	// Final is the target when no rule matches.
	Final string
}

// New builds a router over a compiled rule set. It checks that every
// target exists and that groups do not form a cycle.
func New(rules *RuleSet, opts Options) (*Router, error) {
	r := &Router{
		rules:     rules,
		groups:    make(map[string]Group, len(opts.Groups)),
		outbounds: make(map[string]bool, len(opts.Outbounds)),
		final:     opts.Final,
	}
	for _, id := range opts.Outbounds {
		r.outbounds[id] = true
	}
	for _, g := range opts.Groups {
		if r.outbounds[g.ID] {
			return nil, fmt.Errorf("group %q has the same ID as an outbound", g.ID)
		}
		if _, dup := r.groups[g.ID]; dup {
			return nil, fmt.Errorf("duplicate group %q", g.ID)
		}
		if len(g.Members) == 0 {
			return nil, fmt.Errorf("group %q has no members", g.ID)
		}
		if g.Selected == "" {
			g.Selected = g.Members[0]
		} else if !slices.Contains(g.Members, g.Selected) {
			return nil, fmt.Errorf("group %q: selected %q is not a member", g.ID, g.Selected)
		}
		r.groups[g.ID] = g
	}
	for _, g := range r.groups {
		for _, m := range g.Members {
			if !r.exists(m) {
				return nil, fmt.Errorf("group %q: unknown member %q", g.ID, m)
			}
		}
	}
	for id := range r.groups {
		if _, err := r.resolve(id); err != nil {
			return nil, err
		}
	}
	if rules != nil {
		for i := range rules.rules {
			if t := rules.rules[i].spec.Target; !r.exists(t) {
				return nil, &RuleError{Index: i, Err: fmt.Errorf("unknown target %q", t)}
			}
		}
	}
	if r.final != "" && !r.exists(r.final) {
		return nil, fmt.Errorf("unknown final target %q", r.final)
	}
	return r, nil
}

func (r *Router) exists(id string) bool {
	_, isGroup := r.groups[id]
	return isGroup || r.outbounds[id]
}

// resolve follows group selections from target to an outbound. It returns
// the chain of groups passed through.
func (r *Router) resolve(target string) ([]string, error) {
	var chain []string
	for {
		g, ok := r.groups[target]
		if !ok {
			if !r.outbounds[target] {
				return chain, fmt.Errorf("unknown target %q", target)
			}
			return chain, nil
		}
		if slices.Contains(chain, g.ID) {
			return chain, fmt.Errorf("group cycle: %s -> %s", strings.Join(chain, " -> "), g.ID)
		}
		chain = append(chain, g.ID)
		target = g.Selected
	}
}

// Resolve returns the outbound a target ends at and the groups on the way.
func (r *Router) Resolve(target string) (outbound string, chain []string, err error) {
	chain, err = r.resolve(target)
	if err != nil {
		return "", chain, err
	}
	if len(chain) == 0 {
		return target, nil, nil
	}
	return r.groups[chain[len(chain)-1]].Selected, chain, nil
}

// Rules returns the compiled rule set.
func (r *Router) Rules() *RuleSet { return r.rules }

// Groups returns the groups with their effective selection.
func (r *Router) Groups() []Group {
	out := make([]Group, 0, len(r.groups))
	for _, g := range r.groups {
		out = append(out, g)
	}
	slices.SortFunc(out, func(a, b Group) int { return strings.Compare(a.ID, b.ID) })
	return out
}

// Decision is the result of routing one connection.
type Decision struct {
	// RuleIndex is the matching rule's position, or -1 when the final
	// target was used.
	RuleIndex int
	Rule      RuleSpec
	Target    string
	Chain     []string
	Outbound  string
	// Resolved holds the answers when a domain was resolved for ip rules;
	// ResolveError is set when that failed (ip rules then did not match).
	Resolved     []netip.Addr
	ResolveError error
	Process      string
}

// Route evaluates md. It never returns an error for a connection: a
// failed lookup just makes the rules that needed it not match.
func (r *Router) Route(ctx context.Context, md Metadata, env Env) Decision {
	e := &evaluation{ctx: ctx, md: &md, env: env}
	d := r.decide(e, r.rules.first(e))
	return d
}

func (r *Router) decide(e *evaluation, index int) Decision {
	d := Decision{RuleIndex: index, Resolved: e.addrs, ResolveError: e.resolveErr, Process: e.process}
	if index >= 0 {
		d.Rule = r.rules.rules[index].spec
		d.Target = d.Rule.Target
	} else {
		d.Target = r.final
	}
	if d.Target == "" {
		return d
	}
	// New checked every target, so resolve cannot fail here.
	d.Outbound, d.Chain, _ = r.Resolve(d.Target)
	return d
}

// Explanation is a Decision plus why evaluation may not have finished.
type Explanation struct {
	Decision
	// Undetermined is set when a rule needed a lookup Explain was not
	// allowed to make; StoppedAt is that rule's position.
	Undetermined bool
	StoppedAt    int
}

// Explain routes md like Route. If env.Resolve returns ErrNoLookup the
// evaluation stops there and the explanation says so, instead of
// guessing.
func (r *Router) Explain(ctx context.Context, md Metadata, env Env) Explanation {
	e := &evaluation{ctx: ctx, md: &md, env: env}
	index := r.rules.first(e)
	if e.stopped {
		return Explanation{Decision: Decision{RuleIndex: -1}, Undetermined: true, StoppedAt: e.stoppedAt}
	}
	return Explanation{Decision: r.decide(e, index)}
}

func needsProcess(r *rule) bool {
	if r.spec.Kind == KindProcessName || r.spec.Kind == KindProcessNameRegex || r.spec.Set != nil && r.spec.Set.NeedsProcess() {
		return true
	}
	for _, ch := range r.children {
		if needsProcess(ch) {
			return true
		}
	}
	return false
}

func ruleDepth(r *rule) int {
	depth := 1
	for _, ch := range r.children {
		depth = max(depth, 1+ruleDepth(ch))
	}
	if r.spec.Set != nil {
		depth = max(depth, 1+r.spec.Set.maxDepth)
	}
	return depth
}

// ResolveDynamic follows the same validated group graph using observed choices.
func (r *Router) ResolveDynamic(target string, choose func(Group) string) (string, []string, error) {
	var chain []string
	for {
		g, ok := r.groups[target]
		if !ok {
			if !r.outbounds[target] {
				return "", chain, fmt.Errorf("target unavailable")
			}
			return target, chain, nil
		}
		if slices.Contains(chain, g.ID) {
			return "", chain, fmt.Errorf("group cycle")
		}
		chain = append(chain, g.ID)
		next := choose(g)
		if !slices.Contains(g.Members, next) {
			return "", chain, fmt.Errorf("no healthy group member")
		}
		target = next
	}
}
