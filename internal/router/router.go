package router

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// RuleSet is an immutable ordered rule list or a referenced condition set.
type RuleSet struct {
	maxDepth             int
	rules                []*rule
	members              *conditionSet
	diagnosticEntryCount func() int
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
	hasDomain  bool
	hasHTTP    bool
	// firstDomain bounds the prefix that can be matched before sniffing.
	firstDomain int
}

// CompileRules compiles specs in order.
func CompileRules(specs []RuleSpec) (*RuleSet, error) {
	rs := &RuleSet{
		rules:        make([]*rule, 0, len(specs)),
		exact:        make(map[string]int),
		suffix:       make(map[string]int),
		strictSuffix: make(map[string]int),
		firstDomain:  len(specs),
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
		rs.hasHTTP = rs.hasHTTP || matchesHTTP(r)
		if !rs.hasDomain && matchesDomain(r) {
			rs.hasDomain = true
			rs.firstDomain = i
		}
		switch spec.Kind {
		case KindDomain:
			if spec.compact != nil {
				rs.others = append(rs.others, i)
			}
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
func (rs *RuleSet) Len() int {
	if rs.members != nil {
		return len(rs.members.rows)
	}
	return len(rs.rules)
}

// Rule returns the spec at position i.
func (rs *RuleSet) Rule(i int) RuleSpec {
	if rs.members != nil {
		return rs.members.rule(i)
	}
	return rs.rules[i].spec
}

// VisitReferences visits direct references, including those in logical
// operands. Callers can follow each referenced set if they need its children.
func (rs *RuleSet) VisitReferences(visit func(string, *RuleSet)) {
	var walk func(RuleSpec)
	walk = func(spec RuleSpec) {
		if spec.Set != nil && len(spec.Values) > 0 {
			visit(spec.Values[0], spec.Set)
		}
		for _, child := range spec.Children {
			walk(child)
		}
	}
	if rs.members != nil {
		for _, block := range rs.members.blocks {
			if block.general != nil {
				walk(block.general.spec)
			}
		}
		return
	}
	for _, r := range rs.rules {
		walk(r.spec)
	}
}

// NeedsProcess reports whether any rule matches on the process name.
func (rs *RuleSet) NeedsProcess() bool { return rs.hasProcess }

// MatchesDomain reports whether rules can use the destination domain.
func (rs *RuleSet) MatchesDomain() bool { return rs.hasDomain }

// MatchesHTTP reports whether rules can use an HTTP request's URL or headers.
func (rs *RuleSet) MatchesHTTP() bool { return rs.hasHTTP }

// Metadata describes a connection for matching.
type Metadata struct {
	NetworkScene string
	Inbound      string
	InboundType  string
	InboundUser  string
	InboundPort  uint16
	Network      string // "tcp" or "udp"
	Source       netip.AddrPort
	// Domain is set when the destination is a name. Use NormalizeDomain.
	Domain string
	// Addr is set when the destination is an address.
	Addr netip.Addr
	Port uint16
	// HTTP is set when routing one HTTP request on a TCP connection: a
	// cleartext request, or one decrypted by MITM. URL and user agent
	// conditions never match without it.
	HTTP *HTTPRequest
}

// HTTPRequest is the part of an HTTP request that rules can match.
type HTTPRequest struct {
	// URL is the absolute request URL, for example
	// "http://example.com/path?query". The port is omitted when it is the
	// scheme's default.
	URL       string
	UserAgent string
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
	noResolve     bool
	packetOnly    bool
	domainPending bool
	ctx           context.Context
	md            Metadata
	env           Env

	resolved        bool
	addrs           []netip.Addr
	dialAddr        netip.Addr
	resolveErr      error
	lookupRule      int
	lookupOverride  *RuleSpec
	processDone     bool
	process         string
	processOK       bool
	processUID      uint32
	processUIDKnown bool
	stopped         bool // a lookup was disallowed
	stoppedAt       int
	// httpPending is set when a URL or user agent condition was evaluated
	// without an HTTP request.
	httpPending bool
}

// httpRequest returns the request URL and user agent conditions match.
func (e *evaluation) httpRequest(index int) *HTTPRequest {
	if e.md.HTTP != nil || e.md.Network != "tcp" {
		return e.md.HTTP
	}
	e.httpPending = true
	if e.packetOnly {
		// A request may still arrive on this connection.
		e.stopped, e.stoppedAt = true, index
	}
	return nil
}

func (e *evaluation) destinationAddr(index int) (netip.Addr, bool) {
	if e.md.Addr.IsValid() {
		return e.md.Addr, true
	}
	// A pending domain can make a lookup necessary even without an address.
	if e.md.Domain == "" && !e.domainPending {
		return netip.Addr{}, false
	}
	if !e.resolved {
		if e.packetOnly {
			e.stopped, e.stoppedAt = true, index
			return netip.Addr{}, false
		}
		e.resolved = true
		if e.env == nil {
			e.resolveErr = errors.New("no resolver")
		} else {
			e.lookupRule = index
			e.addrs, e.resolveErr = e.env.Resolve(e.ctx, e.md.Domain)
		}
		if errors.Is(e.resolveErr, ErrNoLookup) {
			e.lookupRule = -1
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
		if e.packetOnly {
			e.stopped, e.stoppedAt = true, index
			return "", false
		}
		e.processDone = true
		if e.env != nil {
			if env, ok := e.env.(ProcessInfoEnv); ok {
				info, found := env.ProcessInfo(e.ctx)
				e.process, e.processOK = info.Path, found && info.Path != ""
				e.processUID, e.processUIDKnown = info.UID, found && info.UIDKnown
			} else {
				e.process, e.processOK = e.env.Process(e.ctx)
			}
		}
	}
	return e.process, e.processOK
}

func (e *evaluation) match(index int, r *rule) bool {
	md := &e.md
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
		resolved := e.resolved
		e.noResolve = old || r.spec.NoResolve
		matched := r.spec.Set.matches(e)
		e.noResolve = old
		if !resolved && e.lookupRule >= 0 {
			// Attribute a member's lookup to the rule that referenced the set.
			e.lookupRule = index
		}
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
		if r.spec.compact != nil {
			return r.spec.compact.domains.match(md.Domain)
		}
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
	case KindNetworkScene:
		return md.NetworkScene != "" && slices.Contains(r.strs, md.NetworkScene)
	case KindProcessName, KindProcessPath, KindProcessNameWildcard, KindProcessPathWildcard:
		p, ok := e.processName(index)
		if !ok {
			return false
		}
		name := p
		if r.spec.Kind == KindProcessName || r.spec.Kind == KindProcessNameWildcard {
			name = processBase(p)
		}
		for _, s := range r.strs {
			if r.spec.Kind == KindProcessNameWildcard || r.spec.Kind == KindProcessPathWildcard {
				if matchProcessWildcard(s, name) {
					return true
				}
			} else if strings.EqualFold(name, s) {
				return true
			}
		}
		return false
	case KindProcessNameRegex, KindProcessPathRegex:
		p, ok := e.processName(index)
		if !ok {
			return false
		}
		name := p
		if r.spec.Kind == KindProcessNameRegex {
			name = processBase(p)
		}
		for _, re := range r.processRegexps {
			if matched, err := re.MatchString(name); err == nil && matched {
				return true
			}
		}
		return false
	case KindURLRegex:
		request := e.httpRequest(index)
		if request == nil {
			return false
		}
		for _, re := range r.regexps {
			if re.MatchString(request.URL) {
				return true
			}
		}
		return false
	case KindUserAgent:
		request := e.httpRequest(index)
		if request == nil {
			return false
		}
		for _, pattern := range r.strs {
			if matchWildcard(pattern, request.UserAgent) {
				return true
			}
		}
		return false
	case KindInboundName:
		return md.Inbound != "" && slices.Contains(r.strs, md.Inbound)
	case KindInboundUser:
		return md.InboundUser != "" && slices.Contains(r.strs, md.InboundUser)
	case KindInboundType:
		return md.InboundType != "" && slices.Contains(r.strs, strings.ToUpper(md.InboundType))
	case KindInboundPort:
		return md.InboundPort != 0 && matchPorts(r.ports, md.InboundPort)
	case KindUID:
		e.processName(index)
		if !e.processUIDKnown || e.processUID == 0 {
			return false
		}
		for _, bounds := range r.uidRanges {
			if e.processUID >= bounds.lo && e.processUID <= bounds.hi {
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
	rules      *RuleSet
	groups     map[string]Group
	outbounds  map[string]bool
	final      string
	dnsFailure string
}

// DNSFailure values. With DNSFailureContinue a failed lookup only makes the
// IP rules that needed it not match, as in Clash.
const (
	DNSFailureContinue = "continue"
	DNSFailureFinal    = "final"
	DNSFailureReject   = "reject"
)

// Options configure New.
type Options struct {
	// Outbounds are the IDs rules and groups may end at.
	Outbounds []string
	Groups    []Group
	// Final is the target when no rule matches.
	Final string
	// DNSFailure decides a connection whose rule lookup failed before any
	// rule matched. Empty means DNSFailureContinue.
	DNSFailure string
}

// New builds a router over a compiled rule set. It checks that every
// target exists and that groups do not form a cycle.
func New(rules *RuleSet, opts Options) (*Router, error) {
	r := &Router{
		rules:      rules,
		groups:     make(map[string]Group, len(opts.Groups)),
		outbounds:  make(map[string]bool, len(opts.Outbounds)),
		final:      opts.Final,
		dnsFailure: opts.DNSFailure,
	}
	switch opts.DNSFailure {
	case "", DNSFailureContinue, DNSFailureFinal, DNSFailureReject:
	default:
		return nil, fmt.Errorf("unknown DNS failure behavior %q", opts.DNSFailure)
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
		if rules.members != nil {
			return nil, errors.New("router requires an ordered rule list")
		}
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

func (r *Router) HasTarget(id string) bool { return r.exists(id) }

// Reaches reports whether target can end at an outbound for which match is
// true, through any member of the groups it passes.
func (r *Router) Reaches(target string, match func(string) bool) bool {
	seen := map[string]bool{}
	var walk func(string) bool
	walk = func(t string) bool {
		if seen[t] {
			return false
		}
		seen[t] = true
		if g, ok := r.groups[t]; ok {
			return slices.ContainsFunc(g.Members, walk)
		}
		return match(t)
	}
	return walk(target)
}

// TargetsReach reports whether the final target or any rule's target can
// end at an outbound for which match is true.
func (r *Router) TargetsReach(match func(string) bool) bool {
	if r.Reaches(r.final, match) {
		return true
	}
	for _, rule := range r.rules.rules {
		if r.Reaches(rule.spec.Target, match) {
			return true
		}
	}
	return false
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
	Temporary bool
	Rule      RuleSpec
	Target    string
	Chain     []string
	Outbound  string
	// Resolved holds the answers when a domain was resolved for ip rules;
	// ResolveError is set when that failed (ip rules then did not match).
	Resolved     []netip.Addr
	ResolveError error
	// LookupRule is the position of the rule that first triggered a lookup,
	// in the saved rules or the supplied overrides, or -1 without a lookup.
	LookupRule     int
	lookupRuleSpec *RuleSpec
	Process        string
	// HTTPPending is set when a URL or user agent condition was evaluated
	// without an HTTP request. Routing each request on the connection may
	// then choose a different rule.
	HTTPPending bool
	// DNSFailure is set when the rule lookup failed and the router's DNS
	// failure behavior chose this decision instead of the rules after it.
	DNSFailure bool
	// UDPFallback is set by callers that send UDP direct because Outbound
	// cannot relay it; it names that outbound.
	UDPFallback string
}

// LookupRuleSpec returns the rule that triggered the lookup, if any.
func (d Decision) LookupRuleSpec() RuleSpec {
	if d.lookupRuleSpec != nil {
		return *d.lookupRuleSpec
	}
	return RuleSpec{}
}

// Route evaluates md. It never returns an error for a connection: a
// failed lookup just makes the rules that needed it not match.
func (r *Router) Route(ctx context.Context, md Metadata, env Env) Decision {
	return r.RouteWithResolver(ctx, md, env, nil)
}

// RouteWithResolver resolves observed group choices before deciding whether a
// PASS target falls through. The indexed first match remains the normal path;
// only rules after an actual PASS need a linear continuation.
func (r *Router) RouteWithResolver(ctx context.Context, md Metadata, env Env, resolve func(*Decision)) Decision {
	e := &evaluation{ctx: ctx, md: md, env: env, lookupRule: -1}
	return r.decideWithPass(e, resolve)
}
func (r *Router) decideWithPass(e *evaluation, resolve func(*Decision)) Decision {
	index := r.rules.first(e)
	for {
		if r.lookupFailedBefore(e, index) {
			return r.dnsFailureDecision(e, resolve)
		}
		d := r.decisionForRule(e, index)
		r.resolveDecision(&d)
		if resolve != nil {
			resolve(&d)
		}
		if !d.passes(index) {
			return d
		}
		var ok bool
		index, ok = r.rules.nextAfterPass(e, index, len(r.rules.rules))
		if !ok {
			return Decision{RuleIndex: -1, LookupRule: -1}
		}
	}
}

// lookupFailedBefore reports whether the rule lookup failed and no rule
// before the one that triggered it matched, so the DNS failure behavior
// decides instead of index. index is -1 when no rule matched.
func (r *Router) lookupFailedBefore(e *evaluation, index int) bool {
	if r.dnsFailure == "" || r.dnsFailure == DNSFailureContinue || e.stopped || !e.resolved {
		return false
	}
	if e.resolveErr == nil && e.dialAddr.IsValid() {
		return false
	}
	if errors.Is(e.resolveErr, ErrNoLookup) {
		return false
	}
	if e.lookupOverride != nil {
		// A temporary rule triggered the lookup, before every saved rule.
		return true
	}
	// The triggering rule itself may still match on another condition.
	return e.lookupRule >= 0 && (index < 0 || index > e.lookupRule)
}

func (r *Router) dnsFailureDecision(e *evaluation, resolve func(*Decision)) Decision {
	var d Decision
	if r.dnsFailure == DNSFailureFinal {
		d = r.decisionForRule(e, -1)
		r.resolveDecision(&d)
		if resolve != nil {
			resolve(&d)
		}
		d.passes(-1)
	} else {
		// No target: the connection fails.
		d = r.decisionForTarget(e, -1, RuleSpec{}, "")
	}
	d.DNSFailure = true
	return d
}

// passes handles PASS for a saved rule or the final target.
func (d *Decision) passes(index int) bool {
	if d.Outbound != "pass" {
		return false
	}
	if index < 0 {
		d.Outbound = ""
		return false
	}
	return true
}

// nextAfterPass scans in order up to limit, since a passed match can hide
// later matches in the domain index. Reaching a partial limit is inconclusive.
func (rs *RuleSet) nextAfterPass(e *evaluation, index, limit int) (int, bool) {
	for i := index + 1; i < limit; i++ {
		if e.match(i, rs.rules[i]) {
			return i, true
		}
		if e.stopped {
			return -1, false
		}
	}
	return -1, limit == len(rs.rules)
}

func (r *Router) decisionForRule(e *evaluation, index int) Decision {
	var spec RuleSpec
	target := r.final
	if index >= 0 {
		spec = r.rules.rules[index].spec
		target = spec.Target
	}
	return r.decisionForTarget(e, index, spec, target)
}

func (r *Router) decisionForTarget(e *evaluation, index int, spec RuleSpec, target string) Decision {
	d := Decision{
		RuleIndex: index, Rule: spec, Target: target, Resolved: e.addrs, ResolveError: e.resolveErr,
		LookupRule: e.lookupRule, Process: e.process, HTTPPending: e.httpPending,
	}
	if e.lookupRule >= 0 {
		d.lookupRuleSpec = e.lookupOverride
		if d.lookupRuleSpec == nil {
			d.lookupRuleSpec = &r.rules.rules[e.lookupRule].spec
		}
	}
	return d
}

func (r *Router) resolveDecision(d *Decision) {
	if d.Target != "" {
		// New checked every target, so resolve cannot fail here.
		d.Outbound, d.Chain, _ = r.Resolve(d.Target)
	}
}

// Explanation is a Decision plus why evaluation may not have finished.
type Explanation struct {
	Decision
	// Undetermined is set when a rule needed a lookup Explain was not
	// allowed to make; StoppedAt is that rule's position.
	Undetermined bool
	StoppedAt    int
	StoppedRule  RuleSpec
}

// Explain routes md like Route. If env.Resolve returns ErrNoLookup the
// evaluation stops there and the explanation says so, instead of
// guessing.
func (r *Router) Explain(ctx context.Context, md Metadata, env Env) Explanation {
	return r.ExplainWithResolver(ctx, md, env, nil)
}
func (r *Router) ExplainWithResolver(ctx context.Context, md Metadata, env Env, resolve func(*Decision)) Explanation {
	return r.ExplainWithOverrides(ctx, md, env, resolve, nil, time.Time{})
}

// TimedRule is one compiled rule checked before the saved rules. Its expiry
// is evaluated against the time at which the flow began routing.
type TimedRule struct {
	Match     *RuleSet
	ExpiresAt time.Time
}

func (r *Router) OverrideActive(rule TimedRule, at time.Time) bool {
	return at.Before(rule.ExpiresAt) && r.exists(rule.Match.Rule(0).Target)
}

func (r *Router) ExplainWithOverrides(ctx context.Context, md Metadata, env Env, resolve func(*Decision), overrides []TimedRule, at time.Time) Explanation {
	e := &evaluation{ctx: ctx, md: md, env: env, lookupRule: -1}
	for i, override := range overrides {
		if !r.OverrideActive(override, at) {
			continue
		}
		spec := override.Match.Rule(0)
		resolved := e.resolved
		index := override.Match.first(e)
		if e.stopped {
			return Explanation{Decision: Decision{RuleIndex: -1, LookupRule: -1}, Undetermined: true, StoppedAt: -1, StoppedRule: spec}
		}
		if !resolved && e.lookupRule >= 0 {
			e.lookupOverride = &override.Match.rules[e.lookupRule].spec
			e.lookupRule = i
		}
		if index < 0 {
			continue
		}
		d := r.decisionForTarget(e, -1, spec, spec.Target)
		r.resolveDecision(&d)
		d.Temporary = true
		if resolve != nil {
			resolve(&d)
		}
		if d.Outbound != "pass" {
			return Explanation{Decision: d}
		}
	}
	d := r.decideWithPass(e, resolve)
	if e.stopped {
		return Explanation{Decision: Decision{RuleIndex: -1, LookupRule: -1}, Undetermined: true, StoppedAt: e.stoppedAt, StoppedRule: r.rules.Rule(e.stoppedAt)}
	}
	return Explanation{Decision: d}
}

func needsProcess(r *rule) bool {
	if isProcessKind(r.spec.Kind) || r.spec.Set != nil && r.spec.Set.NeedsProcess() {
		return true
	}
	for _, ch := range r.children {
		if needsProcess(ch) {
			return true
		}
	}
	return false
}

func matchesHTTP(r *rule) bool {
	switch r.spec.Kind {
	case KindURLRegex, KindUserAgent:
		return true
	case KindRuleSet:
		return r.spec.Set.MatchesHTTP()
	}
	return slices.ContainsFunc(r.children, matchesHTTP)
}

func matchesDomain(r *rule) bool {
	switch r.spec.Kind {
	case KindDomain, KindDomainSuffix, KindDomainKeyword, KindDomainRegex, KindDomainPattern:
		return true
	case KindRuleSet:
		return r.spec.Set.MatchesDomain()
	}
	return slices.ContainsFunc(r.children, matchesDomain)
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
