// Package router matches connections against an ordered rule list and
// resolves the chosen target through select groups to an outbound ID.
//
// Rules keep Clash semantics: the first rule that matches wins, in list
// order. Domain and domain-suffix rules are indexed, but the index only
// yields candidate rule positions; the final answer is still the first
// matching position, so the index never changes which rule wins.
package router

import (
	"fmt"
	"go4.org/netipx"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/dlclark/regexp2"
)

// Kind is a rule condition type.
type Kind uint8

const (
	KindDomain Kind = iota + 1
	KindDomainSuffix
	KindDomainKeyword
	KindDomainRegex
	KindIPCIDR
	KindSrcIPCIDR
	KindDstPort
	KindSrcPort
	KindNetwork
	KindProcessName
	KindMatch
	KindAnd
	KindOr
	KindNot
	KindRuleSet
	KindGeoIP
	KindDomainPattern
	KindProcessNameRegex
	KindProcessPath
	KindProcessPathRegex
	KindProcessNameWildcard
	KindProcessPathWildcard
	KindInboundName
	KindInboundType
	KindInboundPort
	KindInboundUser
	KindUID
	KindNetworkScene
)

var kindNames = map[Kind]string{
	KindDomain:              "domain",
	KindDomainSuffix:        "domain-suffix",
	KindDomainKeyword:       "domain-keyword",
	KindDomainRegex:         "domain-regex",
	KindIPCIDR:              "ip-cidr",
	KindSrcIPCIDR:           "src-ip-cidr",
	KindDstPort:             "dst-port",
	KindSrcPort:             "src-port",
	KindNetwork:             "network",
	KindNetworkScene:        "network-scene",
	KindProcessName:         "process-name",
	KindProcessNameRegex:    "process-name-regex",
	KindProcessPath:         "process-path",
	KindProcessPathRegex:    "process-path-regex",
	KindProcessNameWildcard: "process-name-wildcard",
	KindProcessPathWildcard: "process-path-wildcard",
	KindInboundName:         "in-name",
	KindInboundType:         "in-type",
	KindInboundPort:         "in-port",
	KindInboundUser:         "in-user",
	KindUID:                 "uid",
	KindMatch:               "all",
	KindAnd:                 "and", KindOr: "or", KindNot: "not", KindRuleSet: "rule-set", KindGeoIP: "geoip", KindDomainPattern: "domain-pattern",
}

// String returns the native condition key, for example "domain-suffix".
func (k Kind) String() string {
	if s, ok := kindNames[k]; ok {
		return s
	}
	return "kind(" + strconv.Itoa(int(k)) + ")"
}

// ParseKind maps a native condition key to a Kind.
func ParseKind(s string) (Kind, bool) {
	for k, name := range kindNames {
		if name == s {
			return k, true
		}
	}
	return 0, false
}

// Kinds lists every condition key in a stable order.
func Kinds() []Kind {
	return []Kind{KindDomain, KindDomainSuffix, KindDomainKeyword, KindDomainRegex,
		KindIPCIDR, KindSrcIPCIDR, KindDstPort, KindSrcPort, KindNetwork, KindProcessName, KindMatch, KindAnd, KindOr, KindNot, KindRuleSet, KindGeoIP, KindDomainPattern, KindProcessNameRegex,
		KindProcessPath, KindProcessPathRegex, KindProcessNameWildcard, KindProcessPathWildcard, KindInboundName, KindInboundType, KindInboundPort, KindInboundUser, KindUID, KindNetworkScene}
}

// usesDestinationIP reports whether a kind matches on the destination
// address, which may require resolving a domain.
func (k Kind) usesDestinationIP() bool { return k == KindIPCIDR || k == KindGeoIP || k == KindRuleSet }

// RuleSpec is one rule before compilation. A rule matches when any of its
// Values matches.
type RuleSpec struct {
	IPInverse    bool `json:",omitempty"`
	ID           string
	Children     []RuleSpec `json:",omitempty"`
	Set          *RuleSet   `json:"-"`
	ResourceHash string     `json:",omitempty"`
	Kind         Kind
	Values       []string
	// NoResolve keeps an IP rule from resolving a domain destination; the
	// rule then only matches destinations that already are addresses.
	NoResolve bool
	Target    string
}

// String renders the rule in Clash's one-line form, for explanations.
func (r RuleSpec) String() string { return r.render(true) }
func (r RuleSpec) render(action bool) string {
	var b strings.Builder
	if r.Kind == KindMatch {
		b.WriteString("MATCH")
	} else {
		b.WriteString(strings.ToUpper(r.Kind.String()))
	}
	if r.Kind == KindAnd || r.Kind == KindOr || r.Kind == KindNot {
		for _, ch := range r.Children {
			b.WriteString(",(" + ch.render(false) + ")")
		}
	} else if r.Kind != KindMatch {
		b.WriteByte(',')
		b.WriteString(strings.Join(r.Values, "|"))
	}
	if action {
		b.WriteByte(',')
		b.WriteString(r.Target)
	}
	if r.NoResolve {
		b.WriteString(",no-resolve")
	}
	return b.String()
}

type portRange struct{ lo, hi uint16 }

type rule struct {
	spec           RuleSpec
	children       []*rule
	ipset          *netipx.IPSet
	prefixes       []netip.Prefix
	ports          []portRange
	regexps        []*regexp.Regexp
	processRegexps []*regexp2.Regexp
	uidRanges      []uidRange
	strs           []string // keywords, process names, networks (normalized)
}

// RuleError is a compile error for one rule.
type RuleError struct {
	Index int
	Value string
	Err   error
}

func (e *RuleError) Error() string {
	if e.Value != "" {
		return fmt.Sprintf("rule %d: value %q: %v", e.Index, e.Value, e.Err)
	}
	return fmt.Sprintf("rule %d: %v", e.Index, e.Err)
}

func (e *RuleError) Unwrap() error { return e.Err }

// NormalizeDomain lowercases a domain and strips one trailing dot.
func NormalizeDomain(s string) string {
	s = strings.TrimSuffix(s, ".")
	for i := 0; i < len(s); i++ {
		if c := s[i]; c >= 'A' && c <= 'Z' {
			return strings.ToLower(s)
		}
	}
	return s
}

func compileRule(index int, spec RuleSpec) (*rule, error) { return compileRuleDepth(index, spec, 0) }
func compileRuleDepth(index int, spec RuleSpec, depth int) (*rule, error) {
	r := &rule{spec: spec}
	fail := func(v string, err error) error { return &RuleError{Index: index, Value: v, Err: err} }
	if depth > 32 {
		return nil, fail("", fmt.Errorf("condition nesting exceeds 32"))
	}
	if spec.Kind == KindAnd || spec.Kind == KindOr || spec.Kind == KindNot {
		if len(spec.Values) != 0 || spec.NoResolve || len(spec.Children) == 0 || (spec.Kind == KindNot && len(spec.Children) != 1) {
			return nil, fail("", fmt.Errorf("invalid logical operands or modifiers"))
		}
		for _, child := range spec.Children {
			cr, err := compileRuleDepth(index, child, depth+1)
			if err != nil {
				return nil, err
			}
			r.children = append(r.children, cr)
		}
		return r, nil
	}
	if len(spec.Children) != 0 {
		return nil, fail("", fmt.Errorf("only logical conditions accept operands"))
	}
	if spec.Kind == KindRuleSet {
		if spec.Set == nil || len(spec.Values) != 1 {
			return nil, fail("", fmt.Errorf("unresolved rule-set"))
		}
		if depth+1+spec.Set.maxDepth > 32 {
			return nil, fail("", fmt.Errorf("rule-set nesting exceeds 32"))
		}
		return r, nil
	}
	if spec.Kind == KindGeoIP {
		if len(spec.Values) != 1 || !strings.EqualFold(spec.Values[0], "LAN") {
			return nil, fail("", fmt.Errorf("geoip needs a locked database (only LAN is builtin)"))
		}
		return r, nil
	}
	if spec.Kind == KindMatch {
		if len(spec.Values) != 0 || spec.NoResolve {
			return nil, fail("", fmt.Errorf("a match-all rule takes no values or modifiers"))
		}
		return r, nil
	}
	if len(spec.Values) == 0 {
		return nil, fail("", fmt.Errorf("%s needs at least one value", spec.Kind))
	}
	if spec.NoResolve && !spec.Kind.usesDestinationIP() && spec.Kind != KindSrcIPCIDR {
		return nil, fail("", fmt.Errorf("no-resolve only applies to ip-cidr rules"))
	}
	for _, v := range spec.Values {
		switch spec.Kind {
		case KindDomain, KindDomainSuffix:
			d := NormalizeDomain(strings.TrimPrefix(v, "."))
			if d == "" || strings.ContainsAny(d, " /,") {
				return nil, fail(v, fmt.Errorf("not a domain"))
			}
			r.strs = append(r.strs, d)
		case KindDomainKeyword:
			if v == "" {
				return nil, fail(v, fmt.Errorf("empty keyword"))
			}
			r.strs = append(r.strs, strings.ToLower(v))
		case KindDomainPattern:
			pattern := strings.ToLower(v)
			if err := ValidDomainPattern(pattern); err != nil {
				return nil, fail(v, err)
			}
			if strings.HasPrefix(pattern, ".") && !strings.ContainsAny(pattern, "*+") {
				r.strs = append(r.strs, pattern[1:])
				continue
			}
			prefix, body := "", pattern
			if strings.HasPrefix(body, "+.") {
				prefix = "(?:.+\\.)?"
				body = body[2:]
			} else if strings.HasPrefix(body, ".") {
				prefix = ".+\\."
				body = body[1:]
			}
			expr := prefix + strings.ReplaceAll(regexp.QuoteMeta(body), `\*`, `[^.]+`)
			re, err := regexp.Compile("^" + expr + "$")
			if err != nil {
				return nil, fail(v, err)
			}
			r.regexps = append(r.regexps, re)
		case KindDomainRegex:
			re, err := regexp.Compile(v)
			if err != nil {
				return nil, fail(v, err)
			}
			r.regexps = append(r.regexps, re)
		case KindIPCIDR, KindSrcIPCIDR:
			p, err := parsePrefix(v)
			if err != nil {
				return nil, fail(v, err)
			}
			r.prefixes = append(r.prefixes, p)
		case KindDstPort, KindSrcPort:
			pr, err := parsePortRange(v)
			if err != nil {
				return nil, fail(v, err)
			}
			r.ports = append(r.ports, pr)
		case KindNetwork:
			n := strings.ToLower(v)
			if n != "tcp" && n != "udp" {
				return nil, fail(v, fmt.Errorf("network must be tcp or udp"))
			}
			r.strs = append(r.strs, n)
		case KindProcessName, KindProcessPath, KindProcessNameWildcard, KindProcessPathWildcard:
			if v == "" {
				return nil, fail(v, fmt.Errorf("empty process name"))
			}
			r.strs = append(r.strs, v)
		case KindProcessNameRegex, KindProcessPathRegex:
			re, err := regexp2.Compile(v, regexp2.IgnoreCase)
			if err != nil {
				return nil, fail(v, err)
			}
			re.MatchTimeout = 50 * time.Millisecond
			r.processRegexps = append(r.processRegexps, re)
		case KindInboundName, KindInboundType, KindInboundPort, KindInboundUser, KindUID, KindNetworkScene:
			if err := compileAdvancedRule(r, v); err != nil {
				return nil, fail(v, err)
			}
		default:
			return nil, fail("", fmt.Errorf("unknown rule kind %d", spec.Kind))
		}
	}
	if len(r.prefixes) > 0 {
		var builder netipx.IPSetBuilder
		for _, p := range r.prefixes {
			builder.AddPrefix(p)
		}
		set, err := builder.IPSet()
		if err != nil {
			return nil, fail("", err)
		}
		r.ipset = set
	}
	return r, nil
}

// parsePrefix accepts a CIDR or a bare address (as a host prefix).
func parsePrefix(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, err
		}
		return netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-unmapBits(p.Addr())).Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), nil
}

func unmapBits(a netip.Addr) int {
	if a.Is4In6() {
		return 96
	}
	return 0
}

// parsePortRange accepts "443" or "1000-2000".
func parsePortRange(s string) (portRange, error) {
	lo, hi, isRange := strings.Cut(s, "-")
	a, err := strconv.ParseUint(strings.TrimSpace(lo), 10, 16)
	if err != nil {
		return portRange{}, fmt.Errorf("not a port")
	}
	if !isRange {
		return portRange{uint16(a), uint16(a)}, nil
	}
	b, err := strconv.ParseUint(strings.TrimSpace(hi), 10, 16)
	if err != nil || b < a {
		return portRange{}, fmt.Errorf("not a port range")
	}
	return portRange{uint16(a), uint16(b)}, nil
}

func matchPorts(ports []portRange, p uint16) bool {
	for _, r := range ports {
		if p >= r.lo && p <= r.hi {
			return true
		}
	}
	return false
}

func matchPrefixes(prefixes []netip.Prefix, a netip.Addr) bool {
	if !a.IsValid() {
		return false
	}
	a = a.Unmap()
	for _, p := range prefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// ValidDomainPattern checks Clash provider label wildcards before compilation.
func ValidDomainPattern(s string) error {
	if s == "" || strings.ContainsAny(s, " /,\\\t\r\n") || strings.HasSuffix(s, ".") {
		return fmt.Errorf("invalid domain pattern")
	}
	labels := strings.Split(s, ".")
	for i, label := range labels {
		if label == "" && (i != 0 || len(labels) == 1) {
			return fmt.Errorf("empty domain label")
		}
		if strings.Contains(label, "*") && label != "*" {
			return fmt.Errorf("wildcard must occupy whole label")
		}
		if strings.Contains(label, "+") && (i != 0 || label != "+" || len(labels) == 1) {
			return fmt.Errorf("invalid suffix wildcard")
		}
	}
	return nil
}
