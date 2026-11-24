package httprewrite

import (
	"net/netip"
	"regexp"
	"regexp/syntax"
	"strings"
	"sync"
)

type lazyRegexp struct {
	pattern string
	// required is a literal that every match contains. Checking it first
	// avoids compiling rules that cannot match, which matters for rules the
	// host index cannot place.
	required string
	once     sync.Once
	regexp   *regexp.Regexp
}

func newLazyRegexp(pattern string) (*lazyRegexp, *syntax.Regexp, error) {
	parsed, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return nil, nil, err
	}
	return &lazyRegexp{pattern: pattern, required: requiredLiteral(parsed)}, parsed, nil
}

// minRequiredLiteral skips literals too short to reject many inputs.
const minRequiredLiteral = 4

// requiredLiteral returns the longest case-sensitive literal that is a direct
// part of a top-level concatenation. Any string the expression matches
// contains it.
func requiredLiteral(re *syntax.Regexp) string {
	if re.Op == syntax.OpLiteral {
		return strings.Clone(caseSensitiveLiteral(re))
	}
	if re.Op != syntax.OpConcat {
		return ""
	}
	best := ""
	for _, sub := range re.Sub {
		if literal := caseSensitiveLiteral(sub); len(literal) > len(best) {
			best = literal
		}
	}
	if len(best) < minRequiredLiteral {
		return ""
	}
	return strings.Clone(best)
}

// MatchString compiles the expression only when s contains its required literal.
func (r *lazyRegexp) MatchString(s string) bool {
	return r.mayMatch(s) && r.get().MatchString(s)
}

func (r *lazyRegexp) mayMatch(s string) bool {
	return r.required == "" || strings.Contains(s, r.required)
}

func (r *lazyRegexp) get() *regexp.Regexp {
	r.once.Do(func() {
		// regexp.Compile parses with the same flags used during validation.
		r.regexp = regexp.MustCompile(r.pattern)
	})
	return r.regexp
}

type ruleIndex struct {
	byHost  map[string][]int
	generic []int
	all     []int
}

// add receives rule indices in their original order.
func (r *ruleIndex) add(index int, parsed *syntax.Regexp) {
	r.all = append(r.all, index)
	host := regexpHostname(parsed)
	if host == "" {
		r.generic = append(r.generic, index)
		return
	}
	if r.byHost == nil {
		r.byHost = make(map[string][]int)
	}
	r.byHost[host] = append(r.byHost[host], index)
}

func (r *ruleIndex) each(rawURL string, visit func(int) bool) {
	if len(r.all) == 0 {
		return
	}
	host, known := indexURLHost(rawURL)
	if !known {
		for _, index := range r.all {
			if !visit(index) {
				return
			}
		}
		return
	}

	indexed, generic := r.byHost[host], r.generic
	for len(indexed) > 0 || len(generic) > 0 {
		if len(generic) == 0 || len(indexed) > 0 && indexed[0] < generic[0] {
			if !visit(indexed[0]) {
				return
			}
			indexed = indexed[1:]
		} else {
			if !visit(generic[0]) {
				return
			}
			generic = generic[1:]
		}
	}
}

// regexpHostname recognizes mandatory, case-sensitive host literals following
// an absolute start anchor and an HTTP scheme. A delimiter bounds the host
// in the raw URL. Both keys are lowercased, so case differences can only add
// candidates. Matching still uses the original URL and regexp, preserving
// their case-sensitive behavior.
func regexpHostname(re *syntax.Regexp) string {
	if re.Op != syntax.OpConcat || len(re.Sub) < 2 || re.Sub[0].Op != syntax.OpBeginText {
		return ""
	}
	parts := re.Sub[1:]
	literal := caseSensitiveLiteral(parts[0])
	var authority string
	switch {
	case strings.HasPrefix(literal, "https://"):
		authority = literal[len("https://"):]
	case strings.HasPrefix(literal, "http://"):
		authority = literal[len("http://"):]
	case literal == "http" && len(parts) >= 3 && parts[1].Op == syntax.OpQuest && caseSensitiveLiteral(parts[1].Sub[0]) == "s":
		parts = parts[2:]
		var ok bool
		authority, ok = strings.CutPrefix(caseSensitiveLiteral(parts[0]), "://")
		if !ok {
			return ""
		}
	default:
		return ""
	}

	host := indexHostLiteral(authority)
	if host == "" {
		return ""
	}
	if rest := authority[len(host):]; rest != "" {
		if !strings.ContainsRune("/:?", rune(rest[0])) {
			return ""
		}
	} else if len(parts) < 2 || parts[1].Op != syntax.OpEndText {
		// An unbounded literal at the end of the regexp can still match the
		// start of a longer hostname, so it must stay in the generic list.
		return ""
	}
	return strings.Clone(strings.ToLower(host))
}

func caseSensitiveLiteral(re *syntax.Regexp) string {
	if re.Op == syntax.OpLiteral && re.Flags&syntax.FoldCase == 0 {
		return string(re.Rune)
	}
	return ""
}

// indexURLHost uses the raw authority seen by the regexp. For forms with
// userinfo, escaping, or other ambiguous syntax, a linear scan preserves
// matches against text that resembles the beginning of an authority.
func indexURLHost(rawURL string) (string, bool) {
	authority, ok := strings.CutPrefix(rawURL, "https://")
	if !ok {
		authority, ok = strings.CutPrefix(rawURL, "http://")
		if !ok {
			return "", false
		}
	}
	if end := strings.IndexAny(authority, "/?#"); end >= 0 {
		authority = authority[:end]
	}
	host := indexHostLiteral(authority)
	if host == "" {
		return "", false
	}
	if rest := authority[len(host):]; rest != "" {
		port, ok := strings.CutPrefix(rest, ":")
		if !ok {
			return "", false
		}
		if _, err := parseHostnamePort(port); err != nil {
			return "", false
		}
	}
	return strings.ToLower(host), true
}

func indexHostLiteral(authority string) string {
	if literal, bracketed := strings.CutPrefix(authority, "["); bracketed {
		host, _, closed := strings.Cut(literal, "]")
		addr, err := netip.ParseAddr(host)
		if closed && err == nil && addr.Is6() && addr.Zone() == "" {
			return authority[:len(host)+2]
		}
		return ""
	}
	if end := strings.IndexAny(authority, "/:?"); end >= 0 {
		authority = authority[:end]
	}
	if !validHostname(authority, false) {
		return ""
	}
	return authority
}
