package httprewrite

import (
	"math"
	"net/netip"
	"regexp"
	"regexp/syntax"
	"strconv"
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

// URLPatterns matches an ordered list of URL expressions. Finish adding
// patterns before sharing the matcher between connections.
type URLPatterns struct {
	patterns []*lazyRegexp
	index    ruleIndex
}

func (p *URLPatterns) Add(pattern string) error {
	re, parsed, err := newLazyRegexp(pattern)
	if err != nil {
		return err
	}
	p.index.add(parsed)
	p.patterns = append(p.patterns, re)
	return nil
}

// FirstMatch returns the first matching pattern's index, or -1 for no match.
func (p *URLPatterns) FirstMatch(rawURL string) int {
	first := -1
	p.index.each(rawURL, func(i int) bool {
		if p.patterns[i].MatchString(rawURL) {
			first = i
			return false
		}
		return true
	})
	return first
}

// MayMatchHTTP allows an unknown host or port before sniffing a connection.
func (p *URLPatterns) MayMatchHTTP(host string, port uint16) bool {
	var scratch httpHostBuffer
	return p.index.mayMatchHTTP(scratch.key([]byte(trimHostKey(host))), port, false)
}

// NamesHTTP is MayMatchHTTP without patterns that name no host.
func (p *URLPatterns) NamesHTTP(host string, port uint16) bool {
	var scratch httpHostBuffer
	return p.index.mayMatchHTTP(scratch.key([]byte(trimHostKey(host))), port, true)
}

// MayMatchHTTPAddr uses the destination IP when sniffing yielded no Host.
func (p *URLPatterns) MayMatchHTTPAddr(addr netip.Addr, port uint16) bool {
	var host httpHostBuffer
	return p.index.mayMatchHTTP(addr.Unmap().AppendTo(host[:0]), port, false)
}

type ruleIndex struct {
	byHost      map[string][]int
	generic     []int
	plainPorts  []plainPort
	ports       map[plainPort]bool
	genericHTTP bool
}

// A positive port denotes an exact match. An explicit port in the URL
// excludes the default HTTP port, which the relay omits.
type plainPort int32

const (
	noPlainHTTP  plainPort = -2
	explicitPort plainPort = -1
	anyPort      plainPort = 0
	// sing-box common/urltest and mihomo listener/http default HTTP to 80.
	defaultHTTPPort = 80
)

func (p plainPort) matches(port uint16) bool {
	return p != noPlainHTTP && (port == 0 || p == anyPort || p == plainPort(port) || p == explicitPort && port != defaultHTTPPort)
}

// add receives patterns in their original order.
func (r *ruleIndex) add(parsed *syntax.Regexp) {
	index := len(r.plainPorts)
	host, port := regexpAuthority(parsed)
	r.plainPorts = append(r.plainPorts, port)
	if port != noPlainHTTP {
		if r.ports == nil {
			r.ports = make(map[plainPort]bool)
		}
		r.ports[port] = true
	}
	if host == "" {
		r.generic = append(r.generic, index)
		r.genericHTTP = r.genericHTTP || port != noPlainHTTP
		return
	}
	if r.byHost == nil {
		r.byHost = make(map[string][]int)
	}
	r.byHost[host] = append(r.byHost[host], index)
}

// With named set, rules that name no host, and so can match any port, are
// ignored.
func (r *ruleIndex) mayMatchHTTP(host []byte, port uint16, named bool) bool {
	if r.genericHTTP && !named {
		return true
	}
	if len(r.ports) == 0 {
		return false
	}
	if len(host) == 0 {
		return port == 0 || r.ports[plainPort(port)] || port != defaultHTTPPort && r.ports[explicitPort]
	}
	for _, i := range r.byHost[string(host)] {
		if r.plainPorts[i].matches(port) {
			return true
		}
	}
	return false
}

func (r *ruleIndex) each(rawURL string, visit func(int) bool) {
	if len(r.plainPorts) == 0 {
		return
	}
	host, known := indexURLHost(rawURL)
	if !known {
		for index := range r.plainPorts {
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

// regexpAuthority recognizes a mandatory authority after an anchored scheme.
// Unbounded host literals must stay generic because a longer name can match.
func regexpAuthority(re *syntax.Regexp) (string, plainPort) {
	if re.Op != syntax.OpConcat || len(re.Sub) < 2 || re.Sub[0].Op != syntax.OpBeginText {
		return "", anyPort
	}
	parts := re.Sub[1:]
	literal := caseSensitiveLiteral(parts[0])
	var authority string
	port := anyPort
	switch {
	case strings.HasPrefix(literal, "https://"):
		authority = literal[len("https://"):]
		port = noPlainHTTP
	case strings.HasPrefix(literal, "http://"):
		authority = literal[len("http://"):]
	case literal == "http" && len(parts) >= 3 && parts[1].Op == syntax.OpQuest && caseSensitiveLiteral(parts[1].Sub[0]) == "s":
		parts = parts[2:]
		var ok bool
		authority, ok = strings.CutPrefix(caseSensitiveLiteral(parts[0]), "://")
		if !ok {
			return "", anyPort
		}
	default:
		return "", anyPort
	}

	host := indexHostLiteral(authority)
	if host == "" {
		return "", port
	}
	rest := authority[len(host):]
	ends := len(parts) >= 2 && parts[1].Op == syntax.OpEndText
	if rest == "" && !ends || rest != "" && !strings.ContainsRune("/:?", rune(rest[0])) {
		return "", port
	}
	host = strings.Clone(indexHostKey(host))
	if port == noPlainHTTP {
		return host, port
	}
	portText, explicit := strings.CutPrefix(rest, ":")
	if !explicit {
		return host, defaultHTTPPort
	}
	if end := strings.IndexAny(portText, "/?"); end >= 0 {
		portText, ends = portText[:end], true
	}
	if !ends {
		return host, explicitPort
	}
	number, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || number == defaultHTTPPort || number == 0 || portText[0] == '0' {
		return host, noPlainHTTP
	}
	return host, plainPort(number)
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
	return indexHostKey(host), true
}

func indexHostKey(host string) string {
	return strings.ToLower(trimHostKey(host))
}

func trimHostKey(host string) string {
	return strings.TrimSuffix(strings.TrimSuffix(strings.TrimPrefix(host, "["), "]"), ".")
}

// mihomo's SOCKS5 domain wire format allows up to 255 hostname bytes.
type httpHostBuffer [math.MaxUint8]byte

func (b *httpHostBuffer) key(host []byte) []byte {
	for i, c := range host {
		if c >= 'A' && c <= 'Z' {
			key := append(b[:0], host...)
			for j := i; j < len(key); j++ {
				if key[j] >= 'A' && key[j] <= 'Z' {
					key[j] += 'a' - 'A'
				}
			}
			return key
		}
	}
	return host
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
