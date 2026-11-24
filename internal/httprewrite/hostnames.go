package httprewrite

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"unicode/utf8"
)

// HostnameError identifies an invalid entry in a MITM hostname list.
type HostnameError struct {
	Index int
	Err   error
}

func (e HostnameError) Error() string {
	return fmt.Sprintf("hostname at index %d: %v", e.Index, e.Err)
}

func (e HostnameError) Unwrap() error { return e.Err }

// HostnameErrors contains the invalid entries in their original order.
type HostnameErrors []HostnameError

func (e HostnameErrors) Error() string {
	var message strings.Builder
	for i, entry := range e {
		if i > 0 {
			message.WriteString("\n")
		}
		message.WriteString(entry.Error())
	}
	return message.String()
}

type hostnameKey struct {
	host string
	port uint16
}

type hostnameMatch struct {
	position int // zero means no match
	exclude  bool
}

type hostnamePattern struct {
	key   hostnameKey
	match hostnameMatch
}

// Hostnames is an immutable, ordered MITM hostname matcher.
type Hostnames struct {
	exact    map[hostnameKey]hostnameMatch
	suffix   map[hostnameKey]hostnameMatch
	wildcard []hostnamePattern
}

// NewHostnames validates the entries and builds an ordered matcher.
func NewHostnames(entries []string) (*Hostnames, error) {
	h := &Hostnames{}
	var invalid HostnameErrors
	for i, entry := range entries {
		host, exclude := strings.CutPrefix(entry, "-")
		key, err := parseHostname(host)
		if err != nil {
			invalid = append(invalid, HostnameError{Index: i, Err: err})
			continue
		}
		match := hostnameMatch{position: i + 1, exclude: exclude}
		switch {
		case !strings.ContainsAny(key.host, "*?"):
			addHostname(&h.exact, key, match)
		case strings.HasPrefix(key.host, "*.") && !strings.ContainsAny(key.host[2:], "*?"):
			key.host = key.host[1:]
			addHostname(&h.suffix, key, match)
		default:
			h.wildcard = append(h.wildcard, hostnamePattern{key: key, match: match})
		}
	}
	if len(invalid) > 0 {
		return nil, invalid
	}
	return h, nil
}

func addHostname(entries *map[hostnameKey]hostnameMatch, key hostnameKey, match hostnameMatch) {
	if *entries == nil {
		*entries = make(map[hostnameKey]hostnameMatch)
	}
	if _, exists := (*entries)[key]; !exists {
		(*entries)[key] = match
	}
}

func parseHostname(entry string) (hostnameKey, error) {
	key := hostnameKey{port: 443}
	var port string
	var hasPort bool
	if literal, bracketed := strings.CutPrefix(entry, "["); bracketed {
		host, rest, closed := strings.Cut(literal, "]")
		addr, err := netip.ParseAddr(host)
		if !closed || err != nil || !addr.Is6() || addr.Zone() != "" {
			return key, fmt.Errorf("expected a bracketed IPv6 address")
		}
		key.host = addr.String()
		if rest != "" {
			port, hasPort = strings.CutPrefix(rest, ":")
			if !hasPort {
				return key, fmt.Errorf("expected a port after the IPv6 address")
			}
		}
	} else {
		host, portText, explicitPort := strings.Cut(entry, ":")
		if strings.ContainsRune(portText, ':') {
			return key, fmt.Errorf("IPv6 addresses must be enclosed in brackets")
		}
		if !validHostname(host, true) {
			return key, fmt.Errorf("expected a nonempty hostname with only letters, digits, dots, hyphens, underscores or wildcards")
		}
		key.host = strings.ToLower(host)
		port, hasPort = portText, explicitPort
	}
	if hasPort {
		var err error
		key.port, err = parseHostnamePort(port)
		if err != nil {
			return key, err
		}
	}
	return key, nil
}

func parseHostnamePort(port string) (uint16, error) {
	value, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return 0, fmt.Errorf("expected a port from 0 to 65535")
	}
	return uint16(value), nil
}

func validHostname(host string, wildcard bool) bool {
	if host == "" {
		return false
	}
	for i := range len(host) {
		c := host[i]
		switch {
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9':
		case c == '.', c == '-', c == '_':
		case wildcard && (c == '*' || c == '?'):
		default:
			return false
		}
	}
	return true
}

// Match reports whether the first matching entry enables decryption.
func (h *Hostnames) Match(host string, port uint16) bool {
	if h == nil || host == "" {
		return false
	}
	bracketed := strings.HasPrefix(host, "[")
	if bracketed {
		if !strings.HasSuffix(host, "]") {
			return false
		}
		host = host[1 : len(host)-1]
	}
	host = strings.ToLower(host)
	exact := host
	if bracketed || strings.ContainsRune(host, ':') {
		if addr, err := netip.ParseAddr(host); err == nil && addr.Is6() {
			// Exact addresses compare by value; globs use the original hostname spelling.
			exact = addr.String()
		} else if bracketed {
			return false
		}
	}
	best := indexedHostname(h.exact, exact, port)
	for suffix := host; len(h.suffix) != 0; {
		dot := strings.IndexByte(suffix, '.')
		if dot < 0 {
			break
		}
		best = earlierHostname(best, indexedHostname(h.suffix, suffix[dot:], port))
		suffix = suffix[dot+1:]
	}
	for _, pattern := range h.wildcard {
		if best.position != 0 && pattern.match.position >= best.position {
			break
		}
		if (pattern.key.port == 0 || pattern.key.port == port) && hostnameGlob(pattern.key.host, host) {
			best = pattern.match
			break
		}
	}
	return best.position != 0 && !best.exclude
}

func indexedHostname(index map[hostnameKey]hostnameMatch, host string, port uint16) hostnameMatch {
	return earlierHostname(index[hostnameKey{host: host, port: port}], index[hostnameKey{host: host}])
}

func earlierHostname(a, b hostnameMatch) hostnameMatch {
	if b.position != 0 && (a.position == 0 || b.position < a.position) {
		return b
	}
	return a
}

// hostnameGlob matches ASCII patterns. A question mark consumes a whole rune
// and a star can span labels or match an empty sequence.
func hostnameGlob(pattern, host string) bool {
	star := -1
	var patternPos, hostPos, starEnd int
	for hostPos < len(host) {
		switch {
		case patternPos < len(pattern) && pattern[patternPos] == '*':
			star, starEnd = patternPos, hostPos
			patternPos++
		case patternPos < len(pattern) && pattern[patternPos] == '?':
			_, width := utf8.DecodeRuneInString(host[hostPos:])
			hostPos += width
			patternPos++
		case patternPos < len(pattern) && pattern[patternPos] == host[hostPos]:
			hostPos++
			patternPos++
		case star >= 0:
			_, width := utf8.DecodeRuneInString(host[starEnd:])
			starEnd += width
			hostPos, patternPos = starEnd, star+1
		default:
			return false
		}
	}
	for patternPos < len(pattern) && pattern[patternPos] == '*' {
		patternPos++
	}
	return patternPos == len(pattern)
}
