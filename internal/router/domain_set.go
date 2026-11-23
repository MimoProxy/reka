package router

import (
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/sagernet/sing/common/domain"
)

type domainSet struct {
	names    *domain.Matcher
	plus     *domain.Matcher
	keywords []string
	regexps  []*regexp.Regexp
	bytes    uint64
	singKeys bool // SRS stores sing's original keys.
}

type domainSetBuilder struct {
	names, plus []string
	keywords    []string
	regexps     []*regexp.Regexp
	seenRegexps map[*regexp.Regexp]bool
}

func (b *domainSetBuilder) add(kind Kind, value string, cached map[string]*regexp.Regexp) error {
	switch kind {
	case KindDomain:
		b.names = append(b.names, reversedDomainKey(value, ""))
		return nil
	case KindDomainSuffix:
		// Sing's root label matches the apex or a preceding dot boundary.
		b.names = append(b.names, reversedDomainKey(value, "\n"))
		return nil
	case KindDomainKeyword:
		b.keywords = append(b.keywords, value)
		return nil
	case KindDomainPattern:
		switch {
		case isStrictDomainSuffix(value):
			// The leading dot is part of the key before sing's prefix label.
			b.names = append(b.names, reversedDomainKey(value, "\r"))
			return nil
		case strings.ContainsRune(value, '*') || strings.ContainsRune(value, utf8.RuneError):
			value = domainPatternExpression(value)
		case strings.HasPrefix(value, "+."):
			b.plus = append(b.plus, reversedDomainKey(value[2:], ""))
			return nil
		default:
			b.names = append(b.names, reversedDomainKey(value, ""))
			return nil
		}
	}
	re := cached[value]
	if re == nil {
		var err error
		re, err = regexp.Compile(value)
		if err != nil {
			return err
		}
		cached[value] = re
	}
	if b.seenRegexps == nil {
		b.seenRegexps = make(map[*regexp.Regexp]bool)
	}
	if !b.seenRegexps[re] {
		b.seenRegexps[re] = true
		b.regexps = append(b.regexps, re)
	}
	return nil
}

func (b *domainSetBuilder) build() (*domainSet, error) {
	names, namesBytes, err := buildDomainMatcher(b.names)
	if err != nil {
		return nil, err
	}
	plus, plusBytes, err := buildDomainMatcher(b.plus)
	if err != nil {
		return nil, err
	}
	set := &domainSet{names: names, plus: plus, keywords: b.keywords, regexps: b.regexps, bytes: namesBytes + plusBytes}
	*b = domainSetBuilder{}
	return set, nil
}

func (s *domainSet) match(name string) bool {
	if name == "" {
		return false
	}
	if s.names != nil || s.plus != nil {
		key := name
		if !s.singKeys {
			key = domainKey(name)
		}
		if s.names != nil && s.names.Match(key) {
			return true
		}
		// A literal +. pattern used (?:.+\.)? in the ordered rules. The
		// subdomain prefix must be nonempty and cannot contain a newline.
		if s.plus != nil && !strings.ContainsRune(name, '\n') {
			if s.plus.Match(key) {
				return true
			}
			for i := 1; i < len(key); i++ {
				if key[i] == '.' && s.plus.Match(key[i+1:]) {
					return true
				}
			}
		}
	}
	if slices.ContainsFunc(s.keywords, func(keyword string) bool { return strings.Contains(name, keyword) }) {
		return true
	}
	return slices.ContainsFunc(s.regexps, func(re *regexp.Regexp) bool { return re.MatchString(name) })
}

// Encode sing's reserved labels and non-ASCII bytes without changing dots
// or collapsing distinct domain bytes, even for invalid UTF-8 input.
func domainKey(s string) string {
	for i := 0; i < len(s); i++ {
		if escapedDomainByte(s[i]) {
			const hex = "0123456789abcdef"
			var key strings.Builder
			key.Grow(len(s) + 2)
			key.WriteString(s[:i])
			for ; i < len(s); i++ {
				c := s[i]
				if escapedDomainByte(c) {
					key.WriteByte('%')
					key.WriteByte(hex[c>>4])
					key.WriteByte(hex[c&15])
				} else {
					key.WriteByte(c)
				}
			}
			return key.String()
		}
	}
	return s
}

func escapedDomainByte(c byte) bool { return c >= utf8.RuneSelf || c == '%' || c == '\r' || c == '\n' }

func reversedDomainKey(name, marker string) string {
	key := domainKey(name)
	var reversed strings.Builder
	reversed.Grow(len(key) + len(marker))
	for i := len(key) - 1; i >= 0; i-- {
		reversed.WriteByte(key[i])
	}
	reversed.WriteString(marker)
	return reversed.String()
}
