package router

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"strings"
	"sync"

	"github.com/sagernet/sing/common/domain"
	"go4.org/netipx"
)

// WithEntryDiagnostics enables an expanded listing and a lazily counted size.
// The copy shares the immutable routing data of the original rule set.
func (rs *RuleSet) WithEntryDiagnostics() *RuleSet {
	copy := *rs
	copy.diagnosticEntryCount = sync.OnceValue(rs.countDiagnosticEntries)
	return &copy
}

// DiagnosticSize reports the number of displayed rows and whether they
// represent expanded entries.
func (rs *RuleSet) DiagnosticSize() (count int, expanded bool) {
	if rs.diagnosticEntryCount != nil {
		return rs.diagnosticEntryCount(), true
	}
	return rs.Len(), false
}

func (rs *RuleSet) countDiagnosticEntries() int {
	var count int
	if rs.members == nil {
		for _, r := range rs.rules {
			count += r.spec.countDiagnosticEntries()
		}
		return count
	}
	for _, block := range rs.members.blocks {
		if block.general != nil {
			count += block.general.spec.countDiagnosticEntries()
		}
	}
	if rs.members.packed == nil {
		return count + len(rs.members.values)
	}
	// Packed domain rows are already validated. Count values without
	// allocating strings from the cached data.
	for data := rs.members.packed; len(data) > 0; {
		size, n := binary.Uvarint(data)
		data = data[n+int(size):]
		count++
	}
	return count
}

func (r RuleSpec) countDiagnosticEntries() int {
	if len(r.Children) > 0 {
		var count int
		for _, child := range r.Children {
			count += child.countDiagnosticEntries()
		}
		return count
	}
	if r.compact == nil {
		return max(1, len(r.Values))
	}
	if matcher := r.compact.domains; matcher != nil {
		if counter, ok := any(matcher.names).(interface{ DomainCount() int }); ok {
			return counter.DomainCount()
		}
		exact, suffixes := matcher.names.Dump()
		return len(exact) + len(suffixes)
	}
	var count int
	var scratch []netip.Prefix
	walkDiagnosticIPRanges(r.compact.addresses, func(rng netipx.IPRange) bool {
		scratch = rng.AppendPrefixes(scratch[:0])
		count += len(scratch)
		return true
	})
	return count
}

// WalkDiagnosticEntries presents the expanded conditions in a rule set. A
// compound rule's operands carry their position and operator as context, so
// its values are not presented as independent rules.
func (rs *RuleSet) WalkDiagnosticEntries(yield func(spec RuleSpec, context string) bool) {
	for index := range rs.Len() {
		spec := rs.Rule(index)
		context := ""
		if len(spec.Children) > 0 {
			context = fmt.Sprintf("#%d", index+1)
		}
		if !spec.walkDiagnosticEntries(context, yield) {
			return
		}
	}
}

func (r RuleSpec) walkDiagnosticEntries(context string, yield func(RuleSpec, string) bool) bool {
	for index, child := range r.Children {
		childContext := fmt.Sprintf("%s %s[%d]", context, strings.ToUpper(r.Kind.String()), index+1)
		if !child.walkDiagnosticEntries(childContext, yield) {
			return false
		}
	}
	if len(r.Children) > 0 {
		return true
	}
	row := func(kind Kind, value string) bool {
		entry := r
		entry.Kind, entry.Values, entry.compact = kind, []string{value}, nil
		return yield(entry, context)
	}
	if r.compact == nil {
		if len(r.Values) == 0 {
			return yield(r, context)
		}
		for _, value := range r.Values {
			if !row(r.Kind, value) {
				return false
			}
		}
		return true
	}
	if matcher := r.compact.domains; matcher != nil {
		return walkDiagnosticDomains(matcher.names, func(suffix bool, value string) bool {
			kind := KindDomain
			if suffix {
				kind = KindDomainSuffix
			}
			return row(kind, value)
		})
	}
	var scratch []netip.Prefix
	return walkDiagnosticIPRanges(r.compact.addresses, func(rng netipx.IPRange) bool {
		scratch = rng.AppendPrefixes(scratch[:0])
		for _, prefix := range scratch {
			if !row(r.Kind, prefix.String()) {
				return false
			}
		}
		return true
	})
}

func walkDiagnosticDomains(matcher *domain.Matcher, yield func(bool, string) bool) bool {
	if walker, ok := any(matcher).(interface{ WalkDomains(func(bool, string) bool) }); ok {
		more := true
		walker.WalkDomains(func(suffix bool, value string) bool {
			more = yield(suffix, value)
			return more
		})
		return more
	}
	// Plain Go builds can use the pinned library without project overlays.
	exact, suffixes := matcher.Dump()
	for _, value := range exact {
		if !yield(false, value) {
			return false
		}
	}
	for _, value := range suffixes {
		if !yield(true, value) {
			return false
		}
	}
	return true
}

func walkDiagnosticIPRanges(set *netipx.IPSet, yield func(netipx.IPRange) bool) bool {
	if walker, ok := any(set).(interface {
		WalkRanges(func(netipx.IPRange) bool)
	}); ok {
		more := true
		walker.WalkRanges(func(rng netipx.IPRange) bool {
			more = yield(rng)
			return more
		})
		return more
	}
	for _, rng := range set.Ranges() {
		if !yield(rng) {
			return false
		}
	}
	return true
}
