package router

import (
	"unsafe"

	"github.com/sagernet/sing/common/domain"
	"go4.org/netipx"
)

type compactRuleValues struct {
	domains   *domainSet
	addresses *netipx.IPSet
	bytes     uint64
}

// DomainMatcherCondition uses a decoded sing trie for exact and suffix matches.
func DomainMatcherCondition(matcher *domain.Matcher, edges int) RuleSpec {
	set := &domainSet{names: matcher, singKeys: true}
	set.bytes = domainMatcherBytes(edges, (edges+64)/64, (2*edges+64)/64)
	return RuleSpec{Kind: KindDomain, compact: &compactRuleValues{
		domains: set, bytes: uint64(unsafe.Sizeof(*set)) + set.bytes,
	}}
}

// IPSetCondition uses the already-normalized ranges of a decoded IP set.
func IPSetCondition(kind Kind, set *netipx.IPSet, ranges int) RuleSpec {
	// Sing appends the ranges while decoding. Allow for spare slice capacity.
	bytes := uint64(unsafe.Sizeof(*set)) + 2*uint64(ranges)*uint64(unsafe.Sizeof(netipx.IPRange{}))
	return RuleSpec{Kind: kind, compact: &compactRuleValues{addresses: set, bytes: bytes}}
}
