package router

import (
	"regexp"
	"regexp/syntax"
	"unsafe"

	"go4.org/netipx"
)

type MemoryEstimate struct {
	Bytes            uint64
	LargestRule      int
	LargestRuleBytes uint64
}

// EstimateMemory estimates the retained rule storage. Referenced sets are
// counted by the caller so a shared set is charged only once.
func (rs *RuleSet) EstimateMemory() MemoryEstimate {
	estimate := MemoryEstimate{Bytes: uint64(unsafe.Sizeof(*rs)), LargestRule: -1}
	seenRegexps := make(map[*regexp.Regexp]bool)
	if members := rs.members; members != nil {
		estimate.Bytes += uint64(unsafe.Sizeof(*members)) + sliceMemory(members.rows) + sliceMemory(members.blocks) + stringSliceMemory(members.values)
		estimate.Bytes += sliceMemory(members.packed)
		for _, block := range members.blocks {
			if d := block.domains; d != nil {
				estimate.Bytes += uint64(unsafe.Sizeof(*d)) + d.bytes + stringSliceMemory(d.keywords) + regexpMemory(d.regexps, seenRegexps)
			} else {
				estimate.Bytes += compiledRuleMemory(block.general, seenRegexps)
			}
		}
		return estimate
	}

	// A string/int map entry needs 24 bytes on arm64, plus space for the
	// map's buckets and unused slots. Include the index in each rule's cost.
	const indexedDomainBytes = 40
	estimate.Bytes += sliceMemory(rs.rules) + sliceMemory(rs.others)
	indexed := make([]uint64, len(rs.rules))
	for _, index := range []map[string]int{rs.exact, rs.suffix, rs.strictSuffix} {
		for _, i := range index {
			indexed[i] += indexedDomainBytes
		}
	}
	for i, r := range rs.rules {
		bytes := compiledRuleMemory(r, seenRegexps) + indexed[i]
		estimate.Bytes += bytes
		if bytes > estimate.LargestRuleBytes {
			estimate.LargestRule, estimate.LargestRuleBytes = i, bytes
		}
	}
	return estimate
}

func compiledRuleMemory(r *rule, seenRegexps map[*regexp.Regexp]bool) uint64 {
	spec := r.spec
	bytes := uint64(unsafe.Sizeof(*r)) + uint64(len(spec.ID)+len(spec.Target)+len(spec.ResourceHash))
	bytes += stringSliceMemory(spec.Values) + stringSliceMemory(r.strs) + sliceMemory(spec.Children) + sliceMemory(r.children)
	bytes += sliceMemory(r.ports) + sliceMemory(r.uidRanges) + sliceMemory(r.prefixes)
	if spec.compact != nil {
		bytes += uint64(unsafe.Sizeof(*spec.compact)) + spec.compact.bytes
	} else if r.ipset != nil {
		// Each prefix contributes at most one range before the set merges it.
		bytes += uint64(unsafe.Sizeof(*r.ipset)) + uint64(len(r.prefixes))*uint64(unsafe.Sizeof(netipx.IPRange{}))
	}
	bytes += regexpMemory(r.regexps, seenRegexps) + sliceMemory(r.processRegexps)
	for _, re := range r.processRegexps {
		bytes += uint64(unsafe.Sizeof(*re)) + 32*uint64(len(re.String()))
	}
	for _, child := range r.children {
		bytes += compiledRuleMemory(child, seenRegexps)
	}
	return bytes
}

func sliceMemory[T any](values []T) uint64 {
	var item T
	return uint64(cap(values)) * uint64(unsafe.Sizeof(item))
}

func stringSliceMemory(values []string) uint64 {
	bytes := sliceMemory(values)
	for _, value := range values {
		bytes += uint64(len(value))
	}
	return bytes
}

func regexpMemory(regexps []*regexp.Regexp, seen map[*regexp.Regexp]bool) uint64 {
	bytes := sliceMemory(regexps)
	for _, re := range regexps {
		if seen[re] {
			continue
		}
		seen[re] = true
		expr := re.String()
		bytes += uint64(unsafe.Sizeof(*re)) + 3*uint64(len(expr))
		// Repetition can yield a program far larger than its source. Allow
		// space for the compiled instructions and the optional one-pass table.
		parsed, err := syntax.Parse(expr, syntax.Perl)
		if err != nil {
			continue
		}
		prog, err := syntax.Compile(parsed.Simplify())
		if err != nil {
			continue
		}
		bytes += 2 * (uint64(unsafe.Sizeof(*prog)) + sliceMemory(prog.Inst))
		for _, inst := range prog.Inst {
			bytes += 2 * sliceMemory(inst.Rune)
		}
	}
	return bytes
}
