package router

import (
	"cmp"
	"encoding/binary"
	"fmt"
	"math"
	"regexp"
	"slices"
)

type conditionSet struct {
	rows   []conditionRow
	values []string
	blocks []conditionBlock
	packed []byte // Length-prefixed display values for precompiled rows.
}

// Keep the original order and spelling for the rule listing.
type conditionRow struct {
	valueEnd uint32
	kind     Kind // Zero marks a general rule stored in blocks.
}

type conditionBlock struct {
	index   int
	domains *domainSet
	general *rule
}

// ConditionSetBuilder compiles the members of a referenced rule set. Its
// zero value is ready to use. Add errors must be handled before Build.
type ConditionSetBuilder struct {
	members     conditionSet
	domains     domainSetBuilder
	domainStart int
	regexps     map[string]*regexp.Regexp
	maxDepth    int
	hasDomain   bool
	hasProcess  bool
	hasHTTP     bool
}

// GrowDomains reserves space for single-value domain rows.
func (b *ConditionSetBuilder) GrowDomains(count int) {
	b.members.rows = slices.Grow(b.members.rows, count)
	b.members.values = slices.Grow(b.members.values, count)
	b.domains.names = slices.Grow(b.domains.names, count)
}

func (b *ConditionSetBuilder) Add(spec RuleSpec) error {
	if spec.ID == "" && spec.Target == "" && spec.Set == nil && spec.ResourceHash == "" && spec.compact == nil &&
		len(spec.Children) == 0 && !spec.NoResolve && !spec.IPInverse && isDomainKind(spec.Kind) {
		return b.AddDomain(spec.Kind, spec.Values...)
	}
	index := len(b.members.rows)
	r, err := compileRule(index, spec)
	if err != nil {
		return err
	}
	if err := b.flushDomains(); err != nil {
		return err
	}
	b.members.blocks = append(b.members.blocks, conditionBlock{index: index, general: r})
	b.members.rows = append(b.members.rows, conditionRow{valueEnd: uint32(len(b.members.values))})
	b.domainStart = len(b.members.rows)
	b.maxDepth = max(b.maxDepth, ruleDepth(r))
	b.hasDomain = b.hasDomain || matchesDomain(r)
	b.hasProcess = b.hasProcess || needsProcess(r)
	b.hasHTTP = b.hasHTTP || matchesHTTP(r)
	return nil
}

func (b *ConditionSetBuilder) AddDomain(kind Kind, values ...string) error {
	index := len(b.members.rows)
	if !isDomainKind(kind) {
		return &RuleError{Index: index, Err: fmt.Errorf("invalid domain condition %s", kind)}
	}
	if len(values) == 0 {
		return &RuleError{Index: index, Err: fmt.Errorf("%s needs at least one value", kind)}
	}
	if uint64(len(b.members.values))+uint64(len(values)) > math.MaxUint32 {
		return &RuleError{Index: index, Err: fmt.Errorf("too many domain values")}
	}
	if b.regexps == nil && (kind == KindDomainRegex || kind == KindDomainPattern) {
		b.regexps = make(map[string]*regexp.Regexp)
	}
	for _, raw := range values {
		value, err := normalizeDomainRuleValue(kind, raw)
		if err == nil {
			err = b.domains.add(kind, value, b.regexps)
		}
		if err != nil {
			return &RuleError{Index: index, Value: raw, Err: err}
		}
	}
	b.members.values = append(b.members.values, values...)
	b.members.rows = append(b.members.rows, conditionRow{valueEnd: uint32(len(b.members.values)), kind: kind})
	b.maxDepth = max(b.maxDepth, 1)
	b.hasDomain = true
	return nil
}

func (b *ConditionSetBuilder) flushDomains() error {
	if b.domainStart == len(b.members.rows) {
		return nil
	}
	set, err := b.domains.build()
	if err != nil {
		return err
	}
	b.members.blocks = append(b.members.blocks, conditionBlock{index: b.domainStart, domains: set})
	return nil
}

// Build returns the immutable condition set and resets the builder.
func (b *ConditionSetBuilder) Build() (*RuleSet, error) {
	if err := b.flushDomains(); err != nil {
		return nil, err
	}
	members := b.members
	set := &RuleSet{members: &members, maxDepth: b.maxDepth, hasDomain: b.hasDomain, hasProcess: b.hasProcess, hasHTTP: b.hasHTTP}
	*b = ConditionSetBuilder{}
	return set, nil
}

func (s *conditionSet) rule(i int) RuleSpec {
	row := s.rows[i]
	if row.kind == 0 {
		block, _ := slices.BinarySearchFunc(s.blocks, i, func(b conditionBlock, i int) int { return cmp.Compare(b.index, i) })
		return s.blocks[block].general.spec
	}
	var start uint32
	if i > 0 {
		start = s.rows[i-1].valueEnd
	}
	if s.packed != nil {
		var values []string
		for data := s.packed[start:row.valueEnd]; len(data) > 0; {
			size, n := binary.Uvarint(data)
			data = data[n:]
			values = append(values, string(data[:size]))
			data = data[size:]
		}
		return RuleSpec{Kind: row.kind, Values: values}
	}
	return RuleSpec{Kind: row.kind, Values: s.values[start:row.valueEnd:row.valueEnd]}
}

func (rs *RuleSet) matches(e *evaluation) bool {
	if rs.members == nil {
		return rs.first(e) >= 0
	}
	// Domain conditions between general rules can be combined. General
	// rules stay in order so early matches still suppress DNS/process lookups.
	for _, block := range rs.members.blocks {
		if block.domains != nil {
			if block.domains.match(e.md.Domain) {
				return true
			}
		} else if e.match(block.index, block.general) {
			return true
		}
		if e.stopped {
			return false
		}
	}
	return false
}

func isDomainKind(kind Kind) bool {
	return kind == KindDomain || kind == KindDomainSuffix || kind == KindDomainKeyword || kind == KindDomainRegex || kind == KindDomainPattern
}
