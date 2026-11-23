package router

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math"
	"slices"

	"github.com/sagernet/sing/common/domain"
)

// Build sing's succinct-set format. Like mihomo's DomainSet builder, keep
// only two trie levels in memory while emitting the breadth-first bitmaps.
func buildDomainMatcher(keys []string) (*domain.Matcher, uint64, error) {
	if len(keys) == 0 {
		return nil, 0, nil
	}
	slices.Sort(keys)
	keys = slices.Compact(keys)
	edges := len(keys[0])
	for i := 1; i < len(keys); i++ {
		prev, key := keys[i-1], keys[i]
		shared := 0
		for shared < min(len(prev), len(key)) && prev[shared] == key[shared] {
			shared++
		}
		edges += len(key) - shared
	}
	if edges >= math.MaxInt32/2 || uint64(len(keys)) > math.MaxUint32 {
		return nil, 0, errors.New("domain matcher exceeds index size")
	}
	nodes := edges + 1
	leafWords, labelWords := (nodes+63)/64, (nodes+edges+63)/64
	wire := make([]byte, 1, 1+3*binary.MaxVarintLen64+8*(leafWords+labelWords)+edges)
	wire, leaves := appendMatcherWords(wire, leafWords)
	wire, bitmap := appendMatcherWords(wire, labelWords)
	wire = binary.AppendUvarint(wire, uint64(edges))
	labels := wire[len(wire) : len(wire)+edges]
	wire = wire[:len(wire)+edges]

	type interval struct{ start, end uint32 }
	current := make([]interval, 1, len(keys))
	current[0] = interval{0, uint32(len(keys))}
	next := make([]interval, 0, len(keys))
	node, edge, bit := 0, 0, 0
	for depth := 0; len(current) > 0; depth++ {
		for _, group := range current {
			start := group.start
			if len(keys[start]) == depth {
				setMatcherBit(leaves, node)
				start++
			}
			for start < group.end {
				label := keys[start][depth]
				end := start + 1
				for end < group.end && keys[end][depth] == label {
					end++
				}
				next = append(next, interval{start, end})
				labels[edge] = label
				edge++
				bit++
				start = end
			}
			setMatcherBit(bitmap, bit)
			bit++
			node++
		}
		current, next = next, current[:0]
	}
	matcher, err := domain.ReadMatcher(bytes.NewReader(wire))
	return matcher, domainMatcherBytes(edges, leafWords, labelWords), err
}

func domainMatcherBytes(edges, leafWords, labelWords int) uint64 {
	// Labels, bitmap words and sing's rank/select indexes, with headroom
	// for allocator rounding and the decoded slice capacities.
	nodes := edges + 1
	retained := edges + 8*(leafWords+labelWords) + 4*(labelWords+1) + 4*((nodes+31)/32)
	return 256 + uint64(retained)*5/4
}

func appendMatcherWords(wire []byte, words int) ([]byte, []byte) {
	wire = binary.AppendUvarint(wire, uint64(words))
	start := len(wire)
	wire = wire[:start+8*words]
	return wire, wire[start:]
}

func setMatcherBit(words []byte, bit int) {
	// Bits are numbered from the least significant end of a big-endian word.
	words[bit/64*8+7-bit%64/8] |= 1 << uint(bit%8)
}
