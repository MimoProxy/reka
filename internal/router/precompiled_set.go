package router

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"runtime"
	"slices"

	"github.com/klauspost/compress/zstd"
	"github.com/sagernet/sing/common/domain"
)

// PrecompiledRuleSetVersion changes with either the encoding or its matching
// semantics. Like sing-box SRS and mihomo MRS, the header carries a version.
const PrecompiledRuleSetVersion = 1

const precompiledMagic = "RDS"

// MRS uses Zstandard. Use a smaller window to limit decoder memory on iOS.
const precompiledWindow = 256 << 10

const singleValueRow = 1 << 7

var errPrecompiledSet = errors.New("invalid precompiled rule set")

// MarshalPrecompiledRuleSet encodes a set with compact domain blocks.
// Like SRS, the body includes serialized sing matchers.
// Ordered display rows and general conditions follow their block boundaries.
func (rs *RuleSet) MarshalPrecompiledRuleSet(sourceSize int) ([]byte, error) {
	m := rs.members
	if m == nil || m.packed != nil || !slices.ContainsFunc(m.blocks, func(b conditionBlock) bool { return b.domains != nil }) {
		return nil, nil
	}
	var body bytes.Buffer
	var prefix [binary.MaxVarintLen64]byte
	putNumber := func(n int) { body.Write(prefix[:binary.PutUvarint(prefix[:], uint64(n))]) }
	putData := func(data []byte) {
		putNumber(len(data))
		body.Write(data)
	}
	putStrings := func(count int, value func(int) string) {
		putNumber(count)
		for i := range count {
			s := value(i)
			putNumber(len(s))
			body.WriteString(s)
		}
	}
	putMatcher := func(m *domain.Matcher) error {
		var wire bytes.Buffer
		if m != nil {
			if err := m.Write(&wire); err != nil {
				return err
			}
		}
		putData(wire.Bytes())
		return nil
	}

	putNumber(sourceSize)
	putNumber(len(m.rows))
	var size int
	for _, v := range m.values {
		size += packedValueSize(v)
	}
	putNumber(size)
	for i, block := range m.blocks {
		if block.general != nil {
			putNumber(0)
			spec, err := json.Marshal(withoutResolvedReferences(block.general.spec))
			if err != nil {
				return nil, err
			}
			putData(spec)
			continue
		}
		end := len(m.rows)
		if i+1 < len(m.blocks) {
			end = m.blocks[i+1].index
		}
		putNumber(end - block.index)
		d := block.domains
		if err := putMatcher(d.names); err != nil {
			return nil, err
		}
		if err := putMatcher(d.plus); err != nil {
			return nil, err
		}
		putStrings(len(d.keywords), func(i int) string { return d.keywords[i] })
		putStrings(len(d.regexps), func(i int) string { return d.regexps[i].String() })

		for i := block.index; i < end; i++ {
			spec := m.rule(i)
			kind := byte(spec.Kind)
			if len(spec.Values) == 1 {
				kind |= singleValueRow
			}
			body.WriteByte(kind)
		}
		for i := block.index; i < end; i++ {
			spec := m.rule(i)
			if len(spec.Values) != 1 {
				putNumber(len(spec.Values))
			}
			for _, v := range spec.Values {
				putNumber(len(v))
			}
		}
		for i := block.index; i < end; i++ {
			for _, v := range m.rule(i).Values {
				body.WriteString(v)
			}
		}
	}
	z, err := zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedBestCompression),
		zstd.WithEncoderConcurrency(1), zstd.WithWindowSize(precompiledWindow), zstd.WithSingleSegment(false))
	if err != nil {
		return nil, err
	}
	defer z.Close()
	header := append([]byte(precompiledMagic), PrecompiledRuleSetVersion)
	return z.EncodeAll(body.Bytes(), header), nil
}

func packedValueSize(s string) int {
	var prefix [binary.MaxVarintLen64]byte
	return binary.PutUvarint(prefix[:], uint64(len(s))) + len(s)
}

func withoutResolvedReferences(spec RuleSpec) RuleSpec {
	spec.ResourceHash = ""
	if len(spec.Children) > 0 {
		spec.Children = slices.Clone(spec.Children)
		for i, child := range spec.Children {
			spec.Children[i] = withoutResolvedReferences(child)
		}
	}
	return spec
}

// PrecompiledRuleSet holds domain matchers and unresolved general conditions.
type PrecompiledRuleSet struct {
	SourceSize int
	Entries    int
	members    conditionSet
}

// ReadPrecompiledRuleSet decodes and checks a cached set before any of its
// references are resolved. Referenced sets can have changed since preparation.
func ReadPrecompiledRuleSet(raw io.Reader, maxBytes, maxEntries int) (*PrecompiledRuleSet, error) {
	var header [len(precompiledMagic) + 1]byte
	if _, err := io.ReadFull(raw, header[:]); err != nil || string(header[:len(precompiledMagic)]) != precompiledMagic ||
		header[len(precompiledMagic)] != PrecompiledRuleSetVersion {
		return nil, errPrecompiledSet
	}
	z, err := zstd.NewReader(raw, zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxWindow(precompiledWindow))
	if err != nil {
		return nil, err
	}
	defer z.Close()
	limited := &io.LimitedReader{R: z, N: int64(maxBytes) + 1}
	r := &precompiledReader{bufio.NewReader(limited), maxBytes}

	var p PrecompiledRuleSet
	if p.SourceSize, err = r.number(maxBytes); err != nil {
		return nil, err
	}
	rows, err := r.number(maxEntries)
	if err != nil || rows == 0 {
		return nil, errPrecompiledSet
	}
	size, err := r.number(maxBytes)
	if err != nil || size == 0 {
		return nil, errPrecompiledSet
	}
	var prefix [binary.MaxVarintLen64]byte
	regexps := make(map[string]*regexp.Regexp)
	pos := 0
	for i := 0; i < rows; {
		count, err := r.number(rows - i)
		if err != nil {
			return nil, err
		}
		block := conditionBlock{index: i}
		if count == 0 {
			data, err := r.data()
			if err != nil {
				return nil, err
			}
			var spec RuleSpec
			if err := json.Unmarshal(data, &spec); err != nil {
				return nil, err
			}
			block.general = &rule{spec: spec}
			p.Entries += 1 + len(spec.Values)
			if p.members.rows == nil {
				p.members.rows = make([]conditionRow, rows)
			}
			p.members.rows[i].valueEnd = uint32(pos)
			i++
		} else {
			block.domains, err = r.domains(maxEntries-p.Entries, regexps)
			if err != nil {
				return nil, err
			}
			if p.members.packed == nil {
				if size >= precompiledWindow {
					// Sing grows its decoded slices incrementally. Release the
					// old slices before allocating the display rows and values.
					runtime.GC()
				}
				p.members.packed = make([]byte, size)
			}
			if p.members.rows == nil {
				p.members.rows = make([]conditionRow, rows)
			}
			end := i + count
			for j := i; j < end; j++ {
				wireKind, err := r.ReadByte()
				if err != nil || !isDomainKind(Kind(wireKind&^singleValueRow)) {
					return nil, errPrecompiledSet
				}
				p.members.rows[j].kind = Kind(wireKind)
			}
			start := pos
			for ; i < end; i++ {
				wireKind := p.members.rows[i].kind
				values := 1
				if wireKind&singleValueRow == 0 {
					values, err = r.number(maxEntries - p.Entries - 1)
					if err != nil || values < 2 {
						return nil, errPrecompiledSet
					}
				}
				p.Entries += 1 + values
				if p.Entries > maxEntries {
					return nil, errPrecompiledSet
				}
				for range values {
					n, err := r.number(size - pos)
					prefixLen := binary.PutUvarint(prefix[:], uint64(n))
					if err != nil || prefixLen+n > size-pos {
						return nil, errPrecompiledSet
					}
					pos += copy(p.members.packed[pos:], prefix[:prefixLen])
					pos += n
				}
				p.members.rows[i] = conditionRow{valueEnd: uint32(pos), kind: wireKind &^ singleValueRow}
			}
			// Keeping lengths and string data separate compresses the listing.
			for start < pos {
				n, prefix := binary.Uvarint(p.members.packed[start:pos])
				start += prefix
				if _, err := io.ReadFull(r, p.members.packed[start:start+int(n)]); err != nil {
					return nil, err
				}
				start += int(n)
			}
		}
		if p.Entries > maxEntries {
			return nil, errPrecompiledSet
		}
		p.members.blocks = append(p.members.blocks, block)
	}
	if _, err := r.ReadByte(); err != io.EOF || pos != size || limited.N == 0 {
		return nil, errPrecompiledSet
	}
	return &p, nil
}

// Build resolves and compiles the remaining general conditions in order.
// The decoded set is consumed by this method.
func (p *PrecompiledRuleSet) Build(resolve func(int, RuleSpec) (RuleSpec, error)) (*RuleSet, error) {
	m := p.members
	rs := &RuleSet{members: &m, maxDepth: 1, hasDomain: true}
	for i, block := range m.blocks {
		if block.general == nil {
			continue
		}
		spec, err := resolve(block.index, block.general.spec)
		if err != nil {
			return nil, err
		}
		r, err := compileRule(block.index, spec)
		if err != nil {
			return nil, err
		}
		m.blocks[i].general = r
		rs.maxDepth = max(rs.maxDepth, ruleDepth(r))
		rs.hasProcess = rs.hasProcess || needsProcess(r)
	}
	return rs, nil
}

type precompiledReader struct {
	*bufio.Reader
	maxBytes int
}

func (r *precompiledReader) number(limit int) (int, error) {
	n, err := binary.ReadUvarint(r.Reader)
	if err != nil || limit < 0 || n > uint64(limit) {
		return 0, errPrecompiledSet
	}
	return int(n), nil
}

func (r *precompiledReader) data() ([]byte, error) {
	n, err := r.number(r.maxBytes)
	if err != nil {
		return nil, err
	}
	data := make([]byte, n)
	_, err = io.ReadFull(r, data)
	return data, err
}

func (r *precompiledReader) domains(maxEntries int, cached map[string]*regexp.Regexp) (*domainSet, error) {
	names, namesBytes, err := r.matcher()
	if err != nil {
		return nil, err
	}
	plus, plusBytes, err := r.matcher()
	if err != nil {
		return nil, err
	}
	d := &domainSet{names: names, plus: plus, bytes: namesBytes + plusBytes}
	keywords, err := r.number(maxEntries)
	if err != nil {
		return nil, err
	}
	for range keywords {
		b, err := r.data()
		if err != nil {
			return nil, err
		}
		d.keywords = append(d.keywords, string(b))
	}
	regexps, err := r.number(maxEntries - keywords)
	if err != nil {
		return nil, err
	}
	for range regexps {
		b, err := r.data()
		if err != nil {
			return nil, err
		}
		expr := string(b)
		re := cached[expr]
		if re == nil {
			re, err = regexp.Compile(expr)
			if err != nil {
				return nil, err
			}
			cached[expr] = re
		}
		d.regexps = append(d.regexps, re)
	}
	return d, nil
}

func (r *precompiledReader) matcher() (*domain.Matcher, uint64, error) {
	size, err := r.number(r.maxBytes)
	if err != nil || size == 0 {
		return nil, 0, err
	}
	// Validate the bitmaps first and stream labels to sing without buffering
	// an extra copy of the entire matcher.
	limited := &io.LimitedReader{R: r.Reader, N: int64(size)}
	wire := bufio.NewReader(limited)
	version, err := wire.ReadByte()
	if err != nil || version != 0 {
		return nil, 0, errPrecompiledSet
	}
	remaining := func() uint64 { return uint64(limited.N) + uint64(wire.Buffered()) }
	readWords := func() ([]byte, error) {
		count, err := binary.ReadUvarint(wire)
		if err != nil || count > remaining()/8 {
			return nil, errPrecompiledSet
		}
		words := make([]byte, int(count)*8)
		_, err = io.ReadFull(wire, words)
		return words, err
	}
	leaves, err := readWords()
	if err != nil {
		return nil, 0, err
	}
	bitmap, err := readWords()
	if err != nil {
		return nil, 0, err
	}
	labels, err := binary.ReadUvarint(wire)
	if err != nil || labels != remaining() || labels == 0 {
		return nil, 0, errPrecompiledSet
	}
	edges := int(labels)
	nodes := edges + 1
	lastBit := nodes + edges
	if len(leaves)/8 != (nodes+63)/64 || len(bitmap)/8 != (lastBit+63)/64 {
		return nil, 0, errPrecompiledSet
	}
	// Verify that the breadth-first bitmap describes a single complete trie
	// before handing it to sing's rank/select reader.
	pending := 1
	for i := range len(bitmap) * 8 {
		one := bitmap[i/64*8+7-i%64/8]&(1<<uint(i%8)) != 0
		if i >= lastBit {
			if one {
				return nil, 0, errPrecompiledSet
			}
			continue
		}
		if pending == 0 {
			return nil, 0, errPrecompiledSet
		}
		if one {
			pending--
		} else {
			pending++
		}
	}
	if pending != 0 {
		return nil, 0, errPrecompiledSet
	}
	count := func(n uint64) *bytes.Reader { return bytes.NewReader(binary.AppendUvarint(nil, n)) }
	reader := io.MultiReader(
		bytes.NewReader([]byte{version}), count(uint64(len(leaves)/8)), bytes.NewReader(leaves),
		count(uint64(len(bitmap)/8)), bytes.NewReader(bitmap), count(labels), wire,
	)
	matcher, err := domain.ReadMatcher(bufio.NewReader(reader))
	return matcher, domainMatcherBytes(edges, len(leaves)/8, len(bitmap)/8), err
}
