package rulesdata

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net/netip"
	"strings"

	"github.com/klauspost/compress/zstd"
	"go4.org/netipx"
)

// MRS v1 layout is defined by the pinned mihomo reference. All lengths are
// checked against the bounded decoded buffer before allocation or traversal.
func decodeMRS(behavior string, data []byte) ([]string, error) {
	bad := errors.New("invalid MRS resource")
	z, err := zstd.NewReader(bytes.NewReader(data), zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(MaxExpanded))
	if err != nil {
		return nil, bad
	}
	defer z.Close()
	raw, err := io.ReadAll(io.LimitReader(z, MaxExpanded+1))
	if err != nil || len(raw) > MaxExpanded {
		return nil, bad
	}
	b := bytes.NewReader(raw)
	magic := make([]byte, 4)
	if _, err = io.ReadFull(b, magic); err != nil || !bytes.Equal(magic, []byte{'M', 'R', 'S', 1}) {
		return nil, bad
	}
	kind, err := b.ReadByte()
	if err != nil || (behavior != "domain" || kind != 0) && (behavior != "ipcidr" || kind != 1) {
		return nil, bad
	}
	readN := func(limit int64) (int, error) {
		var n int64
		e := binary.Read(b, binary.BigEndian, &n)
		if e != nil || n < 0 || n > limit {
			return 0, bad
		}
		return int(n), nil
	}
	count, err := readN(MaxEntries)
	if err != nil {
		return nil, bad
	}
	extra, err := readN(int64(b.Len()))
	if err != nil {
		return nil, bad
	}
	if _, err = b.Seek(int64(extra), io.SeekCurrent); err != nil {
		return nil, bad
	}
	v, err := b.ReadByte()
	if err != nil || v != 1 {
		return nil, bad
	}
	var out []string
	if kind == 1 {
		n, e := readN(min(int64(b.Len()/32), int64(MaxEntries)))
		if e != nil {
			return nil, bad
		}
		expanded := 0
		for range n {
			var lo, hi [16]byte
			if _, e = io.ReadFull(b, lo[:]); e != nil {
				return nil, bad
			}
			if _, e = io.ReadFull(b, hi[:]); e != nil {
				return nil, bad
			}
			r := netipx.IPRangeFrom(netip.AddrFrom16(lo).Unmap(), netip.AddrFrom16(hi).Unmap())
			if !r.IsValid() {
				return nil, bad
			}
			// Expand one range at a time (at most 256 prefixes). Building a
			// complete Prefixes slice first could allocate far beyond the
			// output budget on adversarial unaligned ranges.
			for _, p := range r.Prefixes() {
				value := p.String()
				expanded += len(value)
				if len(out) >= MaxEntries || expanded > MaxExpanded {
					return nil, bad
				}
				out = append(out, value)
			}
		}
		// MRS count is original line count, not compacted range/prefix count.
	} else {
		words := func() ([]uint64, error) {
			n, e := readN(int64(b.Len() / 8))
			if e != nil {
				return nil, bad
			}
			v := make([]uint64, n)
			for i := range v {
				if e = binary.Read(b, binary.BigEndian, &v[i]); e != nil {
					return nil, bad
				}
			}
			return v, nil
		}
		leaves, e := words()
		if e != nil {
			return nil, bad
		}
		bitmap, e := words()
		if e != nil {
			return nil, bad
		}
		n, e := readN(int64(b.Len()))
		if e != nil {
			return nil, bad
		}
		labels := make([]byte, n)
		if _, e = io.ReadFull(b, labels); e != nil {
			return nil, bad
		}
		bit := func(v []uint64, i int) bool { return i >= 0 && i/64 < len(v) && v[i/64]&(uint64(1)<<uint(i%64)) != 0 }
		// LOUDS nodes appear in breadth-first order. Keep parent edges rather
		// than copying every prefix (which is quadratic for a long chain).
		type node struct {
			parent int
			label  byte
			depth  int
		}
		nodes := []node{{parent: -1}}
		edge, pos, expanded := 0, 0, 0
		for id := 0; id < len(nodes); id++ {
			if id >= len(leaves)*64 || pos >= len(bitmap)*64 {
				return nil, bad
			}
			if bit(leaves, id) {
				var key []byte
				for x := id; x > 0; x = nodes[x].parent {
					key = append(key, nodes[x].label)
				}
				expanded += len(key)
				if expanded > MaxExpanded {
					return nil, bad
				}
				value := strings.TrimPrefix(string(key), "+")
				out = append(out, value)
				if len(out) > MaxEntries {
					return nil, bad
				}
			}
			for !bit(bitmap, pos) {
				if pos >= len(bitmap)*64 || edge >= len(labels) || nodes[id].depth >= 1024 || len(nodes) >= 2_000_000 {
					return nil, bad
				}
				nodes = append(nodes, node{id, labels[edge], nodes[id].depth + 1})
				edge++
				pos++
			}
			pos++
		}
		if edge != len(labels) {
			return nil, bad
		}
	}
	if b.Len() != 0 || count == 0 && len(out) != 0 {
		return nil, bad
	}
	return out, nil
}
