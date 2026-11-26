package tools

import "encoding/binary"

// XorShift128Plus - a pseudorandom number generator
type XorShift128Plus struct {
	s [2]uint64
}

func (r *XorShift128Plus) Next() uint64 {
	x := r.s[0]
	y := r.s[1]
	r.s[0] = y
	x ^= x << 23
	x ^= y ^ (x >> 17) ^ (y >> 26)
	r.s[1] = x
	return x + y
}

func (r *XorShift128Plus) InitFromBin(bin []byte) {
	var seed [16]byte
	copy(seed[:], bin)
	r.s[0] = binary.LittleEndian.Uint64(seed[:8])
	r.s[1] = binary.LittleEndian.Uint64(seed[8:])
}

func (r *XorShift128Plus) InitFromBinAndLength(bin []byte, length int) {
	var seed [16]byte
	copy(seed[:], bin)
	binary.LittleEndian.PutUint16(seed[:], uint16(length))
	r.InitFromBin(seed[:])
	for range 4 {
		r.Next()
	}
}
