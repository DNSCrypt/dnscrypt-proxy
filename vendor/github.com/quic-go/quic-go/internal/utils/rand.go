package utils

import (
	"crypto/rand"
	"encoding/binary"
)

// Rand is a wrapper around crypto/rand that adds some convenience functions known from math/rand.
type Rand struct {
	buf [4]byte
}

func (r *Rand) Uint32() uint32 {
	rand.Read(r.buf[:])
	return binary.BigEndian.Uint32(r.buf[:])
}

// copied from https://go.dev/src/internal/fuzz/pcg.go#L110.
func (r *Rand) Uint32N(n uint32) uint32 {
	if n == 0 {
		panic("invalid argument to Uint32N")
	}
	v := r.Uint32()
	prod := uint64(v) * uint64(n)
	low := uint32(prod)
	if low < n {
		thresh := uint32(-int32(n)) % n
		for low < thresh {
			v = r.Uint32()
			prod = uint64(v) * uint64(n)
			low = uint32(prod)
		}
	}
	return uint32(prod >> 32)
}
