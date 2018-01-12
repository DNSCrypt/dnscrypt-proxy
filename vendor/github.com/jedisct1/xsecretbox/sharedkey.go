package xsecretbox

import (
	"encoding/binary"
	"errors"

	"golang.org/x/crypto/curve25519"
)

func hChaCha20(inout *[32]byte) {
	v00 := uint32(0x61707865)
	v01 := uint32(0x3320646e)
	v02 := uint32(0x79622d32)
	v03 := uint32(0x6b206574)
	v04 := binary.LittleEndian.Uint32(inout[0:])
	v05 := binary.LittleEndian.Uint32(inout[4:])
	v06 := binary.LittleEndian.Uint32(inout[8:])
	v07 := binary.LittleEndian.Uint32(inout[12:])
	v08 := binary.LittleEndian.Uint32(inout[16:])
	v09 := binary.LittleEndian.Uint32(inout[20:])
	v10 := binary.LittleEndian.Uint32(inout[24:])
	v11 := binary.LittleEndian.Uint32(inout[28:])
	v12 := uint32(0)
	v13 := uint32(0)
	v14 := uint32(0)
	v15 := uint32(0)
	for i := 0; i < 20; i += 2 {
		v00 += v04
		v12 ^= v00
		v12 = (v12 << 16) | (v12 >> 16)
		v08 += v12
		v04 ^= v08
		v04 = (v04 << 12) | (v04 >> 20)
		v00 += v04
		v12 ^= v00
		v12 = (v12 << 8) | (v12 >> 24)
		v08 += v12
		v04 ^= v08
		v04 = (v04 << 7) | (v04 >> 25)
		v01 += v05
		v13 ^= v01
		v13 = (v13 << 16) | (v13 >> 16)
		v09 += v13
		v05 ^= v09
		v05 = (v05 << 12) | (v05 >> 20)
		v01 += v05
		v13 ^= v01
		v13 = (v13 << 8) | (v13 >> 24)
		v09 += v13
		v05 ^= v09
		v05 = (v05 << 7) | (v05 >> 25)
		v02 += v06
		v14 ^= v02
		v14 = (v14 << 16) | (v14 >> 16)
		v10 += v14
		v06 ^= v10
		v06 = (v06 << 12) | (v06 >> 20)
		v02 += v06
		v14 ^= v02
		v14 = (v14 << 8) | (v14 >> 24)
		v10 += v14
		v06 ^= v10
		v06 = (v06 << 7) | (v06 >> 25)
		v03 += v07
		v15 ^= v03
		v15 = (v15 << 16) | (v15 >> 16)
		v11 += v15
		v07 ^= v11
		v07 = (v07 << 12) | (v07 >> 20)
		v03 += v07
		v15 ^= v03
		v15 = (v15 << 8) | (v15 >> 24)
		v11 += v15
		v07 ^= v11
		v07 = (v07 << 7) | (v07 >> 25)
		v00 += v05
		v15 ^= v00
		v15 = (v15 << 16) | (v15 >> 16)
		v10 += v15
		v05 ^= v10
		v05 = (v05 << 12) | (v05 >> 20)
		v00 += v05
		v15 ^= v00
		v15 = (v15 << 8) | (v15 >> 24)
		v10 += v15
		v05 ^= v10
		v05 = (v05 << 7) | (v05 >> 25)
		v01 += v06
		v12 ^= v01
		v12 = (v12 << 16) | (v12 >> 16)
		v11 += v12
		v06 ^= v11
		v06 = (v06 << 12) | (v06 >> 20)
		v01 += v06
		v12 ^= v01
		v12 = (v12 << 8) | (v12 >> 24)
		v11 += v12
		v06 ^= v11
		v06 = (v06 << 7) | (v06 >> 25)
		v02 += v07
		v13 ^= v02
		v13 = (v13 << 16) | (v13 >> 16)
		v08 += v13
		v07 ^= v08
		v07 = (v07 << 12) | (v07 >> 20)
		v02 += v07
		v13 ^= v02
		v13 = (v13 << 8) | (v13 >> 24)
		v08 += v13
		v07 ^= v08
		v07 = (v07 << 7) | (v07 >> 25)
		v03 += v04
		v14 ^= v03
		v14 = (v14 << 16) | (v14 >> 16)
		v09 += v14
		v04 ^= v09
		v04 = (v04 << 12) | (v04 >> 20)
		v03 += v04
		v14 ^= v03
		v14 = (v14 << 8) | (v14 >> 24)
		v09 += v14
		v04 ^= v09
		v04 = (v04 << 7) | (v04 >> 25)
	}
	binary.LittleEndian.PutUint32(inout[0:], v00)
	binary.LittleEndian.PutUint32(inout[4:], v01)
	binary.LittleEndian.PutUint32(inout[8:], v02)
	binary.LittleEndian.PutUint32(inout[12:], v03)
	binary.LittleEndian.PutUint32(inout[16:], v12)
	binary.LittleEndian.PutUint32(inout[20:], v13)
	binary.LittleEndian.PutUint32(inout[24:], v14)
	binary.LittleEndian.PutUint32(inout[28:], v15)
}

// SharedKey computes a shared secret compatible with the one used by `crypto_box_xchacha20poly1305``
func SharedKey(secretKey [32]byte, publicKey [32]byte) ([32]byte, error) {
	var sharedKey [32]byte
	curve25519.ScalarMult(&sharedKey, &secretKey, &publicKey)
	c := byte(0)
	for i := 0; i < 32; i++ {
		c |= sharedKey[i]
	}
	if c == 0 {
		return sharedKey, errors.New("weak public key")
	}
	hChaCha20(&sharedKey)
	return sharedKey, nil
}
