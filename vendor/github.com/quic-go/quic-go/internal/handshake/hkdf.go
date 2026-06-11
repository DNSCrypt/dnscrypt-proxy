package handshake

import (
	"crypto"
	"crypto/hkdf"
	"encoding/binary"
	"fmt"
)

// hkdfExpandLabel HKDF expands a label as defined in RFC 8446, section 7.1.
func hkdfExpandLabel(hash crypto.Hash, secret, context []byte, label string, length int) []byte {
	b := make([]byte, 3, 3+6+len(label)+1+len(context))
	binary.BigEndian.PutUint16(b, uint16(length))
	b[2] = uint8(6 + len(label))
	b = append(b, []byte("tls13 ")...)
	b = append(b, []byte(label)...)
	b = b[:3+6+len(label)+1]
	b[3+6+len(label)] = uint8(len(context))
	b = append(b, context...)

	expanded, err := hkdf.Expand(hash.New, secret, string(b), length)
	if err != nil {
		panic(fmt.Errorf("quic: HKDF-Expand-Label invocation failed unexpectedly: %v", err))
	}
	return expanded
}
