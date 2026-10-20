package handshake

import (
	"crypto/cipher"
	_ "unsafe" // for go:linkname
)

// Reaching into crypto/tls is a bit of a hack, but it's the only way to get the FIPS 140
// compliant AEAD, because the standard library doesn't yet expose the NewGCMForQUIC constructor
// added in https://go-review.googlesource.com/c/go/+/723760.
// See https://github.com/golang/go/issues/79219 for details.
//
// Once the standard library exposes the necessary constructors, we can use a shared code path
// for both FIPS 140 and non-FIPS 140 modes.
//
//go:linkname cryptoTLSAEAD_AESGCMTLS13 crypto/tls.aeadAESGCMTLS13
func cryptoTLSAEAD_AESGCMTLS13(key, nonceMask []byte) cipher.AEAD

func aeadAESGCMTLS13FIPS140(key, nonceMask []byte) cipher.AEAD {
	return &tls13AESGCMAEADFIPS140{aead: cryptoTLSAEAD_AESGCMTLS13(key, nonceMask)}
}

type tls13AESGCMAEADFIPS140 struct {
	aead       cipher.AEAD
	primedSeal bool
}

func (f *tls13AESGCMAEADFIPS140) NonceSize() int { return f.aead.NonceSize() }
func (f *tls13AESGCMAEADFIPS140) Overhead() int  { return f.aead.Overhead() }

func (f *tls13AESGCMAEADFIPS140) Seal(out, nonce, plaintext, additionalData []byte) []byte {
	if !f.primedSeal {
		f.primedSeal = true
		if nonce[0]|nonce[1]|nonce[2]|nonce[3]|nonce[4]|nonce[5]|nonce[6]|nonce[7] != 0 {
			// Go's TLS 1.3 AES-GCM AEAD learns the XOR mask from the first Seal
			// call and enforces monotonically increasing packet numbers after that.
			// QUIC packet numbers don't reset on key updates, so prime it with
			// packet number 0 before the first real, non-zero packet number.
			var zeroNonce [8]byte
			f.aead.Seal(nil, zeroNonce[:], nil, nil)
		}
	}
	return f.aead.Seal(out, nonce, plaintext, additionalData)
}

func (f *tls13AESGCMAEADFIPS140) Open(out, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	return f.aead.Open(out, nonce, ciphertext, additionalData)
}
