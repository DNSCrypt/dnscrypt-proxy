package xsecretbox

import (
	crypto_rand "crypto/rand"

	"golang.org/x/crypto/curve25519"
)

// SharedKey computes a shared secret compatible with the one used by `crypto_box_xchacha20poly1305``
func SharedKey(secretKey [32]byte, publicKey [32]byte) ([32]byte, error) {
	var key [32]byte
	xKey, err := curve25519.X25519(secretKey[:], publicKey[:])
	if err != nil {
		if _, err2 := crypto_rand.Read(key[:]); err != nil {
			return key, err2
		}
		return key, err
	}
	copy(key[:], xKey)
	return key, nil
}
