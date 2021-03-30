package xsecretbox

import (
	crypto_rand "crypto/rand"

	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/curve25519"
)

// SharedKey computes a shared secret compatible with the one used by `crypto_box_xchacha20poly1305``
func SharedKey(secretKey [32]byte, publicKey [32]byte) ([32]byte, error) {
	dhKey, err := curve25519.X25519(secretKey[:], publicKey[:])
	var subKey []byte
	if err == nil {
		var nonce [16]byte
		subKey, err = chacha20.HChaCha20(dhKey[:], nonce[:])
	}
	var key [32]byte
	if err != nil {
		if _, err2 := crypto_rand.Read(key[:]); err != nil {
			return key, err2
		}
		return key, err
	}
	copy(key[:], subKey)
	return key, nil
}
