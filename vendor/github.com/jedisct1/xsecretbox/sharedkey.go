package xsecretbox

import (
	crypto_rand "crypto/rand"
	"errors"

	"github.com/aead/chacha20/chacha"
	"golang.org/x/crypto/curve25519"
)

// SharedKey computes a shared secret compatible with the one used by `crypto_box_xchacha20poly1305``
func SharedKey(secretKey [32]byte, publicKey [32]byte) ([32]byte, error) {
	var sharedKey [32]byte
	curve25519.ScalarMult(&sharedKey, &secretKey, &publicKey)
	c := byte(0)
	for i := 0; i < 32; i++ {
		c |= sharedKey[i]
	}
	if c == 0 {
		if _, err := crypto_rand.Read(sharedKey[:]); err != nil {
			return sharedKey, err
		}
		return sharedKey, errors.New("weak public key")
	}
	var nonce [16]byte
	chacha.HChaCha20(&sharedKey, &nonce, &sharedKey)
	return sharedKey, nil
}
