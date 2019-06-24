package xsecretbox

import (
	"errors"

	"github.com/aead/chacha20/chacha"
	"github.com/cloudflare/circl/dh/x25519"
)

// SharedKey computes a shared secret compatible with the one used by `crypto_box_xchacha20poly1305``
func SharedKey(secretKey [32]byte, publicKey [32]byte) ([32]byte, error) {
	var sharedKey [32]byte
	var cfSharedKey, cfSecretKey, cfPublicKey x25519.Key
	copy(cfSecretKey[:], secretKey[:])
	copy(cfPublicKey[:], publicKey[:])
	if !x25519.Shared(&cfSharedKey, &cfSecretKey, &cfPublicKey) {
		return sharedKey, errors.New("weak public key")
	}
	HChaCha20(&sharedKey)
	return sharedKey, nil
}

// HChaCha20 - Hash the result of an X25519 key exchange in order to get a box-compatible shared secret
func HChaCha20(sharedKey *[32]byte) {
	var zeroNonce [16]byte
	chacha.HChaCha20(sharedKey, &zeroNonce, sharedKey)
}
