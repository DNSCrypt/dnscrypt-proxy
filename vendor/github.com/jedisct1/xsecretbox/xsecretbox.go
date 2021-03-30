package xsecretbox

import (
	"crypto/subtle"
	"errors"

	"github.com/aead/chacha20/chacha"
	"github.com/aead/poly1305"
)

const (
	// KeySize is what the name suggests
	KeySize = 32
	// NonceSize is what the name suggests
	NonceSize = 24
	// TagSize is what the name suggests
	TagSize = 16
)

// Seal does what the name suggests
func Seal(out, nonce, message, key []byte) []byte {
	if len(nonce) != NonceSize {
		panic("unsupported nonce size")
	}
	if len(key) != KeySize {
		panic("unsupported key size")
	}

	var firstBlock [64]byte
	cipher, _ := chacha.NewCipher(nonce, key, 20)
	cipher.XORKeyStream(firstBlock[:], firstBlock[:])
	var polyKey [32]byte
	copy(polyKey[:], firstBlock[:32])

	ret, out := sliceForAppend(out, TagSize+len(message))
	firstMessageBlock := message
	if len(firstMessageBlock) > 32 {
		firstMessageBlock = firstMessageBlock[:32]
	}

	tagOut := out
	out = out[poly1305.TagSize:]
	for i, x := range firstMessageBlock {
		out[i] = firstBlock[32+i] ^ x
	}
	message = message[len(firstMessageBlock):]
	ciphertext := out
	out = out[len(firstMessageBlock):]

	cipher.SetCounter(1)
	cipher.XORKeyStream(out, message)

	var tag [TagSize]byte
	hash := poly1305.New(polyKey)
	hash.Write(ciphertext)
	hash.Sum(tag[:0])
	copy(tagOut, tag[:])

	return ret
}

// Open does what the name suggests
func Open(out, nonce, box, key []byte) ([]byte, error) {
	if len(nonce) != NonceSize {
		panic("unsupported nonce size")
	}
	if len(key) != KeySize {
		panic("unsupported key size")
	}
	if len(box) < TagSize {
		return nil, errors.New("ciphertext is too short")
	}

	var firstBlock [64]byte
	cipher, _ := chacha.NewCipher(nonce, key, 20)
	cipher.XORKeyStream(firstBlock[:], firstBlock[:])
	var polyKey [32]byte
	copy(polyKey[:], firstBlock[:32])

	var tag [TagSize]byte
	ciphertext := box[TagSize:]
	hash := poly1305.New(polyKey)
	hash.Write(ciphertext)
	hash.Sum(tag[:0])
	if subtle.ConstantTimeCompare(tag[:], box[:TagSize]) != 1 {
		return nil, errors.New("ciphertext authentication failed")
	}

	ret, out := sliceForAppend(out, len(ciphertext))

	firstMessageBlock := ciphertext
	if len(firstMessageBlock) > 32 {
		firstMessageBlock = firstMessageBlock[:32]
	}
	for i, x := range firstMessageBlock {
		out[i] = firstBlock[32+i] ^ x
	}
	ciphertext = ciphertext[len(firstMessageBlock):]
	out = out[len(firstMessageBlock):]

	cipher.SetCounter(1)
	cipher.XORKeyStream(out, ciphertext)
	return ret, nil
}

func sliceForAppend(in []byte, n int) (head, tail []byte) {
	if total := len(in) + n; cap(in) >= total {
		head = in[:total]
	} else {
		head = make([]byte, total)
		copy(head, in)
	}
	tail = head[len(in):]
	return
}
