// Copyright (c) 2016 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

package chacha20

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/aead/chacha20/chacha"
)

func toHex(bits []byte) string {
	return hex.EncodeToString(bits)
}

func fromHex(bits string) []byte {
	b, err := hex.DecodeString(bits)
	if err != nil {
		panic(err)
	}
	return b
}

func TestVectors(t *testing.T) {
	for i, v := range vectors {
		if len(v.plaintext) == 0 {
			v.plaintext = make([]byte, len(v.ciphertext))
		}

		dst := make([]byte, len(v.ciphertext))

		XORKeyStream(dst, v.plaintext, v.nonce, v.key)
		if !bytes.Equal(dst, v.ciphertext) {
			t.Errorf("Test %d: ciphertext mismatch:\n \t got:  %s\n \t want: %s", i, toHex(dst), toHex(v.ciphertext))
		}

		c, err := NewCipher(v.nonce, v.key)
		if err != nil {
			t.Fatal(err)
		}
		c.XORKeyStream(dst[:1], v.plaintext[:1])
		c.XORKeyStream(dst[1:], v.plaintext[1:])
		if !bytes.Equal(dst, v.ciphertext) {
			t.Errorf("Test %d: ciphertext mismatch:\n \t got:  %s\n \t want: %s", i, toHex(dst), toHex(v.ciphertext))
		}
	}
}

func benchmarkCipher(b *testing.B, size int, nonceSize int) {
	var key [32]byte
	nonce := make([]byte, nonceSize)
	c, _ := NewCipher(nonce, key[:])
	buf := make([]byte, size)

	b.SetBytes(int64(len(buf)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.XORKeyStream(buf, buf)
	}
}

func benchmarkXORKeyStream(b *testing.B, size int, nonceSize int) {
	var key [32]byte
	nonce := make([]byte, nonceSize)
	buf := make([]byte, size)
	b.SetBytes(int64(len(buf)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		XORKeyStream(buf, buf, nonce[:], key[:])
	}
}

func BenchmarkChaCha20_64(b *testing.B)              { benchmarkCipher(b, 64, chacha.NonceSize) }
func BenchmarkChaCha20_1K(b *testing.B)              { benchmarkCipher(b, 1024, chacha.NonceSize) }
func BenchmarkXChaCha20_64(b *testing.B)             { benchmarkXORKeyStream(b, 64, chacha.XNonceSize) }
func BenchmarkXChaCha20_1K(b *testing.B)             { benchmarkXORKeyStream(b, 1024, chacha.XNonceSize) }
func BenchmarkXORKeyStream64(b *testing.B)           { benchmarkXORKeyStream(b, 64, chacha.NonceSize) }
func BenchmarkXORKeyStream1K(b *testing.B)           { benchmarkXORKeyStream(b, 1024, chacha.NonceSize) }
func BenchmarkXChaCha20_XORKeyStream64(b *testing.B) { benchmarkXORKeyStream(b, 64, chacha.XNonceSize) }
func BenchmarkXChaCha20_XORKeyStream1K(b *testing.B) {
	benchmarkXORKeyStream(b, 1024, chacha.XNonceSize)
}

var vectors = []struct {
	key, nonce, plaintext, ciphertext []byte
}{
	{
		fromHex("0000000000000000000000000000000000000000000000000000000000000000"),
		fromHex("0000000000000000"),
		nil,
		fromHex("76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586"),
	},
	{
		fromHex("0000000000000000000000000000000000000000000000000000000000000000"),
		fromHex("000000000000000000000000"),
		nil,
		fromHex("76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586"),
	},
	{
		fromHex("0000000000000000000000000000000000000000000000000000000000000000"),
		fromHex("000000000000000000000000000000000000000000000000"),
		nil,
		fromHex("bcd02a18bf3f01d19292de30a7a8fdaca4b65e50a6002cc72cd6d2f7c91ac3d5728f83e0aad2bfcf9abd2d2db58faedd65015dd83fc09b131e271043019e8e0f"),
	},
}
