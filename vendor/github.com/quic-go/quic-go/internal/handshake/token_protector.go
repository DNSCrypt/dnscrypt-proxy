package handshake

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
)

// TokenProtectorKey is the key used to encrypt both Retry and session resumption tokens.
type TokenProtectorKey [32]byte

const tokenSaltSize = 32

// tokenProtector is used to create and verify a token
type tokenProtector struct {
	key TokenProtectorKey
}

// newTokenProtector creates a source for source address tokens
func newTokenProtector(key TokenProtectorKey) *tokenProtector {
	return &tokenProtector{key: key}
}

// NewToken encodes data into a new token.
func (s *tokenProtector) NewToken(data []byte) ([]byte, error) {
	var salt [tokenSaltSize]byte
	if _, err := rand.Read(salt[:]); err != nil {
		return nil, err
	}
	aead, err := s.createAEAD(salt[:])
	if err != nil {
		return nil, err
	}
	return append(salt[:], aead.Seal(nil, nil, data, nil)...), nil
}

// DecodeToken decodes a token.
func (s *tokenProtector) DecodeToken(p []byte) ([]byte, error) {
	if len(p) < tokenSaltSize {
		return nil, fmt.Errorf("token too short: %d", len(p))
	}
	salt := p[:tokenSaltSize]
	aead, err := s.createAEAD(salt)
	if err != nil {
		return nil, err
	}
	if len(p[tokenSaltSize:]) < aead.Overhead() {
		return nil, fmt.Errorf("token too short: %d", len(p))
	}
	return aead.Open(nil, nil, p[tokenSaltSize:], nil)
}

const tokenProtectorHKDFInfo = "quic-go token source"

func (s *tokenProtector) createAEAD(salt []byte) (cipher.AEAD, error) {
	prk, err := hkdf.Extract(sha256.New, s.key[:], salt)
	if err != nil {
		return nil, err
	}

	key, err := hkdf.Expand(sha256.New, prk, tokenProtectorHKDFInfo, 32)
	if err != nil {
		return nil, err
	}

	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCMWithRandomNonce(c)
	if err != nil {
		return nil, err
	}
	return aead, nil
}
