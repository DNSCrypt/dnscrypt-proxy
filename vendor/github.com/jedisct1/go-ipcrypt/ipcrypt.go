// Package ipcrypt implements IP address encryption and obfuscation methods.
// It provides three encryption modes:
//   - ipcrypt-deterministic: A deterministic mode where the same input always produces the same output
//   - ipcrypt-nd: A non-deterministic mode that uses an 8-byte tweak
//   - ipcrypt-ndx: An extended non-deterministic mode that uses a 32-byte key and 16-byte tweak
//
// For non-deterministic modes, passing nil as the tweak parameter will automatically generate a random tweak.
package ipcrypt

import (
	"crypto/aes"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
)

// Key sizes for different encryption modes
const (
	KeySizeDeterministic = 16 // Size in bytes of the key for ipcrypt-deterministic mode
	KeySizeND            = 16 // Size in bytes of the key for ipcrypt-nd mode
	KeySizeNDX           = 32 // Size in bytes of the key for ipcrypt-ndx mode
)

// Tweak sizes for different encryption modes
const (
	TweakSize  = 8  // Size in bytes of the tweak for ipcrypt-nd mode
	TweakSizeX = 16 // Size in bytes of the tweak for ipcrypt-ndx mode
)

// Error definitions for the package
var (
	ErrInvalidKeySize = errors.New("invalid key size")
	ErrInvalidIP      = errors.New("invalid IP address")
	ErrInvalidTweak   = errors.New("invalid tweak size")
)

// Utility functions

// validateKey checks if the key length matches the expected size
func validateKey(key []byte, expectedSize int) error {
	if len(key) != expectedSize {
		return fmt.Errorf("%w: got %d bytes, want %d bytes", ErrInvalidKeySize, len(key), expectedSize)
	}
	return nil
}

// validateIP ensures the IP address is valid and can be converted to 16-byte form
func validateIP(ip net.IP) ([]byte, error) {
	if ip == nil {
		return nil, ErrInvalidIP
	}
	ip16 := ip.To16()
	if ip16 == nil {
		return nil, ErrInvalidIP
	}
	return ip16, nil
}

// validateTweak checks if the tweak length matches the expected size
func validateTweak(tweak []byte, expectedSize int) error {
	if len(tweak) != expectedSize {
		return fmt.Errorf("%w: got %d bytes, want %d bytes", ErrInvalidTweak, len(tweak), expectedSize)
	}
	return nil
}

// xorBytes performs XOR operation on two byte slices of equal length
func xorBytes(a, b []byte) []byte {
	if len(a) != len(b) {
		return nil
	}
	c := make([]byte, len(a))
	for i := range a {
		c[i] = a[i] ^ b[i]
	}
	return c
}

// Deterministic mode functions

// EncryptIP encrypts an IP address using ipcrypt-deterministic mode.
// The key must be exactly KeySizeDeterministic bytes long.
// Returns the encrypted IP address as a net.IP.
func EncryptIP(key []byte, ip net.IP) (net.IP, error) {
	if err := validateKey(key, KeySizeDeterministic); err != nil {
		return nil, err
	}

	ipBytes, err := validateIP(ip)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	encrypted := make([]byte, 16)
	block.Encrypt(encrypted, ipBytes)

	return net.IP(encrypted), nil
}

// DecryptIP decrypts an IP address that was encrypted using ipcrypt-deterministic mode.
// The key must be exactly KeySizeDeterministic bytes long.
// Returns the decrypted IP address as a net.IP.
func DecryptIP(key []byte, encrypted net.IP) (net.IP, error) {
	if err := validateKey(key, KeySizeDeterministic); err != nil {
		return nil, err
	}

	ipBytes, err := validateIP(encrypted)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	decrypted := make([]byte, 16)
	block.Decrypt(decrypted, ipBytes)

	return net.IP(decrypted), nil
}

// Non-deterministic mode functions

// EncryptIPNonDeterministic encrypts an IP address using ipcrypt-nd mode.
// The key must be exactly KeySizeND bytes long.
// If tweak is nil, a random tweak will be generated.
// Returns a byte slice containing the tweak concatenated with the encrypted IP.
func EncryptIPNonDeterministic(ip string, key []byte, tweak []byte) ([]byte, error) {
	if err := validateKey(key, KeySizeND); err != nil {
		return nil, err
	}

	ipBytes, err := validateIP(net.ParseIP(ip))
	if err != nil {
		return nil, err
	}

	var t []byte
	if tweak == nil {
		t = make([]byte, TweakSize)
		if _, err := rand.Read(t); err != nil {
			return nil, fmt.Errorf("failed to generate tweak: %w", err)
		}
	} else {
		if err := validateTweak(tweak, TweakSize); err != nil {
			return nil, err
		}
		t = tweak
	}

	encrypted, err := KiasuBCEncrypt(key, t, ipBytes)
	if err != nil {
		return nil, err
	}

	result := make([]byte, TweakSize+16)
	copy(result[:TweakSize], t)
	copy(result[TweakSize:], encrypted)
	return result, nil
}

// DecryptIPNonDeterministic decrypts an IP address that was encrypted using ipcrypt-nd mode.
// The key must be exactly KeySizeND bytes long.
// Returns the decrypted IP address as a string.
func DecryptIPNonDeterministic(ciphertext []byte, key []byte) (string, error) {
	if err := validateKey(key, KeySizeND); err != nil {
		return "", err
	}

	if len(ciphertext) != TweakSize+16 {
		return "", fmt.Errorf("invalid ciphertext length: got %d, want %d", len(ciphertext), TweakSize+16)
	}

	tweak := ciphertext[:TweakSize]
	encryptedIP := ciphertext[TweakSize:]

	decrypted, err := KiasuBCDecrypt(key, tweak, encryptedIP)
	if err != nil {
		return "", err
	}

	return net.IP(decrypted).String(), nil
}

// Extended non-deterministic mode functions

// EncryptIPNonDeterministicX encrypts an IP address using ipcrypt-ndx mode.
// The key must be exactly KeySizeNDX bytes long.
// If tweak is nil, a random tweak will be generated.
// Returns a byte slice containing the tweak concatenated with the encrypted IP.
func EncryptIPNonDeterministicX(ip string, key []byte, tweak []byte) ([]byte, error) {
	if err := validateKey(key, KeySizeNDX); err != nil {
		return nil, err
	}

	ipBytes, err := validateIP(net.ParseIP(ip))
	if err != nil {
		return nil, err
	}

	key1 := key[:KeySizeND]
	key2 := key[KeySizeND:]

	block1, err := aes.NewCipher(key1)
	if err != nil {
		return nil, fmt.Errorf("failed to create first cipher: %w", err)
	}

	block2, err := aes.NewCipher(key2)
	if err != nil {
		return nil, fmt.Errorf("failed to create second cipher: %w", err)
	}

	var t []byte
	if tweak == nil {
		t = make([]byte, TweakSizeX)
		if _, err := rand.Read(t); err != nil {
			return nil, fmt.Errorf("failed to generate tweak: %w", err)
		}
	} else {
		if err := validateTweak(tweak, TweakSizeX); err != nil {
			return nil, err
		}
		t = tweak
	}

	encryptedTweak := make([]byte, 16)
	block2.Encrypt(encryptedTweak, t)

	xoredIP := xorBytes(ipBytes, encryptedTweak)
	if xoredIP == nil {
		return nil, errors.New("XOR operation failed")
	}

	encrypted := make([]byte, 16)
	block1.Encrypt(encrypted, xoredIP)

	finalEncrypted := xorBytes(encrypted, encryptedTweak)
	if finalEncrypted == nil {
		return nil, errors.New("XOR operation failed")
	}

	result := make([]byte, TweakSizeX+16)
	copy(result[:TweakSizeX], t)
	copy(result[TweakSizeX:], finalEncrypted)
	return result, nil
}

// DecryptIPNonDeterministicX decrypts an IP address that was encrypted using ipcrypt-ndx mode.
// The key must be exactly KeySizeNDX bytes long.
// Returns the decrypted IP address as a string.
func DecryptIPNonDeterministicX(ciphertext []byte, key []byte) (string, error) {
	if err := validateKey(key, KeySizeNDX); err != nil {
		return "", err
	}

	if len(ciphertext) != TweakSizeX+16 {
		return "", fmt.Errorf("invalid ciphertext length: got %d, want %d", len(ciphertext), TweakSizeX+16)
	}

	key1 := key[:KeySizeND]
	key2 := key[KeySizeND:]

	block1, err := aes.NewCipher(key1)
	if err != nil {
		return "", fmt.Errorf("failed to create first cipher: %w", err)
	}

	block2, err := aes.NewCipher(key2)
	if err != nil {
		return "", fmt.Errorf("failed to create second cipher: %w", err)
	}

	tweak := ciphertext[:TweakSizeX]
	encryptedIP := ciphertext[TweakSizeX:]

	encryptedTweak := make([]byte, 16)
	block2.Encrypt(encryptedTweak, tweak)

	xoredIP := xorBytes(encryptedIP, encryptedTweak)
	if xoredIP == nil {
		return "", errors.New("XOR operation failed")
	}

	decrypted := make([]byte, 16)
	block1.Decrypt(decrypted, xoredIP)

	finalDecrypted := xorBytes(decrypted, encryptedTweak)
	if finalDecrypted == nil {
		return "", errors.New("XOR operation failed")
	}

	return net.IP(finalDecrypted).String(), nil
}
