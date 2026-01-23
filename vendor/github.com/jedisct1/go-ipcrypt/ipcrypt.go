// Package ipcrypt implements IP address encryption and obfuscation methods.
// It provides four encryption modes:
//   - ipcrypt-deterministic: A deterministic mode where the same input always produces the same output
//   - ipcrypt-nd: A non-deterministic mode that uses an 8-byte tweak
//   - ipcrypt-ndx: An extended non-deterministic mode that uses a 32-byte key and 16-byte tweak
//   - ipcrypt-pfx: A prefix-preserving mode that maintains the original IP format (IPv4 or IPv6)
//
// For non-deterministic modes, passing nil as the tweak parameter will automatically generate a random tweak.
package ipcrypt

import (
	"crypto/aes"
	"crypto/rand"
	"crypto/subtle"
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
	subtle.XORBytes(c, a, b)
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

// Prefix-preserving mode functions

// EncryptIPPfx encrypts an IP address using ipcrypt-pfx mode.
// The key must be exactly 32 bytes long (split into two AES-128 keys).
// Returns the encrypted IP address maintaining the original format (IPv4 or IPv6).
func EncryptIPPfx(ip net.IP, key []byte) (net.IP, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("%w: got %d bytes, want 32 bytes", ErrInvalidKeySize, len(key))
	}

	// Split the key into two AES-128 keys
	k1 := key[:16]
	k2 := key[16:32]

	// Check that K1 and K2 are different
	if subtle.ConstantTimeCompare(k1, k2) == 1 {
		return nil, errors.New("the two halves of the key must be different")
	}

	// Convert IP to 16-byte representation
	ipBytes, err := validateIP(ip)
	if err != nil {
		return nil, err
	}

	// Create AES cipher objects
	cipher1, err := aes.NewCipher(k1)
	if err != nil {
		return nil, fmt.Errorf("failed to create first cipher: %w", err)
	}

	cipher2, err := aes.NewCipher(k2)
	if err != nil {
		return nil, fmt.Errorf("failed to create second cipher: %w", err)
	}

	// Determine if this is IPv4
	isIPv4 := ip.To4() != nil

	// Initialize encrypted result
	encrypted := make([]byte, 16)

	// Determine starting point
	prefixStart := 0
	if isIPv4 {
		prefixStart = 96
		// Copy the IPv4-mapped prefix
		copy(encrypted[:12], ipBytes[:12])
	}

	// Initialize padded prefix for the starting prefix length
	paddedPrefix := make([]byte, 16)
	if isIPv4 {
		// For IPv4: pad_prefix_96
		paddedPrefix[3] = 0x01 // Set bit at position 96
		paddedPrefix[14] = 0xFF
		paddedPrefix[15] = 0xFF
	} else {
		// For IPv6: pad_prefix_0
		paddedPrefix[15] = 0x01 // Set bit at position 0
	}

	// Process each bit position
	for prefixLenBits := prefixStart; prefixLenBits < 128; prefixLenBits++ {
		// Compute pseudorandom function with dual AES encryption
		e1 := make([]byte, 16)
		cipher1.Encrypt(e1, paddedPrefix)

		e2 := make([]byte, 16)
		cipher2.Encrypt(e2, paddedPrefix)

		// XOR the two encryptions
		e := xorBytes(e1, e2)
		// We only need the least significant bit
		cipherBit := e[15] & 1

		// Extract the current bit from the original IP
		currentBitPos := 127 - prefixLenBits
		originalBit := getBit(ipBytes, currentBitPos)

		// Set the bit in the encrypted result
		setBit(encrypted, currentBitPos, cipherBit^originalBit)

		// Prepare padded_prefix for next iteration
		// Shift left by 1 bit and insert the next bit from ipBytes
		paddedPrefix = shiftLeftOneBit(paddedPrefix)
		setBit(paddedPrefix, 0, originalBit)
	}

	// Return the appropriate format
	if isIPv4 {
		// Return just the IPv4 part
		return net.IP(encrypted[12:16]), nil
	}
	return net.IP(encrypted), nil
}

// DecryptIPPfx decrypts an IP address that was encrypted using ipcrypt-pfx mode.
// The key must be exactly 32 bytes long (split into two AES-128 keys).
// Returns the decrypted IP address.
func DecryptIPPfx(encryptedIP net.IP, key []byte) (net.IP, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("%w: got %d bytes, want 32 bytes", ErrInvalidKeySize, len(key))
	}

	// Split the key into two AES-128 keys
	k1 := key[:16]
	k2 := key[16:32]

	// Check that K1 and K2 are different
	if subtle.ConstantTimeCompare(k1, k2) == 1 {
		return nil, errors.New("the two halves of the key must be different")
	}

	// Determine if this is IPv4
	isIPv4 := encryptedIP.To4() != nil

	// Convert to 16-byte representation
	var encryptedBytes []byte
	if isIPv4 {
		// Convert IPv4 to IPv4-mapped IPv6 format
		encryptedBytes = make([]byte, 16)
		copy(encryptedBytes[:10], []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
		copy(encryptedBytes[10:12], []byte{0xff, 0xff})
		copy(encryptedBytes[12:], encryptedIP.To4())
	} else {
		var err error
		encryptedBytes, err = validateIP(encryptedIP)
		if err != nil {
			return nil, err
		}
	}

	// Create AES cipher objects
	cipher1, err := aes.NewCipher(k1)
	if err != nil {
		return nil, fmt.Errorf("failed to create first cipher: %w", err)
	}

	cipher2, err := aes.NewCipher(k2)
	if err != nil {
		return nil, fmt.Errorf("failed to create second cipher: %w", err)
	}

	// Initialize decrypted result
	decrypted := make([]byte, 16)

	// Determine starting point
	prefixStart := 0
	if isIPv4 {
		prefixStart = 96
		// Copy the IPv4-mapped prefix
		copy(decrypted[:12], encryptedBytes[:12])
	}

	// Initialize padded prefix for the starting prefix length
	paddedPrefix := make([]byte, 16)
	if isIPv4 {
		// For IPv4: pad_prefix_96
		paddedPrefix[3] = 0x01 // Set bit at position 96
		paddedPrefix[14] = 0xFF
		paddedPrefix[15] = 0xFF
	} else {
		// For IPv6: pad_prefix_0
		paddedPrefix[15] = 0x01 // Set bit at position 0
	}

	// Process each bit position
	for prefixLenBits := prefixStart; prefixLenBits < 128; prefixLenBits++ {
		// Compute pseudorandom function with dual AES encryption
		e1 := make([]byte, 16)
		cipher1.Encrypt(e1, paddedPrefix)

		e2 := make([]byte, 16)
		cipher2.Encrypt(e2, paddedPrefix)

		// XOR the two encryptions
		e := xorBytes(e1, e2)
		// We only need the least significant bit
		cipherBit := e[15] & 1

		// Extract the current bit from the encrypted IP
		currentBitPos := 127 - prefixLenBits
		encryptedBit := getBit(encryptedBytes, currentBitPos)
		originalBit := cipherBit ^ encryptedBit

		// Set the bit in the decrypted result
		setBit(decrypted, currentBitPos, originalBit)

		// Prepare padded_prefix for next iteration
		// Shift left by 1 bit and insert the next bit from decrypted
		paddedPrefix = shiftLeftOneBit(paddedPrefix)
		setBit(paddedPrefix, 0, originalBit)
	}

	// Return the appropriate format
	if isIPv4 {
		// Return just the IPv4 part
		return net.IP(decrypted[12:16]), nil
	}
	return net.IP(decrypted), nil
}

// Helper functions for bit manipulation

// getBit extracts bit at position from 16-byte array
// position: 0 = LSB of byte 15, 127 = MSB of byte 0
func getBit(data []byte, position int) byte {
	byteIndex := 15 - (position / 8)
	bitIndex := position % 8
	return (data[byteIndex] >> bitIndex) & 1
}

// setBit sets bit at position in 16-byte array
// position: 0 = LSB of byte 15, 127 = MSB of byte 0
func setBit(data []byte, position int, value byte) {
	byteIndex := 15 - (position / 8)
	bitIndex := position % 8
	if value != 0 {
		data[byteIndex] |= 1 << bitIndex
	} else {
		data[byteIndex] &^= 1 << bitIndex
	}
}

// shiftLeftOneBit shifts a 16-byte array one bit to the left
// The most significant bit is lost, and a zero bit is shifted in from the right
func shiftLeftOneBit(data []byte) []byte {
	if len(data) != 16 {
		return nil
	}

	result := make([]byte, 16)
	carry := byte(0)

	// Process from least significant byte (byte 15) to most significant (byte 0)
	for i := 15; i >= 0; i-- {
		// Current byte shifted left by 1, with carry from previous byte
		result[i] = (data[i] << 1) | carry
		// Extract the bit that will be carried to the next byte
		carry = (data[i] >> 7) & 1
	}

	return result
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
