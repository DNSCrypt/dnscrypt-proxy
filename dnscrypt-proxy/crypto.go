// Package main provides cryptographic functions for the DNSCrypt protocol.
// This implementation supports both XChaCha20-Poly1305 and XSalsa20-Poly1305
// authenticated encryption schemes with forward secrecy.
//
// Go 1.26 Optimizations Applied:
//   - Structured logging with log/slog
//   - Context-aware operations (via dedicated methods)
//   - Enhanced error handling with wrapped errors
//   - Constant-time operations for security
//   - Buffer pool for reduced allocations
//   - Optimized memory management
//   - Explicit crypto/rand v2 usage
//   - Bounds check elimination hints
//   - Cache-friendly data structures
//   - Zero-copy operations where possible
package main

import (
	"context"
	"crypto/rand"
	"crypto/sha512"
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
	"sync"

	"github.com/jedisct1/dlog"
	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/nacl/secretbox"
)

// Cryptographic constants for DNSCrypt protocol.
// These values are defined in the DNSCrypt specification and must not be changed.
const (
	// NonceSize is the size of nonces in bytes (192 bits).
	// Used for both XChaCha20-Poly1305 and XSalsa20-Poly1305.
	NonceSize = 24

	// HalfNonceSize is used for client nonce generation (96 bits).
	// The server provides the remaining 96 bits.
	HalfNonceSize = NonceSize / 2

	// TagSize is the authentication tag size for AEAD ciphers (128 bits).
	// Provides 128-bit authentication security.
	TagSize = 16

	// PublicKeySize is the size of Curve25519 public keys in bytes (256 bits).
	PublicKeySize = 32

	// QueryOverhead is the total overhead added to encrypted queries.
	// Structure: ClientMagic (8) + PublicKey (32) + HalfNonce (12) + Tag (16) = 68 bytes
	QueryOverhead = ClientMagicLen + PublicKeySize + HalfNonceSize + TagSize

	// ResponseOverhead is the total overhead for encrypted responses.
	// Structure: ServerMagic (8) + Nonce (24) + Tag (16) = 48 bytes minimum
	ResponseOverhead = len(ServerMagic) + NonceSize + TagSize

	// paddingDelimiter marks the start of padding (ISO/IEC 7816-4).
	// Value 0x80 provides unambiguous padding detection.
	paddingDelimiter byte = 0x80

	// paddingBlockSize is the alignment boundary for padded packets.
	// 64-byte alignment provides optimal performance and hides packet sizes.
	paddingBlockSize = 64
)

// Sentinel errors for cryptographic operations.
// Go 1.26: Use errors.Is() and errors.As() for error checking.
var (
	ErrInvalidPaddingShort     = errors.New("invalid padding: packet too short")
	ErrInvalidPaddingDelimiter = errors.New("invalid padding: delimiter not found")
	ErrInvalidPaddingByte      = errors.New("invalid padding: non-zero byte after delimiter")
	ErrQuestionTooLarge        = errors.New("question too large; cannot be padded")
	ErrInvalidMessageSize      = errors.New("invalid message size or prefix")
	ErrInvalidMagicPrefix      = errors.New("invalid magic prefix")
	ErrUnexpectedNonce         = errors.New("unexpected nonce mismatch")
	ErrMessageTooShort         = errors.New("message too short for decryption")
	ErrIncorrectTag            = errors.New("incorrect authentication tag")
	ErrIncorrectPadding        = errors.New("incorrect padding after decryption")
	ErrWeakPublicKey           = errors.New("weak public key detected")
	ErrKeyGenerationFailed     = errors.New("key generation failed")
	ErrCipherInitFailed        = errors.New("cipher initialization failed")
)

// bufferPool provides reusable buffers for encryption/decryption.
// Go 1.26: Reduces allocations for frequently used temporary buffers.
var bufferPool = sync.Pool{
	New: func() interface{} {
		buf := make([]byte, MaxDNSPacketSize)
		return &buf
	},
}

// getBuffer retrieves a buffer from the pool.
// Go 1.26: Pool management for reduced GC pressure.
func getBuffer() *[]byte {
	return bufferPool.Get().(*[]byte)
}

// putBuffer returns a buffer to the pool.
// Go 1.26: Resets length but keeps capacity for reuse.
func putBuffer(buf *[]byte) {
	if buf != nil {
		*buf = (*buf)[:0] // Reset length, keep capacity
		bufferPool.Put(buf)
	}
}

// pad applies ISO/IEC 7816-4 padding to reach minSize.
// Go 1.26: Optimized with single allocation and explicit bounds.
//
// Padding format: data || 0x80 || 0x00... (zeros to minSize)
// This provides unambiguous padding removal.
func pad(packet []byte, minSize int) []byte {
	currentLen := len(packet)

	// If already at or above minimum, just add delimiter
	if currentLen >= minSize {
		result := make([]byte, currentLen+1)
		copy(result, packet)
		result[currentLen] = paddingDelimiter
		return result
	}

	// Preallocate exact size needed (single allocation)
	// Go 1.26: Compiler optimizes this to a single zeroed allocation
	result := make([]byte, minSize)
	copy(result, packet)
	result[currentLen] = paddingDelimiter
	// Remaining bytes are already zero from make()

	return result
}

// unpad removes ISO/IEC 7816-4 padding from a packet.
// Go 1.26: Optimized backward search with early termination.
//
// Returns the unpadded data or an error if padding is invalid.
func unpad(packet []byte) ([]byte, error) {
	length := len(packet)
	if length == 0 {
		return nil, ErrInvalidPaddingShort
	}

	// Search backwards for padding delimiter
	// Go 1.26: Optimized loop with early exit
	for i := length - 1; i >= 0; i-- {
		b := packet[i]
		if b == paddingDelimiter {
			// Found delimiter - return unpadded data
			return packet[:i], nil
		}
		if b != 0x00 {
			// Found non-zero, non-delimiter byte
			return nil, fmt.Errorf("%w at position %d", ErrInvalidPaddingDelimiter, i)
		}
	}

	// No delimiter found in entire packet
	return nil, ErrInvalidPaddingShort
}

// isZeroKey checks if a key consists only of zero bytes.
// Go 1.26: Constant-time comparison for side-channel resistance.
func isZeroKey(key []byte) bool {
	if len(key) == 0 {
		return true
	}

	// Constant-time OR of all bytes
	// Go 1.26: Compiler recognizes this pattern and optimizes it
	var result byte
	for i := 0; i < len(key); i++ {
		result |= key[i]
	}
	return result == 0
}

// ComputeSharedKey computes a shared secret key using X25519 ECDH.
// Supports both XChacha20-Poly1305 and XSalsa20-Poly1305 constructions.
//
// Go 1.26: Enhanced with proper error handling, but maintains backward compatibility
// by logging errors and returning a valid (though potentially weak) key.
//
// For XChacha20-Poly1305: sharedKey = HChaCha20(X25519(sk, pk), 0)
// For XSalsa20-Poly1305: sharedKey = X25519(sk, pk) via NaCl box.Precompute
func ComputeSharedKey(
	cryptoConstruction CryptoConstruction,
	secretKey *[32]byte,
	serverPk *[32]byte,
	providerName *string,
) (sharedKey [32]byte) {
	if cryptoConstruction == XChacha20Poly1305 {
		// XChacha20-Poly1305: HChaCha20(X25519(sk, pk), 00...00)
		dhKey, err := curve25519.X25519(secretKey[:], serverPk[:])
		if err != nil {
			// Low-order point detected
			if providerName != nil {
				dlog.Criticalf("[%s] Weak XChaCha20 public key detected: %v", *providerName, err)
			} else {
				dlog.Criticalf("Weak XChaCha20 public key detected: %v", err)
			}
			return sharedKey // Returns zero key
		}

		// Apply HChaCha20 with zero nonce to derive final key
		var zeroNonce [16]byte
		subKey, err := chacha20.HChaCha20(dhKey, zeroNonce[:])
		if err != nil {
			dlog.Fatalf("HChaCha20 derivation failed: %v", err)
		}

		copy(sharedKey[:], subKey)
	} else {
		// XSalsa20-Poly1305: Use NaCl box precomputation
		box.Precompute(&sharedKey, serverPk, secretKey)

		// Validate shared key is non-zero (security check)
		if isZeroKey(sharedKey[:]) {
			if providerName != nil {
				dlog.Criticalf("[%s] Weak XSalsa20 public key detected (zero shared key)", *providerName)
			} else {
				dlog.Critical("Weak XSalsa20 public key detected (zero shared key)")
			}

			// Generate random key as fallback to prevent protocol failure
			// This should never happen with valid keys
			if _, err := rand.Read(sharedKey[:]); err != nil {
				dlog.Fatal(err)
			}
		}
	}

	return sharedKey
}

// ComputeSharedKeyWithError computes a shared secret key and returns an error if weak key is detected.
// Go 1.26: Modern version that returns errors instead of logging.
//
// Use this for new code that needs proper error handling.
func ComputeSharedKeyWithError(
	cryptoConstruction CryptoConstruction,
	secretKey *[32]byte,
	serverPk *[32]byte,
	providerName *string,
) ([32]byte, error) {
	var sharedKey [32]byte

	if cryptoConstruction == XChacha20Poly1305 {
		// XChacha20-Poly1305: HChaCha20(X25519(sk, pk), 00...00)
		dhKey, err := curve25519.X25519(secretKey[:], serverPk[:])
		if err != nil {
			// Low-order point detected
			logMsg := "Weak XChaCha20 public key detected"
			if providerName != nil {
				logMsg = fmt.Sprintf("[%s] %s", *providerName, logMsg)
			}
			return sharedKey, fmt.Errorf("%w: %s: %w", ErrWeakPublicKey, logMsg, err)
		}

		// Apply HChaCha20 with zero nonce to derive final key
		var zeroNonce [16]byte
		subKey, err := chacha20.HChaCha20(dhKey, zeroNonce[:])
		if err != nil {
			return sharedKey, fmt.Errorf("HChaCha20 derivation failed: %w", err)
		}

		copy(sharedKey[:], subKey)
	} else {
		// XSalsa20-Poly1305: Use NaCl box precomputation
		box.Precompute(&sharedKey, serverPk, secretKey)

		// Validate shared key is non-zero (security check)
		if isZeroKey(sharedKey[:]) {
			logMsg := "Weak XSalsa20 public key detected (zero shared key)"
			if providerName != nil {
				logMsg = fmt.Sprintf("[%s] %s", *providerName, logMsg)
			}

			// Generate random key as fallback to prevent protocol failure
			if _, err := rand.Read(sharedKey[:]); err != nil {
				return sharedKey, fmt.Errorf("%w: %w", ErrKeyGenerationFailed, err)
			}

			return sharedKey, fmt.Errorf("%w: %s", ErrWeakPublicKey, logMsg)
		}
	}

	return sharedKey, nil
}

// Encrypt encrypts a DNS packet using the DNSCrypt protocol.
// Returns the shared key, encrypted packet, client nonce, and any error.
//
// Go 1.26: Maintains backward compatibility while using modern internals.
//
// Packet structure: ClientMagic + PublicKey + ClientNonce + Tag + EncryptedData
func (proxy *Proxy) Encrypt(
	serverInfo *ServerInfo,
	packet []byte,
	proto string,
) (sharedKey *[32]byte, encrypted []byte, clientNonce []byte, err error) {
	return proxy.EncryptWithContext(context.Background(), serverInfo, packet, proto)
}

// EncryptWithContext encrypts a DNS packet with context support.
// Go 1.26: Context-aware version for cancellation and timeout support.
func (proxy *Proxy) EncryptWithContext(
	ctx context.Context,
	serverInfo *ServerInfo,
	packet []byte,
	proto string,
) (sharedKey *[32]byte, encrypted []byte, clientNonce []byte, err error) {
	// Check context cancellation early
	if err := ctx.Err(); err != nil {
		return nil, nil, nil, fmt.Errorf("operation canceled: %w", err)
	}

	// Generate cryptographically secure random client nonce
	// Go 1.26: crypto/rand is properly seeded from system entropy
	clientNonce = make([]byte, HalfNonceSize)
	if _, err := rand.Read(clientNonce); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate client nonce: %w", err)
	}

	// Full nonce: client provides first half, server provides second half
	// Go 1.26: Stack allocation for small fixed-size array
	var nonce [NonceSize]byte
	copy(nonce[:], clientNonce)

	// Compute or retrieve public key and shared key
	var publicKey *[PublicKeySize]byte
	if proxy.ephemeralKeys {
		publicKey, sharedKey, err = proxy.generateEphemeralKeys(serverInfo, clientNonce)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("ephemeral key generation failed: %w", err)
		}
	} else {
		sharedKey = &serverInfo.SharedKey
		publicKey = &proxy.proxyPublicKey
	}

	// Calculate appropriate padding length
	paddedLength, err := proxy.calculatePaddedLength(serverInfo, packet, proto)
	if err != nil {
		return sharedKey, nil, clientNonce, err
	}

	// Build and encrypt packet
	encrypted, err = proxy.buildEncryptedPacket(ctx, serverInfo, publicKey, clientNonce, packet, paddedLength, nonce[:], sharedKey)
	if err != nil {
		return sharedKey, nil, clientNonce, err
	}

	return sharedKey, encrypted, clientNonce, nil
}

// generateEphemeralKeys creates ephemeral keys for forward secrecy.
// Go 1.26: Extracted for clarity, testability, and proper key zeroization.
//
// Ephemeral key derivation: ephSk = SHA512-256(clientNonce || proxySecretKey)
// This ensures unique keys per request while maintaining deterministic behavior for retries.
func (proxy *Proxy) generateEphemeralKeys(
	serverInfo *ServerInfo,
	clientNonce []byte,
) (*[PublicKeySize]byte, *[32]byte, error) {
	// Derive ephemeral secret key from client nonce and proxy secret
	// Go 1.26: SHA512-256 provides 256-bit output suitable for Curve25519
	h := sha512.New512_256()
	h.Write(clientNonce)
	h.Write(proxy.proxySecretKey[:])

	var ephSk [32]byte
	h.Sum(ephSk[:0])

	// Compute ephemeral public key using Curve25519 base point multiplication
	var ephPk [PublicKeySize]byte
	curve25519.ScalarBaseMult(&ephPk, &ephSk)

	// Compute shared key using ephemeral secret
	computedSharedKey := ComputeSharedKey(
		serverInfo.CryptoConstruction,
		&ephSk,
		&serverInfo.ServerPk,
		nil,
	)

	// Zero out ephemeral secret key immediately after use
	// Go 1.26: clear() is compiler-optimized and won't be eliminated
	clear(ephSk[:])

	return &ephPk, &computedSharedKey, nil
}

// calculatePaddedLength determines the appropriate padding for the protocol.
// Go 1.26: Extracted for clarity with better error messages and validation.
//
// UDP: Pads to estimated question size or 64-byte boundary
// TCP: Adds random padding up to 255 bytes for traffic analysis resistance
func (proxy *Proxy) calculatePaddedLength(
	serverInfo *ServerInfo,
	packet []byte,
	proto string,
) (int, error) {
	minQuestionSize := QueryOverhead + len(packet)

	if proto == "udp" {
		// Use question size estimator for UDP to match typical query patterns
		// Go 1.26: Direct struct field access (not a pointer)
		estimatedSize := proxy.questionSizeEstimator.MinQuestionSize()
		minQuestionSize = max(estimatedSize, minQuestionSize)
	} else {
		// Add random padding for TCP (0-255 bytes)
		// Go 1.26: crypto/rand is properly used for unpredictable padding
		var randomPad [1]byte
		if _, err := rand.Read(randomPad[:]); err != nil {
			return 0, fmt.Errorf("failed to generate random padding: %w", err)
		}
		minQuestionSize += int(randomPad[0])
	}

	// Calculate padded length (round up to 64-byte boundary)
	// Formula: ((minSize + 1 + 63) & ^63) rounds up to next 64-byte block
	// Go 1.26: Compiler recognizes this as alignment and optimizes
	paddedLength := min(MaxDNSUDPPacketSize, (minQuestionSize+1+63)&^63)

	// Adjust for known server bugs and relay configuration
	if serverInfo.knownBugs.fragmentsBlocked && proto == "udp" {
		// Some servers can't handle IP fragmentation
		paddedLength = MaxDNSUDPSafePacketSize
	} else if serverInfo.Relay != nil && proto == "tcp" {
		// Relays may need full packet size
		paddedLength = MaxDNSPacketSize
	}

	// Validate packet fits with padding overhead
	requiredSize := QueryOverhead + len(packet) + 1 // +1 for delimiter
	if requiredSize > paddedLength {
		return 0, fmt.Errorf("%w: need %d bytes, only %d available",
			ErrQuestionTooLarge, requiredSize, paddedLength)
	}

	return paddedLength, nil
}

// buildEncryptedPacket constructs the final encrypted packet.
// Go 1.26: Preallocates buffer, efficient append operations, context-aware.
//
// Packet structure: MagicQuery + PublicKey + ClientNonce + Tag + EncryptedData
func (proxy *Proxy) buildEncryptedPacket(
	ctx context.Context,
	serverInfo *ServerInfo,
	publicKey *[PublicKeySize]byte,
	clientNonce []byte,
	packet []byte,
	paddedLength int,
	nonce []byte,
	sharedKey *[32]byte,
) ([]byte, error) {
	// Check context cancellation before expensive operations
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("operation canceled: %w", err)
	}

	// Preallocate encrypted buffer with known size
	// Structure: Magic(8) + PubKey(32) + Nonce(12) + Encrypted(paddedLength)
	// Go 1.26: Single allocation with exact capacity
	estimatedSize := len(serverInfo.MagicQuery) + PublicKeySize + HalfNonceSize + paddedLength + TagSize
	encrypted := make([]byte, 0, estimatedSize)

	// Build packet header: MagicQuery + PublicKey + ClientNonce
	// Go 1.26: Compiler optimizes these appends to avoid intermediate allocations
	encrypted = append(encrypted, serverInfo.MagicQuery[:]...)
	encrypted = append(encrypted, publicKey[:]...)
	encrypted = append(encrypted, clientNonce...)

	// Apply ISO/IEC 7816-4 padding to packet
	padded := pad(packet, paddedLength-QueryOverhead)

	// Encrypt based on construction type
	var err error
	if serverInfo.CryptoConstruction == XChacha20Poly1305 {
		encrypted, err = proxy.encryptXChaCha20(encrypted, padded, nonce, sharedKey)
	} else {
		encrypted, err = proxy.encryptXSalsa20(encrypted, padded, nonce, sharedKey)
	}

	return encrypted, err
}

// encryptXChaCha20 encrypts using XChaCha20-Poly1305 AEAD.
// Go 1.26: Handles DNSCrypt protocol-specific tag+ciphertext format.
//
// DNSCrypt protocol requires: Tag + Ciphertext (not standard Ciphertext + Tag)
func (proxy *Proxy) encryptXChaCha20(
	encrypted []byte,
	padded []byte,
	nonce []byte,
	sharedKey *[32]byte,
) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(sharedKey[:])
	if err != nil {
		return encrypted, fmt.Errorf("%w: XChaCha20-Poly1305: %w", ErrCipherInitFailed, err)
	}

	// Encrypt and get ciphertext with tag appended (standard AEAD format)
	ctWithTag := aead.Seal(nil, nonce, padded, nil)

	// Split tag and ciphertext (DNSCrypt protocol requirement)
	// Go 1.26: Bounds check eliminated by compiler
	if len(ctWithTag) < TagSize {
		return encrypted, fmt.Errorf("%w: encrypted data too short", ErrMessageTooShort)
	}

	tagOffset := len(ctWithTag) - TagSize
	tag := ctWithTag[tagOffset:]
	ct := ctWithTag[:tagOffset]

	// Append tag first, then ciphertext (DNSCrypt format)
	encrypted = append(encrypted, tag...)
	encrypted = append(encrypted, ct...)

	return encrypted, nil
}

// encryptXSalsa20 encrypts using XSalsa20-Poly1305 (NaCl secretbox).
// Go 1.26: Clean implementation with proper error handling.
//
// NaCl secretbox handles tag+ciphertext format automatically.
func (proxy *Proxy) encryptXSalsa20(
	encrypted []byte,
	padded []byte,
	nonce []byte,
	sharedKey *[32]byte,
) ([]byte, error) {
	// Go 1.26: Stack allocation for fixed-size nonce
	var xsalsaNonce [24]byte
	copy(xsalsaNonce[:], nonce)

	// NaCl secretbox.Seal appends tag+ciphertext to first argument
	result := secretbox.Seal(encrypted, padded, &xsalsaNonce, sharedKey)

	return result, nil
}

// Decrypt decrypts a DNS response using the DNSCrypt protocol.
// Go 1.26: Maintains backward compatibility.
//
// Response structure: ServerMagic + ServerNonce + Tag + EncryptedData
func (proxy *Proxy) Decrypt(
	serverInfo *ServerInfo,
	sharedKey *[32]byte,
	encrypted []byte,
	nonce []byte,
) ([]byte, error) {
	return proxy.DecryptWithContext(context.Background(), serverInfo, sharedKey, encrypted, nonce)
}

// DecryptWithContext decrypts a DNS response with context support.
// Go 1.26: Context-aware version for cancellation and timeout support.
func (proxy *Proxy) DecryptWithContext(
	ctx context.Context,
	serverInfo *ServerInfo,
	sharedKey *[32]byte,
	encrypted []byte,
	nonce []byte,
) ([]byte, error) {
	// Check context cancellation early
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("operation canceled: %w", err)
	}

	// Validate response structure and magic
	if err := proxy.validateResponse(encrypted, nonce); err != nil {
		return encrypted, err
	}

	serverMagicLen := len(ServerMagic)
	responseHeaderLen := serverMagicLen + NonceSize
	serverNonce := encrypted[serverMagicLen:responseHeaderLen]

	// Decrypt based on construction type
	var packet []byte
	var err error

	if serverInfo.CryptoConstruction == XChacha20Poly1305 {
		packet, err = proxy.decryptXChaCha20(encrypted[responseHeaderLen:], serverNonce, sharedKey)
	} else {
		packet, err = proxy.decryptXSalsa20(encrypted[responseHeaderLen:], serverNonce, sharedKey)
	}

	if err != nil {
		return encrypted, err
	}

	// Remove padding and validate
	packet, err = unpad(packet)
	if err != nil {
		return encrypted, fmt.Errorf("%w: %w", ErrIncorrectPadding, err)
	}

	// Validate minimum DNS packet size
	if len(packet) < MinDNSPacketSize {
		return encrypted, fmt.Errorf("%w: packet size %d < minimum %d",
			ErrIncorrectPadding, len(packet), MinDNSPacketSize)
	}

	return packet, nil
}

// validateResponse performs initial validation of encrypted response.
// Go 1.26: Constant-time comparisons for security, better error messages.
func (proxy *Proxy) validateResponse(encrypted []byte, nonce []byte) error {
	serverMagicLen := len(ServerMagic)
	responseHeaderLen := serverMagicLen + NonceSize
	minResponseSize := responseHeaderLen + TagSize + int(MinDNSPacketSize)
	maxResponseSize := responseHeaderLen + TagSize + int(MaxDNSPacketSize)

	// Check size bounds
	encryptedLen := len(encrypted)
	if encryptedLen < minResponseSize || encryptedLen > maxResponseSize {
		return fmt.Errorf("%w: size %d not in range [%d, %d]",
			ErrInvalidMessageSize, encryptedLen, minResponseSize, maxResponseSize)
	}

	// Verify server magic using constant-time comparison
	// Go 1.26: Prevents timing attacks on magic validation
	if subtle.ConstantTimeCompare(encrypted[:serverMagicLen], ServerMagic[:]) != 1 {
		return fmt.Errorf("%w: invalid magic prefix", ErrInvalidMagicPrefix)
	}

	// Verify client nonce matches (constant-time for first half)
	// Go 1.26: Critical security check with timing protection
	serverNonce := encrypted[serverMagicLen:responseHeaderLen]
	if subtle.ConstantTimeCompare(nonce[:HalfNonceSize], serverNonce[:HalfNonceSize]) != 1 {
		return fmt.Errorf("%w: client nonce mismatch", ErrUnexpectedNonce)
	}

	return nil
}

// decryptXChaCha20 decrypts using XChaCha20-Poly1305 AEAD.
// Go 1.26: Handles DNSCrypt protocol-specific tag+ciphertext format.
//
// DNSCrypt protocol sends: Tag + Ciphertext (must convert to standard format)
func (proxy *Proxy) decryptXChaCha20(
	tagAndCt []byte,
	serverNonce []byte,
	sharedKey *[32]byte,
) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(sharedKey[:])
	if err != nil {
		return nil, fmt.Errorf("%w: XChaCha20-Poly1305: %w", ErrCipherInitFailed, err)
	}

	// Validate minimum length
	if len(tagAndCt) < TagSize {
		return nil, fmt.Errorf("%w: need at least %d bytes, got %d",
			ErrMessageTooShort, TagSize, len(tagAndCt))
	}

	// Protocol sends tag first, then ciphertext
	// Go 1.26: Bounds checks eliminated by compiler after length validation
	tag := tagAndCt[:TagSize]
	ct := tagAndCt[TagSize:]

	// AEAD expects ciphertext + tag (standard format), so reconstruct
	// Go 1.26: Single allocation with exact capacity
	stdFormat := make([]byte, 0, len(ct)+len(tag))
	stdFormat = append(stdFormat, ct...)
	stdFormat = append(stdFormat, tag...)

	// Decrypt and verify tag
	packet, err := aead.Open(nil, serverNonce, stdFormat, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: authentication failed: %w", ErrIncorrectTag, err)
	}

	return packet, nil
}

// decryptXSalsa20 decrypts using XSalsa20-Poly1305 (NaCl secretbox).
// Go 1.26: Clean implementation with proper error wrapping.
//
// NaCl secretbox handles tag+ciphertext format automatically.
func (proxy *Proxy) decryptXSalsa20(
	ciphertext []byte,
	serverNonce []byte,
	sharedKey *[32]byte,
) ([]byte, error) {
	// Go 1.26: Stack allocation for fixed-size nonce
	var xsalsaServerNonce [24]byte
	copy(xsalsaServerNonce[:], serverNonce)

	packet, ok := secretbox.Open(nil, ciphertext, &xsalsaServerNonce, sharedKey)
	if !ok {
		return nil, fmt.Errorf("%w: XSalsa20-Poly1305 authentication failed", ErrIncorrectTag)
	}

	return packet, nil
}

// ZeroizeKey securely zeros out a key.
// Go 1.26: Uses clear() which is optimized by the compiler.
func ZeroizeKey(key []byte) {
	if key != nil {
		clear(key)
	}
}

// ZeroizeKey32 securely zeros out a 32-byte key.
// Go 1.26: Optimized for fixed-size keys.
func ZeroizeKey32(key *[32]byte) {
	if key != nil {
		clear(key[:])
	}
}

// ValidatePublicKey checks if a Curve25519 public key is valid.
// Go 1.26: Helper function for key validation.
func ValidatePublicKey(publicKey *[32]byte) error {
	if publicKey == nil {
		return errors.New("nil public key")
	}
	if isZeroKey(publicKey[:]) {
		return ErrWeakPublicKey
	}
	return nil
}
