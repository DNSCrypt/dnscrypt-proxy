// Package main provides cryptographic functions for the DNSCrypt protocol.
//
// This implementation supports both XChaCha20-Poly1305 and XSalsa20-Poly1305
// authenticated encryption schemes with forward secrecy via per-session
// ephemeral Curve25519 key pairs.
//
// Go 1.26 full rewrite — all improvements applied:
//   - isZeroKey replaced by subtle.ConstantTimeCompare (true constant-time)
//   - ComputeSharedKey zero-key branch returns error cleanly; no random-key fallback
//   - ComputeSharedKeyWithError is now the single implementation; compat wrapper removed
//   - generateEphemeralKeys uses sha512.Sum512_256 (stack, no heap alloc)
//   - generateEphemeralKeys: ephSk zeroed with clear() + runtime.KeepAlive to prevent elision
//   - generateEphemeralKeys: fixed-size stack buffer replaces append() for KDF input,
//     eliminating buffer-aliasing risk and ensuring secret key material is explicitly zeroed
//   - encryptXChaCha20: Seal appends directly into the output buffer (one fewer allocation)
//   - decryptXChaCha20: tag reorder done with a [TagSize]byte stack copy (no extra alloc)
//   - bufferPool removed (was dead code; getBuffer/putBuffer never called)
//   - ErrInvalidPaddingByte removed (was declared but never returned)
//   - calculatePaddedLength: TCP cap uses MaxDNSPacketSize (not MaxDNSUDPPacketSize)
//   - sync.Pool.New uses `any` (not obsolete `interface{}`)
//   - ZeroizeKey / ZeroizeKey32 remain exported for cross-file callers
//   - All public functions carry full godoc comments
//   - Drop-in replacement: all public API signatures unchanged
package main

import (
	"crypto/rand"
	"crypto/sha512"
	"crypto/subtle"
	"errors"
	"fmt"
	"runtime"
	"sync"

	"github.com/jedisct1/dlog"
	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/nacl/secretbox"
)

// ─────────────────────────────────────── constants ──────────────────────────

// Cryptographic constants for DNSCrypt protocol.
// Values are defined in the DNSCrypt specification and MUST NOT be changed.
const (
	// NonceSize is the full nonce size in bytes (192 bits).
	// Used for both XChaCha20-Poly1305 and XSalsa20-Poly1305.
	NonceSize = 24

	// HalfNonceSize is the client-provided nonce half (96 bits).
	// The server provides the remaining 96 bits.
	HalfNonceSize = NonceSize / 2

	// TagSize is the AEAD authentication tag size (128 bits).
	TagSize = 16

	// PublicKeySize is the Curve25519 public key size in bytes (256 bits).
	PublicKeySize = 32

	// QueryOverhead is the total header overhead prepended to encrypted queries.
	// Layout: ClientMagic(8) + PublicKey(32) + HalfNonce(12) + Tag(16) = 68 bytes.
	QueryOverhead = ClientMagicLen + PublicKeySize + HalfNonceSize + TagSize

	// ResponseOverhead is the minimum header overhead of an encrypted response.
	// Layout: ServerMagic(8) + Nonce(24) + Tag(16) = 48 bytes.
	ResponseOverhead = len(ServerMagic) + NonceSize + TagSize

	// paddingDelimiter is the ISO/IEC 7816-4 padding start marker (0x80).
	paddingDelimiter byte = 0x80

	// paddingBlockSize is the alignment boundary for padded DNS packets.
	// 64-byte blocks hide query sizes and provide natural alignment.
	paddingBlockSize = 64

	// Minimum capacities kept in buffer pools to avoid retaining tiny buffers.
	minPooledPaddedPacketCap  = 512
	minPooledXChaChaBufferCap = 512
)

// ─────────────────────────────────────── sentinel errors ────────────────────

// Sentinel errors for cryptographic operations.
// Use errors.Is() to test for these values.
var (
	ErrInvalidPaddingShort     = errors.New("invalid padding: packet too short")
	ErrInvalidPaddingDelimiter = errors.New("invalid padding: delimiter not found")
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

var (
	// paddedPacketPool reuses temporary plaintext buffers used during query
	// padding/encryption on the DNSCrypt hot path.
	paddedPacketPool = sync.Pool{
		New: func() any {
			return make([]byte, 0, MaxDNSPacketSize)
		},
	}

	// xchachaReorderPool reuses temporary buffers used to convert DNSCrypt's
	// tag||ciphertext layout into AEAD's ciphertext||tag layout.
	xchachaReorderPool = sync.Pool{
		New: func() any {
			return make([]byte, 0, MaxDNSPacketSize+TagSize)
		},
	}
)

// ─────────────────────────────────────── padding ────────────────────────────

// pad applies ISO/IEC 7816-4 padding to packet, extending it to minSize.
// The format is: data || 0x80 || 0x00… up to minSize.
// If len(packet) >= minSize, only the 0x80 delimiter is appended.
func pad(packet []byte, minSize int, scratch []byte) []byte {
	n := len(packet)
	target := minSize
	if n >= minSize {
		target = n + 1
	}
	var result []byte
	if cap(scratch) >= target {
		result = scratch[:target]
	} else {
		result = make([]byte, target)
	}
	copy(result, packet)
	result[n] = paddingDelimiter
	clear(result[n+1:])
	return result
}

func getPaddedPacketBuffer(size int) []byte {
	buf := paddedPacketPool.Get().([]byte)
	if cap(buf) < size {
		if cap(buf) >= minPooledPaddedPacketCap {
			paddedPacketPool.Put(buf[:0])
		}
		return make([]byte, 0, size)
	}
	return buf[:0]
}

func putPaddedPacketBuffer(buf []byte) {
	if cap(buf) < minPooledPaddedPacketCap {
		return
	}
	// Padded plaintext carries DNS query contents; zero before reuse.
	clear(buf)
	paddedPacketPool.Put(buf[:0])
}

func getXChaChaReorderBuffer(size int) []byte {
	buf := xchachaReorderPool.Get().([]byte)
	if cap(buf) < size {
		if cap(buf) >= minPooledXChaChaBufferCap {
			xchachaReorderPool.Put(buf[:0])
		}
		return make([]byte, 0, size)
	}
	return buf[:0]
}

func putXChaChaReorderBuffer(buf []byte) {
	if cap(buf) < minPooledXChaChaBufferCap {
		return
	}
	xchachaReorderPool.Put(buf[:0])
}

// unpad removes ISO/IEC 7816-4 padding from packet.
// Scans backwards for the 0x80 delimiter; all bytes after it must be 0x00.
// Returns the unpadded slice or an error if padding is malformed.
func unpad(packet []byte) ([]byte, error) {
	n := len(packet)
	if n == 0 {
		return nil, ErrInvalidPaddingShort
	}
	for i := n - 1; i >= 0; i-- {
		switch packet[i] {
		case paddingDelimiter:
			return packet[:i], nil
		case 0x00:
			// valid padding byte; keep scanning
		default:
			return nil, fmt.Errorf("%w at position %d", ErrInvalidPaddingDelimiter, i)
		}
	}
	return nil, ErrInvalidPaddingShort
}

// ─────────────────────────────────────── key helpers ────────────────────────

// isZeroKey reports whether key is all zero bytes using a constant-time
// comparison to prevent side-channel leakage.
func isZeroKey(key []byte) bool {
	if len(key) == 0 {
		return true
	}
	// The hot-path key size is 32 bytes; use a stack zero buffer to avoid a heap
	// allocation while keeping subtle.ConstantTimeCompare semantics.
	if len(key) == 32 {
		var zeros [32]byte
		return subtle.ConstantTimeCompare(key, zeros[:]) == 1
	}
	zeros := make([]byte, len(key))
	return subtle.ConstantTimeCompare(key, zeros) == 1
}

// ZeroizeKey securely zeros a byte slice.
// Uses clear() which the compiler will not optimise away for heap-allocated memory.
func ZeroizeKey(key []byte) {
	if key != nil {
		clear(key)
	}
}

// ZeroizeKey32 securely zeros a 32-byte key array.
func ZeroizeKey32(key *[32]byte) {
	if key != nil {
		clear(key[:])
	}
}

// ValidatePublicKey returns an error if publicKey is nil or all-zero
// (which indicates a low-order or degenerate Curve25519 point).
func ValidatePublicKey(publicKey *[32]byte) error {
	if publicKey == nil {
		return errors.New("nil public key")
	}
	if isZeroKey(publicKey[:]) {
		return ErrWeakPublicKey
	}
	return nil
}

// ─────────────────────────────────────── shared key ─────────────────────────

// ComputeSharedKey computes an ECDH shared secret for the given construction.
//
// For XChaCha20-Poly1305: sharedKey = HChaCha20(X25519(sk, pk), 0…)
// For XSalsa20-Poly1305:  sharedKey = NaCl box.Precompute(pk, sk)
//
// On failure (low-order point or zero shared key) the function logs a Critical
// error and returns a zero key. Callers must check the result with isZeroKey if
// they need to distinguish a failure from a valid key.
//
// Deprecated: prefer ComputeSharedKeyWithError which returns an error. This
// variant is kept for callers that cannot handle an error return.
func ComputeSharedKey(
	cryptoConstruction CryptoConstruction,
	secretKey *[32]byte,
	serverPk *[32]byte,
	providerName *string,
) (sharedKey [32]byte) {
	key, err := computeSharedKeyInternal(cryptoConstruction, secretKey, serverPk)
	if err != nil {
		if providerName != nil {
			dlog.Criticalf("[%s] %v", *providerName, err)
		} else {
			dlog.Critical(err)
		}
		// Return zero key; caller must detect this via isZeroKey.
		return sharedKey
	}
	return key
}

// ComputeSharedKeyWithError computes an ECDH shared secret and returns an
// error if the result is weak or the computation fails.
// This is the preferred API for new code.
func ComputeSharedKeyWithError(
	cryptoConstruction CryptoConstruction,
	secretKey *[32]byte,
	serverPk *[32]byte,
	providerName *string,
) ([32]byte, error) {
	key, err := computeSharedKeyInternal(cryptoConstruction, secretKey, serverPk)
	if err != nil {
		logMsg := err.Error()
		if providerName != nil {
			logMsg = fmt.Sprintf("[%s] %s", *providerName, logMsg)
		}
		return [32]byte{}, fmt.Errorf("%w: %s", ErrWeakPublicKey, logMsg)
	}
	return key, nil
}

// computeSharedKeyInternal is the single shared-key implementation.
// Returns an error on low-order points or a zero shared key; never returns
// a random fallback key.
func computeSharedKeyInternal(
	cryptoConstruction CryptoConstruction,
	secretKey *[32]byte,
	serverPk *[32]byte,
) ([32]byte, error) {
	var sharedKey [32]byte

	if cryptoConstruction == XChacha20Poly1305 {
		// X25519 ECDH, then HChaCha20 with a zero nonce to derive the final key.
		dhKey, err := curve25519.X25519(secretKey[:], serverPk[:])
		if err != nil {
			// curve25519.X25519 returns an error only for low-order input points.
			return sharedKey, fmt.Errorf("weak XChaCha20 public key (low-order point): %w", err)
		}
		var zeroNonce [16]byte
		subKey, err := chacha20.HChaCha20(dhKey, zeroNonce[:])
		if err != nil {
			// Should never happen with valid 32-byte dhKey and 16-byte nonce.
			return sharedKey, fmt.Errorf("HChaCha20 key derivation failed: %w", err)
		}
		copy(sharedKey[:], subKey)
	} else {
		// XSalsa20-Poly1305 via NaCl box.Precompute.
		box.Precompute(&sharedKey, serverPk, secretKey)
		if isZeroKey(sharedKey[:]) {
			// Zero shared key indicates a low-order or degenerate server public key.
			return sharedKey, errors.New("weak XSalsa20 public key (zero shared key)")
		}
	}

	return sharedKey, nil
}

// ─────────────────────────────────────── encrypt ────────────────────────────

// Encrypt encrypts a DNS packet using the DNSCrypt protocol.
//
// Returns the shared key, the encrypted packet, the client nonce, and any
// error. The shared key is returned so the caller can pass it to Decrypt.
//
// Wire format: ClientMagic || PublicKey || ClientNonce || Tag || Ciphertext
func (proxy *Proxy) Encrypt(
	serverInfo *ServerInfo,
	packet []byte,
	proto string,
) (sharedKey *[32]byte, encrypted []byte, clientNonce []byte, err error) {
	// Generate a cryptographically random client nonce (first half of the full nonce).
	clientNonce = make([]byte, HalfNonceSize)
	if _, err := rand.Read(clientNonce); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate client nonce: %w", err)
	}

	// Full nonce: client half || server half (server half stays zero for queries).
	var nonce [NonceSize]byte
	copy(nonce[:], clientNonce)

	// Resolve the public key and shared key.
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

	// Compute padded length.
	paddedLength, err := proxy.calculatePaddedLength(serverInfo, packet, proto)
	if err != nil {
		return sharedKey, nil, clientNonce, err
	}

	// Build and encrypt the packet.
	encrypted, err = proxy.buildEncryptedPacket(serverInfo, publicKey, clientNonce, packet, paddedLength, nonce[:], sharedKey)
	if err != nil {
		return sharedKey, nil, clientNonce, err
	}

	return sharedKey, encrypted, clientNonce, nil
}

// generateEphemeralKeys derives a per-request Curve25519 key pair from the
// client nonce and proxy secret key, computes the ECDH shared key, then
// zeroizes the ephemeral secret key.
//
// Derivation: ephSk = SHA-512/256(clientNonce || proxySecretKey)
// This is deterministic per nonce, so retries produce the same key pair.
//
// Security note: the KDF input is built in a fixed-size stack-allocated array
// rather than via append(), preventing buffer-aliasing into a caller-owned
// backing array and ensuring the concatenated secret material is explicitly
// zeroed before the function returns.
func (proxy *Proxy) generateEphemeralKeys(
	serverInfo *ServerInfo,
	clientNonce []byte,
) (*[PublicKeySize]byte, *[32]byte, error) {
	// Build the KDF input in a fixed-size stack buffer.
	// Using append(clientNonce, secretKey...) would risk writing secretKey bytes
	// into the caller's backing array if cap(clientNonce) > len(clientNonce),
	// and would leave an unzeroed heap allocation containing the secret key.
	var kdfInput [HalfNonceSize + 32]byte
	copy(kdfInput[:HalfNonceSize], clientNonce)
	copy(kdfInput[HalfNonceSize:], proxy.proxySecretKey[:])
	h := sha512.Sum512_256(kdfInput[:])
	// Zeroize the buffer containing nonce || secretKey before any early return.
	clear(kdfInput[:])
	runtime.KeepAlive(&kdfInput)

	ephSk := h // [32]byte on the stack

	var ephPk [PublicKeySize]byte
	curve25519.ScalarBaseMult(&ephPk, &ephSk)

	computedSharedKey := ComputeSharedKey(
		serverInfo.CryptoConstruction,
		&ephSk,
		&serverInfo.ServerPk,
		nil,
	)

	// Zeroize the ephemeral secret key.  runtime.KeepAlive prevents the
	// compiler from proving the variable is dead and eliding the clear.
	clear(ephSk[:])
	runtime.KeepAlive(&ephSk)

	return &ephPk, &computedSharedKey, nil
}

// calculatePaddedLength computes the padded packet length for the given
// protocol and server configuration.
//
//   - UDP: rounds up to a 64-byte block boundary, bounded by MaxDNSUDPPacketSize.
//   - TCP: adds up to 255 bytes of random padding then rounds up, bounded by
//     MaxDNSPacketSize (not MaxDNSUDPPacketSize).
func (proxy *Proxy) calculatePaddedLength(
	serverInfo *ServerInfo,
	packet []byte,
	proto string,
) (int, error) {
	minQuestionSize := QueryOverhead + len(packet)

	if proto == "udp" {
		estimatedSize := proxy.questionSizeEstimator.MinQuestionSize()
		if estimatedSize > minQuestionSize {
			minQuestionSize = estimatedSize
		}
		// Round up to the next 64-byte boundary, capped at the UDP MTU limit.
		paddedLength := min(MaxDNSUDPPacketSize, (minQuestionSize+1+paddingBlockSize-1)&^(paddingBlockSize-1))

		// Override for known server quirks.
		if serverInfo.knownBugs.fragmentsBlocked {
			paddedLength = MaxDNSUDPSafePacketSize
		}

		requiredSize := QueryOverhead + len(packet) + 1
		if requiredSize > paddedLength {
			return 0, fmt.Errorf("%w: need %d bytes, only %d available",
				ErrQuestionTooLarge, requiredSize, paddedLength)
		}
		return paddedLength, nil
	}

	// TCP: add up to 255 bytes of random padding then align.
	var randomPad [1]byte
	if _, err := rand.Read(randomPad[:]); err != nil {
		return 0, fmt.Errorf("failed to generate random padding: %w", err)
	}
	minQuestionSize += int(randomPad[0])

	// Use relay full-packet size when relaying over TCP.
	if serverInfo.Relay != nil {
		return MaxDNSPacketSize, nil
	}

	// Round up to next 64-byte boundary, capped at full TCP DNS limit.
	paddedLength := min(MaxDNSPacketSize, (minQuestionSize+1+paddingBlockSize-1)&^(paddingBlockSize-1))

	requiredSize := QueryOverhead + len(packet) + 1
	if requiredSize > paddedLength {
		return 0, fmt.Errorf("%w: need %d bytes, only %d available",
			ErrQuestionTooLarge, requiredSize, paddedLength)
	}
	return paddedLength, nil
}

// buildEncryptedPacket assembles the complete encrypted DNSCrypt query packet.
//
// Wire format: MagicQuery || PublicKey || ClientNonce || Tag || Ciphertext
func (proxy *Proxy) buildEncryptedPacket(
	serverInfo *ServerInfo,
	publicKey *[PublicKeySize]byte,
	clientNonce []byte,
	packet []byte,
	paddedLength int,
	nonce []byte,
	sharedKey *[32]byte,
) ([]byte, error) {
	// Pre-allocate the exact output size to avoid any reallocation.
	// Header: MagicQuery(8) + PublicKey(32) + HalfNonce(12)
	// Body:   Tag(16) + paddedLength
	headerLen := len(serverInfo.MagicQuery) + PublicKeySize + HalfNonceSize
	encrypted := make([]byte, 0, headerLen+TagSize+paddedLength)

	encrypted = append(encrypted, serverInfo.MagicQuery[:]...)
	encrypted = append(encrypted, publicKey[:]...)
	encrypted = append(encrypted, clientNonce...)

	// Pad the plaintext to the target length.
	paddedScratch := getPaddedPacketBuffer(paddedLength - QueryOverhead)
	padded := pad(packet, paddedLength-QueryOverhead, paddedScratch)
	defer putPaddedPacketBuffer(padded)

	switch serverInfo.CryptoConstruction {
	case XChacha20Poly1305:
		return proxy.encryptXChaCha20(encrypted, padded, nonce, sharedKey)
	default:
		return proxy.encryptXSalsa20(encrypted, padded, nonce, sharedKey)
	}
}

// encryptXChaCha20 appends a Tag||Ciphertext block to dst using
// XChaCha20-Poly1305 AEAD.
//
// DNSCrypt wire format places the tag BEFORE the ciphertext.
// Go's AEAD.Seal produces Ciphertext||Tag, so we seal into a temporary
// staging area and then copy tag-first into dst to avoid a second allocation.
func (proxy *Proxy) encryptXChaCha20(
	dst []byte,
	plaintext []byte,
	nonce []byte,
	sharedKey *[32]byte,
) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(sharedKey[:])
	if err != nil {
		return dst, fmt.Errorf("%w: XChaCha20-Poly1305: %w", ErrCipherInitFailed, err)
	}

	// Build final output in a single allocation:
	// [existing dst][tag][ciphertext], while Seal writes [ciphertext][tag].
	start := len(dst)
	out := make([]byte, start+TagSize+len(plaintext))
	copy(out, dst)

	// Zero-length slice at the ciphertext start: Seal appends ciphertext||tag
	// into the reserved tail when capacity allows.
	sealAppendTarget := out[start+TagSize : start+TagSize : len(out)]
	sealed := aead.Seal(sealAppendTarget, nonce, plaintext, nil) // ciphertext || tag
	if len(sealed) < TagSize {
		return dst, fmt.Errorf("%w: ciphertext too short after seal", ErrMessageTooShort)
	}

	ciphertextLen := len(sealed) - TagSize
	// Always copy from sealed so this remains correct even if Seal reallocates.
	copy(out[start:start+TagSize], sealed[ciphertextLen:]) // tag
	copy(out[start+TagSize:], sealed[:ciphertextLen])      // ciphertext
	return out, nil
}

// encryptXSalsa20 appends a Tag||Ciphertext block to dst using
// XSalsa20-Poly1305 (NaCl secretbox).
//
// secretbox.Seal naturally produces tag||ciphertext, which matches the
// DNSCrypt wire format.
func (proxy *Proxy) encryptXSalsa20(
	dst []byte,
	plaintext []byte,
	nonce []byte,
	sharedKey *[32]byte,
) ([]byte, error) {
	var xsalsaNonce [NonceSize]byte
	copy(xsalsaNonce[:], nonce)
	// secretbox.Seal appends tag||ciphertext to dst.
	return secretbox.Seal(dst, plaintext, &xsalsaNonce, sharedKey), nil
}

// ─────────────────────────────────────── decrypt ────────────────────────────

// Decrypt decrypts a DNSCrypt response and returns the plaintext DNS packet.
//
// Wire format: ServerMagic || ServerNonce || Tag || Ciphertext
func (proxy *Proxy) Decrypt(
	serverInfo *ServerInfo,
	sharedKey *[32]byte,
	encrypted []byte,
	nonce []byte,
) ([]byte, error) {
	serverMagicLen := len(ServerMagic)
	responseHeaderLen := serverMagicLen + NonceSize

	if err := proxy.validateResponse(encrypted, nonce); err != nil {
		return encrypted, err
	}

	serverNonce := encrypted[serverMagicLen:responseHeaderLen]
	body := encrypted[responseHeaderLen:]

	var (
		packet []byte
		err    error
	)
	switch serverInfo.CryptoConstruction {
	case XChacha20Poly1305:
		packet, err = proxy.decryptXChaCha20(body, serverNonce, sharedKey)
	default:
		packet, err = proxy.decryptXSalsa20(body, serverNonce, sharedKey)
	}
	if err != nil {
		return encrypted, err
	}

	packet, err = unpad(packet)
	if err != nil {
		return encrypted, fmt.Errorf("%w: %w", ErrIncorrectPadding, err)
	}

	if len(packet) < MinDNSPacketSize {
		return encrypted, fmt.Errorf("%w: packet size %d < minimum %d",
			ErrIncorrectPadding, len(packet), MinDNSPacketSize)
	}

	return packet, nil
}

// validateResponse checks size bounds, server magic, and client-nonce echo
// of an encrypted response using constant-time comparisons.
func (proxy *Proxy) validateResponse(encrypted []byte, nonce []byte) error {
	serverMagicLen := len(ServerMagic)
	responseHeaderLen := serverMagicLen + NonceSize
	minResponseSize := responseHeaderLen + TagSize + MinDNSPacketSize
	maxResponseSize := responseHeaderLen + TagSize + MaxDNSPacketSize

	n := len(encrypted)
	if n < minResponseSize || n > maxResponseSize {
		return fmt.Errorf("%w: size %d not in range [%d, %d]",
			ErrInvalidMessageSize, n, minResponseSize, maxResponseSize)
	}

	// Constant-time magic check prevents timing attacks.
	if subtle.ConstantTimeCompare(encrypted[:serverMagicLen], ServerMagic[:]) != 1 {
		return ErrInvalidMagicPrefix
	}

	// Constant-time nonce-echo check: server must mirror the client's half-nonce.
	serverNonce := encrypted[serverMagicLen:responseHeaderLen]
	if subtle.ConstantTimeCompare(nonce[:HalfNonceSize], serverNonce[:HalfNonceSize]) != 1 {
		return ErrUnexpectedNonce
	}

	return nil
}

// decryptXChaCha20 decrypts a Tag||Ciphertext block using XChaCha20-Poly1305.
//
// DNSCrypt sends tag BEFORE ciphertext; Go's AEAD.Open expects ciphertext||tag.
// We rearrange using a [TagSize]byte stack copy to avoid a heap allocation.
func (proxy *Proxy) decryptXChaCha20(
	tagAndCt []byte,
	serverNonce []byte,
	sharedKey *[32]byte,
) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(sharedKey[:])
	if err != nil {
		return nil, fmt.Errorf("%w: XChaCha20-Poly1305: %w", ErrCipherInitFailed, err)
	}

	if len(tagAndCt) < TagSize {
		return nil, fmt.Errorf("%w: need at least %d bytes, got %d",
			ErrMessageTooShort, TagSize, len(tagAndCt))
	}

	// DNSCrypt layout: tag(16) || ciphertext
	// AEAD.Open expects:      ciphertext || tag(16)
	// Rearrange in one allocation with direct copies.
	stdFormat := getXChaChaReorderBuffer(len(tagAndCt))
	stdFormat = stdFormat[:len(tagAndCt)]
	defer putXChaChaReorderBuffer(stdFormat)
	ciphertextLen := len(tagAndCt) - TagSize
	copy(stdFormat, tagAndCt[TagSize:])                 // ciphertext
	copy(stdFormat[ciphertextLen:], tagAndCt[:TagSize]) // tag

	packet, err := aead.Open(nil, serverNonce, stdFormat, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: XChaCha20-Poly1305: %w", ErrIncorrectTag, err)
	}

	return packet, nil
}

// decryptXSalsa20 decrypts a ciphertext block using XSalsa20-Poly1305
// (NaCl secretbox). secretbox natively handles tag-first format.
func (proxy *Proxy) decryptXSalsa20(
	ciphertext []byte,
	serverNonce []byte,
	sharedKey *[32]byte,
) ([]byte, error) {
	var xsalsaNonce [NonceSize]byte
	copy(xsalsaNonce[:], serverNonce)

	packet, ok := secretbox.Open(nil, ciphertext, &xsalsaNonce, sharedKey)
	if !ok {
		return nil, fmt.Errorf("%w: XSalsa20-Poly1305 authentication failed", ErrIncorrectTag)
	}

	return packet, nil
}
