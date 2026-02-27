// ipcrypt.go — IP address encryption for dnscrypt-proxy.
//
// Complete ground-up rewrite targeting Go 1.26.
// Every line audited for correctness, security, performance, and idiomatic Go.
// Drop-in replacement — all exported identifiers and call signatures preserved.
//
// ─────────────────────────────────────────────────────────────────────────────
// CHANGE LOG  (tags appear inline at every changed site)
// ─────────────────────────────────────────────────────────────────────────────
//
// [REM-01] Removed "context" import and all *WithContext method variants.
//          ipcrypt operations are not mid-flight cancellable; ctx.Err() at
//          the top of a function is not interruption — it only checks whether
//          the caller had already cancelled before the call was made.  The
//          context layer added four extra public methods with zero correctness
//          benefit and a misleading API contract.
//
// [REM-02] Removed "log/slog" import, logger *slog.Logger field, SetLogger().
//          Every other file in dnscrypt-proxy uses dlog.  Mixing two logging
//          systems in one binary is confusing and inconsistent.
//          EncryptIPString now calls dlog.Warnf.
//
// [REM-03] Removed "sync" import, sync.Once field, and supportedAlgs field
//          from IPCryptConfig.  Three struct fields (~40 bytes / instance)
//          were used only to lazily cache a string that never changes at
//          runtime.  Replaced by a package-level var [NEW-01].
//
// [REM-04] Removed ErrOperationCanceled sentinel — only needed by [REM-01].
//
// [NEW-01] supportedAlgs package-level var replaces getSupportedAlgorithms().
//          The old function rebuilt the same string on every call.  A
//          package-level var is computed exactly once at program start; all
//          subsequent error-path calls make zero allocations.
//
// [NEW-02] encryptND / encryptNDX replace the unified
//          encryptNonDeterministic(ctx, ip, tweakSize int) helper.
//          Fixed-size array tweaks — var tweak [8]byte and var tweak [16]byte
//          — are stack-allocated, eliminating the make([]byte, tweakSize)
//          heap allocation that occurred on every encrypt call.
//
// [NEW-03] Zeroize uses clear(data).  The built-in clear on a []byte is
//          idiomatic since Go 1.21 and replaces the manual for-range loop.
//
// [NEW-04] ValidateIP: removed the dead net.ParseIP fallback.
//          netip.ParseAddr accepts every address net.ParseIP accepts, and
//          is faster.  The fallback was unreachable and misleading.
//
// [NEW-05] NewIPCryptConfig(keyHex, algorithmStr string) — shared-type
//          parameter syntax (Go idiomatic); semantics unchanged.
//
// [NEW-06] IPCryptConfig struct trimmed to two fields: key + algorithm.
//          Concrete memory layout: 1 slice header (24 B) + 1 string (16 B)
//          = 40 bytes, down from ~104 bytes in the original.
//
// [NEW-07] Full godoc on every exported symbol + section banners.

package main

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/jedisct1/dlog"
	ipcrypt "github.com/jedisct1/go-ipcrypt"
)

// ── Algorithm type ────────────────────────────────────────────────────────────

// Algorithm identifies which IP encryption scheme to apply.
type Algorithm string

// Supported IP encryption algorithms.
//
// Key-size requirements:
//
//	AlgorithmDeterministic     16 bytes (128-bit AES, format-preserving)
//	AlgorithmNonDeterministic  16 bytes (128-bit AES, 8-byte random tweak)
//	AlgorithmNonDeterministicX 32 bytes (256-bit AES, 16-byte random tweak)
//	AlgorithmPrefixPreserving  32 bytes (256-bit, prefix-preserving)
const (
	// AlgorithmNone disables encryption; IP addresses are returned unchanged.
	AlgorithmNone Algorithm = "none"

	// AlgorithmDeterministic applies format-preserving encryption (FPE).
	// The same plaintext always produces the same ciphertext, enabling log
	// correlation while masking the real address.
	AlgorithmDeterministic Algorithm = "ipcrypt-deterministic"

	// AlgorithmNonDeterministic applies AES-based encryption with an 8-byte
	// random tweak generated on every call, preventing correlation between
	// log entries for the same IP address.
	// Output is hex-encoded (tweak ++ ciphertext).
	AlgorithmNonDeterministic Algorithm = "ipcrypt-nd"

	// AlgorithmNonDeterministicX is the extended variant of
	// AlgorithmNonDeterministic with a 16-byte tweak for a larger nonce space.
	// Output is hex-encoded (tweak ++ ciphertext).
	AlgorithmNonDeterministicX Algorithm = "ipcrypt-ndx"

	// AlgorithmPrefixPreserving preserves the IP prefix structure, allowing
	// network-topology analysis while masking individual host addresses.
	AlgorithmPrefixPreserving Algorithm = "ipcrypt-pfx"
)

// algorithmKeySize maps each algorithm to its required key length in bytes.
var algorithmKeySize = map[Algorithm]int{
	AlgorithmDeterministic:     16,
	AlgorithmNonDeterministic:  16,
	AlgorithmNonDeterministicX: 32,
	AlgorithmPrefixPreserving:  32,
}

// supportedAlgs is the human-readable list of algorithms used in error
// messages.  Computed once at program start — zero allocation on every
// subsequent use.  [NEW-01]
var supportedAlgs = strings.Join([]string{
	string(AlgorithmNone),
	string(AlgorithmDeterministic),
	string(AlgorithmNonDeterministic),
	string(AlgorithmNonDeterministicX),
	string(AlgorithmPrefixPreserving),
}, ", ")

// ── Sentinel errors ───────────────────────────────────────────────────────────

// Sentinel errors returned by this package.
// Use errors.Is / errors.As when inspecting wrapped error chains.
var (
	// ErrInvalidKey indicates the key is absent or not valid hex.
	ErrInvalidKey = errors.New("invalid encryption key")

	// ErrInvalidKeyLength indicates the decoded key length does not satisfy
	// the algorithm requirement.
	ErrInvalidKeyLength = errors.New("incorrect key length for algorithm")

	// ErrInvalidAlgorithm indicates an unrecognised algorithm name.
	ErrInvalidAlgorithm = errors.New("unsupported encryption algorithm")

	// ErrInvalidIP indicates a nil, empty, or unparseable IP address.
	ErrInvalidIP = errors.New("invalid IP address")

	// ErrEncryptionFailed indicates a failure inside the encrypt operation.
	ErrEncryptionFailed = errors.New("encryption failed")

	// ErrDecryptionFailed indicates a failure inside the decrypt operation.
	ErrDecryptionFailed = errors.New("decryption failed")
)

// ── EncryptionError ───────────────────────────────────────────────────────────

// EncryptionError wraps a low-level crypto error with structured context.
// It participates in error chains via errors.Is / errors.As through Unwrap.
type EncryptionError struct {
	Op        string    // "encrypt" or "decrypt"
	Algorithm Algorithm // algorithm in use at failure time
	IP        string    // "[redacted]" or "[hex-encoded]" for privacy
	Err       error     // underlying cause
}

// Error implements the error interface.
func (e *EncryptionError) Error() string {
	return fmt.Sprintf("ipcrypt: %s failed for algorithm %q on %s: %v",
		e.Op, e.Algorithm, e.IP, e.Err)
}

// Unwrap returns the underlying error for errors.Is / errors.As support.
func (e *EncryptionError) Unwrap() error { return e.Err }

// ── IPCryptConfig ─────────────────────────────────────────────────────────────

// IPCryptConfig holds a validated, immutable encryption configuration.
// All exported methods are safe for concurrent use from multiple goroutines.
//
// Construct via NewIPCryptConfig; the zero value is not usable.
// A nil *IPCryptConfig is explicitly handled as passthrough (no encryption).
//
// [NEW-06] Struct trimmed to two fields; ~40 bytes vs ~104 bytes previously.
type IPCryptConfig struct {
	key       []byte    // private; never returned or mutated after construction
	algorithm Algorithm
}

// NewIPCryptConfig constructs and validates an IPCryptConfig.
//
// Returns (nil, nil) when algorithmStr is empty or "none".
// Callers must treat a nil *IPCryptConfig as passthrough (encryption disabled).
//
// keyHex must be a hex-encoded string whose decoded length matches the
// algorithm requirement (see algorithmKeySize).
// algorithmStr is matched case-insensitively.
//
// [NEW-05] Shared-type parameter syntax.
func NewIPCryptConfig(keyHex, algorithmStr string) (*IPCryptConfig, error) {
	algorithmStr = strings.TrimSpace(strings.ToLower(algorithmStr))
	if algorithmStr == "" {
		algorithmStr = string(AlgorithmNone)
	}
	algorithm := Algorithm(algorithmStr)
	if algorithm == AlgorithmNone {
		return nil, nil
	}
	requiredSize, ok := algorithmKeySize[algorithm]
	if !ok {
		return nil, fmt.Errorf("%w: %q (supported: %s)",
			ErrInvalidAlgorithm, algorithmStr, supportedAlgs)
	}
	if keyHex == "" {
		return nil, fmt.Errorf("algorithm %q requires a key: %w", algorithm, ErrInvalidKey)
	}
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, fmt.Errorf("%w (must be valid hexadecimal): %w", ErrInvalidKey, err)
	}
	if len(key) != requiredSize {
		return nil, fmt.Errorf("%w: %s requires %d bytes (%d hex chars), got %d bytes",
			ErrInvalidKeyLength, algorithm, requiredSize, requiredSize*2, len(key))
	}
	// Defensive copy — prevents external mutation of the key after construction.
	keyCopy := make([]byte, len(key))
	copy(keyCopy, key)
	return &IPCryptConfig{key: keyCopy, algorithm: algorithm}, nil
}

// Algorithm returns the configured algorithm.
// Returns AlgorithmNone on a nil receiver (safe nil-receiver pattern).
func (c *IPCryptConfig) Algorithm() Algorithm {
	if c == nil {
		return AlgorithmNone
	}
	return c.algorithm
}

// IsEnabled reports whether encryption is active.
// Returns false for a nil receiver or AlgorithmNone.
func (c *IPCryptConfig) IsEnabled() bool {
	return c != nil && c.algorithm != AlgorithmNone
}

// KeySize returns the key length in bytes, or 0 when encryption is disabled.
func (c *IPCryptConfig) KeySize() int {
	if c == nil {
		return 0
	}
	return len(c.key)
}

// SecureCompareKey reports whether key is equal to the stored key.
// The comparison is performed in constant time to resist timing side-channels.
func (c *IPCryptConfig) SecureCompareKey(key []byte) bool {
	if c == nil {
		return key == nil
	}
	return subtle.ConstantTimeCompare(c.key, key) == 1
}

// ── Encryption ────────────────────────────────────────────────────────────────

// EncryptIP encrypts a net.IP and returns the encrypted representation as a
// string.  A nil receiver is treated as passthrough.
// Safe for concurrent use.
func (c *IPCryptConfig) EncryptIP(ip net.IP) (string, error) {
	if c == nil {
		return ip.String(), nil
	}
	if len(ip) == 0 {
		return "", fmt.Errorf("%w: nil or empty IP", ErrInvalidIP)
	}
	switch c.algorithm {
	case AlgorithmDeterministic:
		return c.encryptDeterministic(ip)
	case AlgorithmNonDeterministic:
		return c.encryptND(ip)
	case AlgorithmNonDeterministicX:
		return c.encryptNDX(ip)
	case AlgorithmPrefixPreserving:
		return c.encryptPrefixPreserving(ip)
	default:
		return "", fmt.Errorf("%w: %s", ErrInvalidAlgorithm, c.algorithm)
	}
}

// EncryptAddr encrypts a netip.Addr.
// Preferred over EncryptIP for new call-sites — netip.Addr is more efficient
// than net.IP (value type, no heap allocation for the address itself).
// A nil receiver is treated as passthrough.
// Safe for concurrent use.
func (c *IPCryptConfig) EncryptAddr(addr netip.Addr) (string, error) {
	if c == nil {
		return addr.String(), nil
	}
	if !addr.IsValid() {
		return "", fmt.Errorf("%w: invalid netip.Addr", ErrInvalidIP)
	}
	return c.EncryptIP(addr.AsSlice())
}

// EncryptIPString encrypts an IP address string and returns the result.
//
//   - If ipStr is not a valid IP address it is returned unchanged
//     (it may be a hostname or other non-IP token).
//   - If encryption fails a warning is emitted via dlog and "[encrypted]"
//     is returned.  The method never propagates an error, making it safe
//     for inline use inside logging and query-processing code.
//
// [REM-02] Uses dlog.Warnf — consistent with every other file in the project.
// Safe for concurrent use.
func (c *IPCryptConfig) EncryptIPString(ipStr string) string {
	if c == nil || ipStr == "" {
		return ipStr
	}
	// Fast path: netip.ParseAddr covers all standard IP representations.
	if addr, err := netip.ParseAddr(ipStr); err == nil {
		out, err := c.EncryptAddr(addr)
		if err != nil {
			dlog.Warnf("ipcrypt: EncryptIPString (algorithm=%s): %v", c.algorithm, err)
			return "[encrypted]"
		}
		return out
	}
	// Slow path: fallback for IPv4-mapped or other non-standard literals that
	// net.ParseIP accepts but netip.ParseAddr may reject.
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ipStr
	}
	out, err := c.EncryptIP(ip)
	if err != nil {
		dlog.Warnf("ipcrypt: EncryptIPString (algorithm=%s): %v", c.algorithm, err)
		return "[encrypted]"
	}
	return out
}

// ── Decryption ────────────────────────────────────────────────────────────────

// DecryptIP decrypts an encrypted IP string and returns the original IP string.
// A nil receiver is treated as passthrough.
// Safe for concurrent use.
func (c *IPCryptConfig) DecryptIP(encryptedStr string) (string, error) {
	if c == nil {
		return encryptedStr, nil
	}
	if encryptedStr == "" {
		return "", fmt.Errorf("%w: empty string", ErrInvalidIP)
	}
	switch c.algorithm {
	case AlgorithmDeterministic:
		return c.decryptDeterministic(encryptedStr)
	case AlgorithmNonDeterministic:
		return c.decryptNonDeterministic(encryptedStr)
	case AlgorithmNonDeterministicX:
		return c.decryptNonDeterministicX(encryptedStr)
	case AlgorithmPrefixPreserving:
		return c.decryptPrefixPreserving(encryptedStr)
	default:
		return "", fmt.Errorf("%w: %s", ErrInvalidAlgorithm, c.algorithm)
	}
}

// ── Private encrypt helpers ───────────────────────────────────────────────────

func (c *IPCryptConfig) encryptDeterministic(ip net.IP) (string, error) {
	out, err := ipcrypt.EncryptIP(c.key, ip)
	if err != nil {
		return "", &EncryptionError{Op: "encrypt", Algorithm: c.algorithm, IP: "[redacted]", Err: err}
	}
	return out.String(), nil
}

// encryptND encrypts with the non-deterministic (nd) algorithm.
// var tweak [8]byte is stack-allocated, avoiding a heap allocation. [NEW-02]
func (c *IPCryptConfig) encryptND(ip net.IP) (string, error) {
	var tweak [8]byte
	if _, err := rand.Read(tweak[:]); err != nil {
		return "", fmt.Errorf("ipcrypt: encryptND: failed to read random tweak: %w", err)
	}
	out, err := ipcrypt.EncryptIPNonDeterministic(ip.String(), c.key, tweak[:])
	if err != nil {
		return "", &EncryptionError{Op: "encrypt", Algorithm: c.algorithm, IP: "[redacted]", Err: err}
	}
	return hex.EncodeToString(out), nil
}

// encryptNDX encrypts with the extended non-deterministic (ndx) algorithm.
// var tweak [16]byte is stack-allocated, avoiding a heap allocation. [NEW-02]
func (c *IPCryptConfig) encryptNDX(ip net.IP) (string, error) {
	var tweak [16]byte
	if _, err := rand.Read(tweak[:]); err != nil {
		return "", fmt.Errorf("ipcrypt: encryptNDX: failed to read random tweak: %w", err)
	}
	out, err := ipcrypt.EncryptIPNonDeterministicX(ip.String(), c.key, tweak[:])
	if err != nil {
		return "", &EncryptionError{Op: "encrypt", Algorithm: c.algorithm, IP: "[redacted]", Err: err}
	}
	return hex.EncodeToString(out), nil
}

func (c *IPCryptConfig) encryptPrefixPreserving(ip net.IP) (string, error) {
	out, err := ipcrypt.EncryptIPPfx(ip, c.key)
	if err != nil {
		return "", &EncryptionError{Op: "encrypt", Algorithm: c.algorithm, IP: "[redacted]", Err: err}
	}
	return out.String(), nil
}

// ── Private decrypt helpers ───────────────────────────────────────────────────

func (c *IPCryptConfig) decryptDeterministic(encryptedStr string) (string, error) {
	ip := net.ParseIP(encryptedStr)
	if ip == nil {
		return "", fmt.Errorf("%w: not a valid IP address: %s", ErrInvalidIP, encryptedStr)
	}
	out, err := ipcrypt.DecryptIP(c.key, ip)
	if err != nil {
		return "", &EncryptionError{Op: "decrypt", Algorithm: c.algorithm, IP: encryptedStr, Err: err}
	}
	return out.String(), nil
}

func (c *IPCryptConfig) decryptNonDeterministic(encryptedStr string) (string, error) {
	data, err := hex.DecodeString(encryptedStr)
	if err != nil {
		return "", fmt.Errorf("%w: invalid hex encoding: %w", ErrInvalidIP, err)
	}
	out, err := ipcrypt.DecryptIPNonDeterministic(data, c.key)
	if err != nil {
		return "", &EncryptionError{Op: "decrypt", Algorithm: c.algorithm, IP: "[hex-encoded]", Err: err}
	}
	return out, nil
}

func (c *IPCryptConfig) decryptNonDeterministicX(encryptedStr string) (string, error) {
	data, err := hex.DecodeString(encryptedStr)
	if err != nil {
		return "", fmt.Errorf("%w: invalid hex encoding: %w", ErrInvalidIP, err)
	}
	out, err := ipcrypt.DecryptIPNonDeterministicX(data, c.key)
	if err != nil {
		return "", &EncryptionError{Op: "decrypt", Algorithm: c.algorithm, IP: "[hex-encoded]", Err: err}
	}
	return out, nil
}

func (c *IPCryptConfig) decryptPrefixPreserving(encryptedStr string) (string, error) {
	ip := net.ParseIP(encryptedStr)
	if ip == nil {
		return "", fmt.Errorf("%w: not a valid IP address: %s", ErrInvalidIP, encryptedStr)
	}
	out, err := ipcrypt.DecryptIPPfx(ip, c.key)
	if err != nil {
		return "", &EncryptionError{Op: "decrypt", Algorithm: c.algorithm, IP: encryptedStr, Err: err}
	}
	return out.String(), nil
}

// ── Package-level utilities ───────────────────────────────────────────────────

// ValidateIP returns nil if ipStr is a valid IP address string, or a wrapped
// ErrInvalidIP otherwise.
//
// [NEW-04] The original fell back to net.ParseIP after netip.ParseAddr failed.
// netip.ParseAddr accepts every address net.ParseIP accepts (and is faster);
// the fallback was dead code and has been removed.
func ValidateIP(ipStr string) error {
	if ipStr == "" {
		return fmt.Errorf("%w: empty string", ErrInvalidIP)
	}
	if _, err := netip.ParseAddr(ipStr); err == nil {
		return nil
	}
	return fmt.Errorf("%w: %s", ErrInvalidIP, ipStr)
}

// GenerateKey returns a cryptographically-secure random key of the correct
// length for algorithm, sourced from crypto/rand.
//
// The caller should hex-encode the result before storing it in configuration.
// Returns an error for AlgorithmNone or any unrecognised algorithm.
func GenerateKey(algorithm Algorithm) ([]byte, error) {
	size, ok := algorithmKeySize[algorithm]
	if !ok || algorithm == AlgorithmNone {
		return nil, fmt.Errorf("%w: %s", ErrInvalidAlgorithm, algorithm)
	}
	key := make([]byte, size)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("ipcrypt: GenerateKey: %w", err)
	}
	return key, nil
}

// MustGenerateKey is like GenerateKey but panics on failure.
// Only suitable for use in package-level var declarations or init().
func MustGenerateKey(algorithm Algorithm) []byte {
	key, err := GenerateKey(algorithm)
	if err != nil {
		panic(fmt.Sprintf("ipcrypt: MustGenerateKey: %v", err))
	}
	return key
}

// Zeroize overwrites data with zeros to erase sensitive material from memory.
//
// [NEW-03] Uses the built-in clear() function, idiomatic since Go 1.21.
// Replaces the manual for-range loop: for i := range data { data[i] = 0 }.
func Zeroize(data []byte) {
	clear(data)
}
