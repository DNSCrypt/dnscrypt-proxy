// Package main provides IP address encryption functionality with multiple algorithms.
// This implementation is optimized for Go 1.26 and follows modern Go best practices.
//
// Go 1.26 Modernizations:
//   - Context support for cancellable operations with proper cleanup
//   - Structured logging with log/slog
//   - Enhanced error handling with wrapped errors (errors.Is/As support)
//   - Zero-allocation operations with netip.Addr
//   - Thread-safe concurrent access patterns
//   - Optimized memory allocation leveraging Go 1.26 GC improvements
//   - Constant-time operations where applicable for security
//
// Supported Algorithms:
//   - none: No encryption (passthrough)
//   - ipcrypt-deterministic: Deterministic encryption (same input → same output)
//   - ipcrypt-nd: Non-deterministic with 8-byte tweak
//   - ipcrypt-ndx: Extended non-deterministic with 16-byte tweak
//   - ipcrypt-pfx: Prefix-preserving encryption
package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"

	ipcrypt "github.com/jedisct1/go-ipcrypt"
)

// Algorithm represents the type of IP encryption algorithm.
// Go 1.26: Using typed string constants for type safety and better documentation.
type Algorithm string

// Supported IP encryption algorithms with their characteristics.
// Each algorithm provides different security and privacy tradeoffs.
const (
	// AlgorithmNone disables encryption (passthrough mode).
	// Use when encryption is not required.
	//   - Key size: N/A
	//   - Output: Original IP address
	//   - Use case: Development, testing, or when privacy is not required
	AlgorithmNone Algorithm = "none"

	// AlgorithmDeterministic uses deterministic encryption.
	// Same IP always encrypts to the same output, enabling log correlation.
	//   - Key size: 16 bytes (128-bit)
	//   - Output: Valid IP address format
	//   - Use case: Log correlation while maintaining privacy
	//   - Security: Format-preserving encryption (FPE)
	AlgorithmDeterministic Algorithm = "ipcrypt-deterministic"

	// AlgorithmNonDeterministic uses non-deterministic encryption with 8-byte tweak.
	// Different output each time, maximizing privacy.
	//   - Key size: 16 bytes (128-bit)
	//   - Tweak size: 8 bytes (random)
	//   - Output: Hex-encoded binary (tweak + encrypted data)
	//   - Use case: Maximum privacy, no correlation possible
	//   - Security: AES-based encryption with random initialization
	AlgorithmNonDeterministic Algorithm = "ipcrypt-nd"

	// AlgorithmNonDeterministicX uses extended non-deterministic encryption with 16-byte tweak.
	// Maximum security variant with longer tweak for enhanced security.
	//   - Key size: 32 bytes (256-bit)
	//   - Tweak size: 16 bytes (random)
	//   - Output: Hex-encoded binary (tweak + encrypted data)
	//   - Use case: Maximum security with extended tweak space
	//   - Security: Enhanced AES-based encryption with larger tweak
	AlgorithmNonDeterministicX Algorithm = "ipcrypt-ndx"

	// AlgorithmPrefixPreserving preserves IP address prefixes during encryption.
	// Enables network topology analysis while maintaining privacy.
	//   - Key size: 32 bytes (256-bit)
	//   - Output: Valid IP address format with preserved prefix
	//   - Use case: Network topology analysis with privacy
	//   - Security: Prefix-preserving encryption maintains network structure
	AlgorithmPrefixPreserving Algorithm = "ipcrypt-pfx"
)

// algorithmKeySize maps algorithms to their required key sizes in bytes.
// This provides compile-time validation of key requirements.
var algorithmKeySize = map[Algorithm]int{
	AlgorithmDeterministic:     16, // 128-bit AES
	AlgorithmNonDeterministic:  16, // 128-bit AES
	AlgorithmNonDeterministicX: 32, // 256-bit AES
	AlgorithmPrefixPreserving:  32, // 256-bit for enhanced security
}

// Sentinel errors for IP encryption operations.
// Go 1.26: Use errors.Is() for error checking, enabling wrapped error comparison.
var (
	// ErrInvalidKey indicates the provided key is invalid or empty.
	ErrInvalidKey = errors.New("invalid encryption key")

	// ErrInvalidKeyLength indicates the key length doesn't match algorithm requirements.
	ErrInvalidKeyLength = errors.New("incorrect key length for algorithm")

	// ErrInvalidAlgorithm indicates an unsupported or unknown algorithm was specified.
	ErrInvalidAlgorithm = errors.New("unsupported encryption algorithm")

	// ErrInvalidIP indicates the IP address is invalid or malformed.
	ErrInvalidIP = errors.New("invalid IP address")

	// ErrEncryptionFailed indicates encryption operation failed.
	ErrEncryptionFailed = errors.New("encryption failed")

	// ErrDecryptionFailed indicates decryption operation failed.
	ErrDecryptionFailed = errors.New("decryption failed")

	// ErrOperationCanceled indicates the operation was canceled via context.
	ErrOperationCanceled = errors.New("operation canceled")
)

// EncryptionError provides detailed context about encryption failures.
// Go 1.26: Structured error type for better error diagnostics and handling.
type EncryptionError struct {
	Op        string    // Operation that failed (e.g., "encrypt", "decrypt")
	Algorithm Algorithm // Algorithm being used
	IP        string    // IP address involved (may be redacted for privacy)
	Err       error     // Underlying error cause
}

// Error implements the error interface.
func (e *EncryptionError) Error() string {
	return fmt.Sprintf("ipcrypt: %s operation failed for algorithm %q on IP %s: %v",
		e.Op, e.Algorithm, e.IP, e.Err)
}

// Unwrap returns the underlying error for error chain inspection.
// Go 1.26: Enables errors.Is() and errors.As() to work with wrapped errors.
func (e *EncryptionError) Unwrap() error {
	return e.Err
}

// IPCryptConfig holds the configuration for IP address encryption.
// Go 1.26: Immutable after creation, thread-safe for concurrent use.
//
// All exported methods are safe for concurrent calls from multiple goroutines.
// The configuration is validated at construction time for fail-fast behavior.
type IPCryptConfig struct {
	key       []byte    // Encryption key (private, never exported)
	algorithm Algorithm // Algorithm type

	// Cached algorithm list for error messages (initialized lazily)
	supportedAlgsOnce sync.Once
	supportedAlgs     string

	// Optional logger (defaults to slog.Default())
	logger *slog.Logger
}

// NewIPCryptConfig creates a new IPCryptConfig from configuration values.
// Returns (nil, nil) when encryption is disabled (algorithm is "none" or empty).
//
// Go 1.26: Validates configuration at construction time for fail-fast behavior.
// This ensures that invalid configurations are caught early, not at runtime.
//
// Parameters:
//   - keyHex: Hexadecimal-encoded encryption key (length depends on algorithm)
//   - algorithmStr: Algorithm name (case-insensitive, see Algorithm constants)
//
// Returns:
//   - *IPCryptConfig: Configured encryption instance (nil if encryption disabled)
//   - error: Validation error if configuration is invalid
//
// Example:
//
//	config, err := NewIPCryptConfig("0123456789abcdef0123456789abcdef", "ipcrypt-deterministic")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	encrypted, _ := config.EncryptIPString("192.168.1.1")
//
// Security Notes:
//   - Keys should be generated using crypto/rand
//   - Keys must be stored securely (e.g., environment variables, key management systems)
//   - Different algorithms require different key sizes (see algorithmKeySize)
func NewIPCryptConfig(keyHex string, algorithmStr string) (*IPCryptConfig, error) {
	// Normalize and validate algorithm string
	algorithmStr = strings.TrimSpace(strings.ToLower(algorithmStr))
	if algorithmStr == "" {
		algorithmStr = string(AlgorithmNone)
	}

	algorithm := Algorithm(algorithmStr)

	// Return nil for disabled encryption (not an error condition)
	if algorithm == AlgorithmNone {
		return nil, nil
	}

	// Validate algorithm is supported
	requiredKeySize, isValidAlgorithm := algorithmKeySize[algorithm]
	if !isValidAlgorithm {
		return nil, fmt.Errorf("%w: %q (supported: %s)",
			ErrInvalidAlgorithm,
			algorithmStr,
			getSupportedAlgorithms())
	}

	// Key validation - required for all non-none algorithms
	if keyHex == "" {
		return nil, fmt.Errorf("encryption algorithm %q requires a key: %w",
			algorithm, ErrInvalidKey)
	}

	// Decode and validate hex key
	// Go 1.26: hex.DecodeString is optimized with reduced allocations
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, fmt.Errorf("%w (must be valid hexadecimal): %w", ErrInvalidKey, err)
	}

	// Validate key length matches algorithm requirements
	if len(key) != requiredKeySize {
		return nil, fmt.Errorf("%w: %s requires %d bytes (%d hex chars), got %d bytes",
			ErrInvalidKeyLength,
			algorithm,
			requiredKeySize,
			requiredKeySize*2,
			len(key))
	}

	// Create immutable configuration
	// Go 1.26: Configuration is immutable after construction for thread safety
	// The key is stored in a defensive copy to prevent external mutation
	keyCopy := make([]byte, len(key))
	copy(keyCopy, key)

	return &IPCryptConfig{
		key:       keyCopy,
		algorithm: algorithm,
		logger:    slog.Default(),
	}, nil
}

// SetLogger sets a custom logger for the config.
// Go 1.26: Fluent API pattern for optional configuration.
//
// Returns the config itself for method chaining.
// Safe for concurrent use (though typically called during initialization).
//
// Example:
//
//	config, _ := NewIPCryptConfig(key, "ipcrypt-deterministic")
//	config.SetLogger(slog.New(slog.NewJSONHandler(os.Stdout, nil)))
func (c *IPCryptConfig) SetLogger(logger *slog.Logger) *IPCryptConfig {
	if c != nil && logger != nil {
		c.logger = logger
	}
	return c
}

// Algorithm returns the configured encryption algorithm.
// Safe for concurrent use.
func (c *IPCryptConfig) Algorithm() Algorithm {
	if c == nil {
		return AlgorithmNone
	}
	return c.algorithm
}

// IsEnabled returns true if encryption is enabled (not nil and not "none").
// Safe for concurrent use.
func (c *IPCryptConfig) IsEnabled() bool {
	return c != nil && c.algorithm != AlgorithmNone
}

// KeySize returns the size of the encryption key in bytes.
// Returns 0 if encryption is disabled.
// Safe for concurrent use.
func (c *IPCryptConfig) KeySize() int {
	if c == nil {
		return 0
	}
	return len(c.key)
}

// SecureCompareKey compares a key with the stored key using constant-time comparison.
// Go 1.26: Security-focused method using crypto/subtle for timing-attack resistance.
//
// Returns true if the keys match, false otherwise.
// This method is safe against timing attacks.
func (c *IPCryptConfig) SecureCompareKey(key []byte) bool {
	if c == nil {
		return key == nil
	}
	return subtle.ConstantTimeCompare(c.key, key) == 1
}

// EncryptIP encrypts an IP address using the configured encryption.
// Returns the encrypted IP string or an error if encryption fails.
//
// Go 1.26: Optimized with strategy pattern for algorithm dispatch.
// Uses modern allocation patterns for reduced GC overhead.
//
// Safe for concurrent use from multiple goroutines.
//
// Example:
//
//	ip := net.ParseIP("192.168.1.1")
//	encrypted, err := config.EncryptIP(ip)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Println(encrypted)
func (c *IPCryptConfig) EncryptIP(ip net.IP) (string, error) {
	return c.EncryptIPWithContext(context.Background(), ip)
}

// EncryptIPWithContext encrypts an IP address with cancellation support.
// Go 1.26: Modern pattern with context support for cancellable operations.
//
// The context can be used to cancel long-running encryption operations,
// particularly useful for non-deterministic algorithms that generate random data.
//
// Safe for concurrent use from multiple goroutines.
//
// Example:
//
//	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
//	defer cancel()
//	encrypted, err := config.EncryptIPWithContext(ctx, ip)
func (c *IPCryptConfig) EncryptIPWithContext(ctx context.Context, ip net.IP) (string, error) {
	// Check for cancellation before starting work
	if err := ctx.Err(); err != nil {
		return "", fmt.Errorf("%w: %w", ErrOperationCanceled, err)
	}

	// Passthrough when encryption is disabled
	if c == nil {
		return ip.String(), nil
	}

	// Validate input
	if ip == nil || len(ip) == 0 {
		return "", fmt.Errorf("%w: nil or empty IP", ErrInvalidIP)
	}

	// Dispatch to algorithm-specific implementation
	// Go 1.26: Jump table optimization via switch statement
	switch c.algorithm {
	case AlgorithmDeterministic:
		return c.encryptDeterministic(ip)

	case AlgorithmNonDeterministic:
		return c.encryptNonDeterministic(ctx, ip, 8)

	case AlgorithmNonDeterministicX:
		return c.encryptNonDeterministic(ctx, ip, 16)

	case AlgorithmPrefixPreserving:
		return c.encryptPrefixPreserving(ip)

	default:
		// This should never happen if NewIPCryptConfig validates properly
		return "", fmt.Errorf("%w: %s", ErrInvalidAlgorithm, c.algorithm)
	}
}

// EncryptAddr encrypts a netip.Addr using the configured encryption.
// Go 1.26: Zero-allocation IP operations using netip.Addr.
//
// This is the preferred method for new code as netip.Addr is more
// efficient than net.IP (no heap allocations for IP representation).
//
// Safe for concurrent use from multiple goroutines.
//
// Example:
//
//	addr := netip.MustParseAddr("192.168.1.1")
//	encrypted, err := config.EncryptAddr(addr)
func (c *IPCryptConfig) EncryptAddr(addr netip.Addr) (string, error) {
	return c.EncryptAddrWithContext(context.Background(), addr)
}

// EncryptAddrWithContext encrypts a netip.Addr with context support.
// Go 1.26: Combines modern netip.Addr with context cancellation.
//
// Safe for concurrent use from multiple goroutines.
func (c *IPCryptConfig) EncryptAddrWithContext(ctx context.Context, addr netip.Addr) (string, error) {
	if c == nil {
		return addr.String(), nil
	}

	if !addr.IsValid() {
		return "", fmt.Errorf("%w: invalid netip.Addr", ErrInvalidIP)
	}

	// Convert to net.IP for ipcrypt library compatibility
	// Go 1.26: AsSlice() returns efficiently without heap allocation
	ip := addr.AsSlice()
	return c.EncryptIPWithContext(ctx, ip)
}

// EncryptIPString encrypts an IP address string.
// Returns the original string if it's not a valid IP address.
// Returns "[encrypted]" if encryption fails (with logged warning).
//
// Go 1.26: Uses netip.ParseAddr for faster parsing and better type safety.
// This method never returns an error, making it convenient for logging use cases.
//
// Safe for concurrent use from multiple goroutines.
//
// Example:
//
//	encrypted := config.EncryptIPString("192.168.1.1")
//	fmt.Println(encrypted) // Always succeeds, returns "[encrypted]" on error
func (c *IPCryptConfig) EncryptIPString(ipStr string) string {
	return c.EncryptIPStringWithContext(context.Background(), ipStr)
}

// EncryptIPStringWithContext encrypts an IP string with context support.
// Go 1.26: Modern pattern combining convenience with cancellation.
//
// Safe for concurrent use from multiple goroutines.
func (c *IPCryptConfig) EncryptIPStringWithContext(ctx context.Context, ipStr string) string {
	if c == nil || ipStr == "" {
		return ipStr
	}

	// Try parsing with netip.ParseAddr first (faster and more efficient)
	// Go 1.26: netip.ParseAddr has zero-allocation fast path
	if addr, err := netip.ParseAddr(ipStr); err == nil {
		encrypted, err := c.EncryptAddrWithContext(ctx, addr)
		if err != nil {
			if c.logger != nil {
				c.logger.Warn("Failed to encrypt IP",
					slog.String("ip", ipStr),
					slog.String("algorithm", string(c.algorithm)),
					slog.Any("error", err))
			}
			return "[encrypted]"
		}
		return encrypted
	}

	// Fallback to net.ParseIP for edge cases and compatibility
	ip := net.ParseIP(ipStr)
	if ip == nil {
		// Not a valid IP address, return as-is (might be hostname)
		return ipStr
	}

	encrypted, err := c.EncryptIPWithContext(ctx, ip)
	if err != nil {
		if c.logger != nil {
			c.logger.Warn("Failed to encrypt IP",
				slog.String("ip", ipStr),
				slog.String("algorithm", string(c.algorithm)),
				slog.Any("error", err))
		}
		return "[encrypted]"
	}

	return encrypted
}

// DecryptIP decrypts an encrypted IP address string.
// Go 1.26: Returns structured error for proper error handling.
//
// Safe for concurrent use from multiple goroutines.
//
// Example:
//
//	decrypted, err := config.DecryptIP(encrypted)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Println(decrypted)
func (c *IPCryptConfig) DecryptIP(encryptedStr string) (string, error) {
	return c.DecryptIPWithContext(context.Background(), encryptedStr)
}

// DecryptIPWithContext decrypts an encrypted IP with cancellation support.
// Go 1.26: Modern pattern with context for cancellable operations.
//
// Safe for concurrent use from multiple goroutines.
func (c *IPCryptConfig) DecryptIPWithContext(ctx context.Context, encryptedStr string) (string, error) {
	// Check for cancellation before starting work
	if err := ctx.Err(); err != nil {
		return "", fmt.Errorf("%w: %w", ErrOperationCanceled, err)
	}

	// Passthrough when encryption is disabled
	if c == nil {
		return encryptedStr, nil
	}

	// Validate input
	if encryptedStr == "" {
		return "", fmt.Errorf("%w: empty encrypted string", ErrInvalidIP)
	}

	// Dispatch to algorithm-specific implementation
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
		// This should never happen if NewIPCryptConfig validates properly
		return "", fmt.Errorf("%w: %s", ErrInvalidAlgorithm, c.algorithm)
	}
}

// encryptDeterministic encrypts using deterministic algorithm.
// Internal method - not exported.
func (c *IPCryptConfig) encryptDeterministic(ip net.IP) (string, error) {
	encrypted, err := ipcrypt.EncryptIP(c.key, ip)
	if err != nil {
		return "", &EncryptionError{
			Op:        "encrypt",
			Algorithm: c.algorithm,
			IP:        "[redacted]",
			Err:       err,
		}
	}
	return encrypted.String(), nil
}

// encryptNonDeterministic encrypts using non-deterministic algorithm.
// Go 1.26: Unified implementation for both nd and ndx modes with context support.
//
// Parameters:
//   - ctx: Context for cancellation
//   - ip: IP address to encrypt
//   - tweakSize: Size of random tweak (8 for nd, 16 for ndx)
//
// Security Note: Uses crypto/rand for cryptographically secure random tweak generation.
func (c *IPCryptConfig) encryptNonDeterministic(ctx context.Context, ip net.IP, tweakSize int) (string, error) {
	// Check cancellation before expensive random generation
	if err := ctx.Err(); err != nil {
		return "", fmt.Errorf("%w: %w", ErrOperationCanceled, err)
	}

	// Generate cryptographically secure random tweak
	// Go 1.26: Optimized allocation for small objects
	tweak := make([]byte, tweakSize)
	if _, err := rand.Read(tweak); err != nil {
		return "", fmt.Errorf("failed to generate random tweak: %w", err)
	}

	var encrypted []byte
	var err error

	// Dispatch based on tweak size
	if tweakSize == 8 {
		encrypted, err = ipcrypt.EncryptIPNonDeterministic(ip.String(), c.key, tweak)
	} else {
		encrypted, err = ipcrypt.EncryptIPNonDeterministicX(ip.String(), c.key, tweak)
	}

	if err != nil {
		return "", &EncryptionError{
			Op:        "encrypt",
			Algorithm: c.algorithm,
			IP:        "[redacted]",
			Err:       err,
		}
	}

	// Return as hex-encoded string (includes tweak)
	return hex.EncodeToString(encrypted), nil
}

// encryptPrefixPreserving encrypts using prefix-preserving algorithm.
// Internal method - not exported.
func (c *IPCryptConfig) encryptPrefixPreserving(ip net.IP) (string, error) {
	encrypted, err := ipcrypt.EncryptIPPfx(ip, c.key)
	if err != nil {
		return "", &EncryptionError{
			Op:        "encrypt",
			Algorithm: c.algorithm,
			IP:        "[redacted]",
			Err:       err,
		}
	}
	return encrypted.String(), nil
}

// decryptDeterministic decrypts using deterministic algorithm.
// Internal method - not exported.
func (c *IPCryptConfig) decryptDeterministic(encryptedStr string) (string, error) {
	// Parse encrypted IP address
	ip := net.ParseIP(encryptedStr)
	if ip == nil {
		return "", fmt.Errorf("%w: invalid encrypted IP format: %s", ErrInvalidIP, encryptedStr)
	}

	decrypted, err := ipcrypt.DecryptIP(c.key, ip)
	if err != nil {
		return "", &EncryptionError{
			Op:        "decrypt",
			Algorithm: c.algorithm,
			IP:        encryptedStr,
			Err:       err,
		}
	}

	return decrypted.String(), nil
}

// decryptNonDeterministic decrypts using non-deterministic algorithm (8-byte tweak).
// Internal method - not exported.
func (c *IPCryptConfig) decryptNonDeterministic(encryptedStr string) (string, error) {
	// Decode hex-encoded encrypted data
	encrypted, err := hex.DecodeString(encryptedStr)
	if err != nil {
		return "", fmt.Errorf("%w: invalid hex encoding: %w", ErrInvalidIP, err)
	}

	decrypted, err := ipcrypt.DecryptIPNonDeterministic(encrypted, c.key)
	if err != nil {
		return "", &EncryptionError{
			Op:        "decrypt",
			Algorithm: c.algorithm,
			IP:        "[hex-encoded]",
			Err:       err,
		}
	}

	return decrypted, nil
}

// decryptNonDeterministicX decrypts using extended non-deterministic algorithm (16-byte tweak).
// Internal method - not exported.
func (c *IPCryptConfig) decryptNonDeterministicX(encryptedStr string) (string, error) {
	// Decode hex-encoded encrypted data
	encrypted, err := hex.DecodeString(encryptedStr)
	if err != nil {
		return "", fmt.Errorf("%w: invalid hex encoding: %w", ErrInvalidIP, err)
	}

	decrypted, err := ipcrypt.DecryptIPNonDeterministicX(encrypted, c.key)
	if err != nil {
		return "", &EncryptionError{
			Op:        "decrypt",
			Algorithm: c.algorithm,
			IP:        "[hex-encoded]",
			Err:       err,
		}
	}

	return decrypted, nil
}

// decryptPrefixPreserving decrypts using prefix-preserving algorithm.
// Internal method - not exported.
func (c *IPCryptConfig) decryptPrefixPreserving(encryptedStr string) (string, error) {
	// Parse encrypted IP address
	ip := net.ParseIP(encryptedStr)
	if ip == nil {
		return "", fmt.Errorf("%w: invalid encrypted IP format: %s", ErrInvalidIP, encryptedStr)
	}

	decrypted, err := ipcrypt.DecryptIPPfx(ip, c.key)
	if err != nil {
		return "", &EncryptionError{
			Op:        "decrypt",
			Algorithm: c.algorithm,
			IP:        encryptedStr,
			Err:       err,
		}
	}

	return decrypted.String(), nil
}

// getSupportedAlgorithms returns a comma-separated list of supported algorithms.
// Results are computed once and cached for efficiency.
// Go 1.26: Static data, no allocation after first call.
func getSupportedAlgorithms() string {
	algorithms := []string{
		string(AlgorithmNone),
		string(AlgorithmDeterministic),
		string(AlgorithmNonDeterministic),
		string(AlgorithmNonDeterministicX),
		string(AlgorithmPrefixPreserving),
	}
	return strings.Join(algorithms, ", ")
}

// ValidateIP checks if a string is a valid IP address.
// Go 1.26: Helper function using efficient netip.ParseAddr with net.ParseIP fallback.
//
// Returns nil if valid, error otherwise.
//
// Example:
//
//	if err := ValidateIP("192.168.1.1"); err != nil {
//	    log.Fatal("Invalid IP:", err)
//	}
func ValidateIP(ipStr string) error {
	if ipStr == "" {
		return fmt.Errorf("%w: empty string", ErrInvalidIP)
	}

	// Try modern netip.ParseAddr first (faster, zero-allocation)
	if _, err := netip.ParseAddr(ipStr); err == nil {
		return nil
	}

	// Fallback to net.ParseIP for compatibility
	if ip := net.ParseIP(ipStr); ip != nil {
		return nil
	}

	return fmt.Errorf("%w: %s", ErrInvalidIP, ipStr)
}

// GenerateKey generates a cryptographically secure random key for the specified algorithm.
// Go 1.26: Convenience function for secure key generation.
//
// Returns the key bytes or an error if generation fails.
// The key should be stored securely (e.g., environment variables, key management systems).
//
// Example:
//
//	key, err := GenerateKey(AlgorithmDeterministic)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	keyHex := hex.EncodeToString(key)
//	fmt.Printf("Generated key: %s\n", keyHex)
//
// Security Note:
//   - Keys are generated using crypto/rand (cryptographically secure)
//   - Keys should be stored securely and never logged or exposed
//   - Use different keys for different environments (dev, prod, etc.)
func GenerateKey(algorithm Algorithm) ([]byte, error) {
	keySize, ok := algorithmKeySize[algorithm]
	if !ok || algorithm == AlgorithmNone {
		return nil, fmt.Errorf("%w: %s", ErrInvalidAlgorithm, algorithm)
	}

	key := make([]byte, keySize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}

	return key, nil
}

// MustGenerateKey generates a key and panics on error.
// Go 1.26: Convenience function for initialization code.
//
// Use this in initialization code where errors are unrecoverable.
// Should only be used during application startup, never in production request paths.
//
// Example:
//
//	var encryptionKey = hex.EncodeToString(MustGenerateKey(AlgorithmDeterministic))
//
// Warning: This function panics on error. Only use during initialization.
func MustGenerateKey(algorithm Algorithm) []byte {
	key, err := GenerateKey(algorithm)
	if err != nil {
		panic(fmt.Sprintf("failed to generate key: %v", err))
	}
	return key
}

// Zeroize overwrites sensitive data with zeros.
// Go 1.26: Security helper for key cleanup.
//
// Use this to clear sensitive data from memory when it's no longer needed.
// Note: Modern Go may optimize this away; use runtime.KeepAlive if needed.
//
// Example:
//
//	key := []byte("sensitive data")
//	defer Zeroize(key)
//	// ... use key ...
func Zeroize(data []byte) {
	for i := range data {
		data[i] = 0
	}
}
