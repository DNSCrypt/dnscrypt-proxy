package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"strings"

	"github.com/jedisct1/dlog"
	ipcrypt "github.com/jedisct1/go-ipcrypt"
)

// IPCryptConfig holds the configuration for IP address encryption
type IPCryptConfig struct {
	Key       []byte
	Algorithm string
	Tweak     []byte // For non-deterministic modes
}

// NewIPCryptConfig creates a new IPCryptConfig from configuration values
// Returns nil when encryption is disabled (algorithm is "none" or empty)
func NewIPCryptConfig(keyHex string, algorithm string) (*IPCryptConfig, error) {
	// Default to "none" if empty
	if algorithm == "" {
		algorithm = "none"
	}

	// Return nil for "none" algorithm - encryption disabled
	if algorithm == "none" {
		return nil, nil
	}

	if keyHex == "" {
		return nil, fmt.Errorf("IP encryption algorithm is set to %s but no key provided", algorithm)
	}

	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid IP encryption key (must be hex): %w", err)
	}

	config := &IPCryptConfig{
		Key:       key,
		Algorithm: algorithm,
	}

	// Validate key length and prepare config based on algorithm
	switch strings.ToLower(algorithm) {
	case "ipcrypt-deterministic":
		// Deterministic IPCrypt uses 16-byte keys
		if len(key) != 16 {
			return nil, fmt.Errorf("ipcrypt-deterministic requires a 16-byte (32 hex chars) key, got %d bytes", len(key))
		}

	case "ipcrypt-nd":
		// Non-deterministic with 8-byte tweak
		if len(key) != 16 {
			return nil, fmt.Errorf("ipcrypt-nd requires a 16-byte (32 hex chars) key, got %d bytes", len(key))
		}
		config.Tweak = make([]byte, 8)

	case "ipcrypt-ndx":
		// Extended non-deterministic with 16-byte tweak  
		if len(key) != 32 {
			return nil, fmt.Errorf("ipcrypt-ndx requires a 32-byte (64 hex chars) key, got %d bytes", len(key))
		}
		config.Tweak = make([]byte, 16)

	default:
		return nil, fmt.Errorf("unsupported IP encryption algorithm: %s (must be 'ipcrypt-deterministic', 'ipcrypt-nd', 'ipcrypt-ndx', or 'none')", algorithm)
	}

	return config, nil
}

// EncryptIP encrypts an IP address using the configured encryption
func (config *IPCryptConfig) EncryptIP(ip net.IP) (string, error) {
	if config == nil {
		return ip.String(), nil
	}

	switch config.Algorithm {
	case "ipcrypt-deterministic":
		// Deterministic encryption
		encrypted, err := ipcrypt.EncryptIP(config.Key, ip)
		if err != nil {
			return "", fmt.Errorf("failed to encrypt IP: %w", err)
		}
		return encrypted.String(), nil

	case "ipcrypt-nd":
		// Non-deterministic: generate random tweak for this encryption
		if _, err := rand.Read(config.Tweak); err != nil {
			return "", fmt.Errorf("failed to generate random tweak: %w", err)
		}
		encrypted, err := ipcrypt.EncryptIPNonDeterministic(ip.String(), config.Key, config.Tweak)
		if err != nil {
			return "", fmt.Errorf("failed to encrypt IP (nd): %w", err)
		}
		// Return as hex string for non-deterministic modes since they return bytes
		return hex.EncodeToString(encrypted), nil

	case "ipcrypt-ndx":
		// Extended non-deterministic: generate random tweak
		if _, err := rand.Read(config.Tweak); err != nil {
			return "", fmt.Errorf("failed to generate random tweak: %w", err)
		}
		encrypted, err := ipcrypt.EncryptIPNonDeterministicX(ip.String(), config.Key, config.Tweak)
		if err != nil {
			return "", fmt.Errorf("failed to encrypt IP (ndx): %w", err)
		}
		// Return as hex string for non-deterministic modes
		return hex.EncodeToString(encrypted), nil

	default:
		return "", fmt.Errorf("unsupported algorithm: %s", config.Algorithm)
	}
}

// EncryptIPString encrypts an IP address string
func (config *IPCryptConfig) EncryptIPString(ipStr string) string {
	if config == nil || ipStr == "" {
		return ipStr
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		// If it's not a valid IP, return as-is
		return ipStr
	}

	encrypted, err := config.EncryptIP(ip)
	if err != nil {
		dlog.Warnf("Failed to encrypt IP %s: %v", ipStr, err)
		return ipStr
	}

	return encrypted
}

// DecryptIP decrypts an encrypted IP address
func (config *IPCryptConfig) DecryptIP(encryptedStr string) (string, error) {
	if config == nil {
		return encryptedStr, nil
	}

	switch config.Algorithm {
	case "ipcrypt-deterministic":
		// Parse as IP for deterministic mode
		ip := net.ParseIP(encryptedStr)
		if ip == nil {
			return "", fmt.Errorf("invalid encrypted IP address: %s", encryptedStr)
		}
		decrypted, err := ipcrypt.DecryptIP(config.Key, ip)
		if err != nil {
			return "", fmt.Errorf("failed to decrypt IP: %w", err)
		}
		return decrypted.String(), nil

	case "ipcrypt-nd":
		// Decode from hex for non-deterministic mode
		encrypted, err := hex.DecodeString(encryptedStr)
		if err != nil {
			return "", fmt.Errorf("failed to decode encrypted IP: %w", err)
		}
		decrypted, err := ipcrypt.DecryptIPNonDeterministic(encrypted, config.Key)
		if err != nil {
			return "", fmt.Errorf("failed to decrypt IP (nd): %w", err)
		}
		return decrypted, nil

	case "ipcrypt-ndx":
		// Decode from hex for extended non-deterministic mode
		encrypted, err := hex.DecodeString(encryptedStr)
		if err != nil {
			return "", fmt.Errorf("failed to decode encrypted IP: %w", err)
		}
		decrypted, err := ipcrypt.DecryptIPNonDeterministicX(encrypted, config.Key)
		if err != nil {
			return "", fmt.Errorf("failed to decrypt IP (ndx): %w", err)
		}
		return decrypted, nil

	default:
		return "", fmt.Errorf("unsupported algorithm: %s", config.Algorithm)
	}
}