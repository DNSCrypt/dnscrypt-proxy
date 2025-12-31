package main

import (
    "crypto/rand"
    "encoding/hex"
    "errors"
    "fmt"
    "net"
    "net/netip"
    "strings"

    "github.com/jedisct1/dlog"
    ipcrypt "github.com/jedisct1/go-ipcrypt"
)

// Common errors pre-allocated to avoid runtime allocation
var (
    ErrNoKey             = errors.New("IP encryption algorithm set but no key provided")
    ErrInvalidKeyHex     = errors.New("invalid IP encryption key (must be hex)")
    ErrInvalidIP         = errors.New("invalid IP address")
    ErrTweakGen          = errors.New("failed to generate random tweak")
    ErrUnsupportedAlgo   = errors.New("unsupported IP encryption algorithm")
    ErrEncryptionDisabled = errors.New("encryption disabled")
)

// IPCryptConfig holds the configuration for IP address encryption.
// Tweak is removed to ensure thread-safety.
type IPCryptConfig struct {
    Key       []byte
    Algorithm string
}

// NewIPCryptConfig creates a new IPCryptConfig.
func NewIPCryptConfig(keyHex string, algorithm string) (*IPCryptConfig, error) {
    if algorithm == "" {
        algorithm = "none"
    }
    if algorithm == "none" {
        return nil, nil
    }
    if keyHex == "" {
        return nil, ErrNoKey
    }

    key, err := hex.DecodeString(keyHex)
    if err != nil {
        return nil, fmt.Errorf("%w: %v", ErrInvalidKeyHex, err)
    }

    // Validate key length immediately
    algoLower := strings.ToLower(algorithm)
    switch algoLower {
    case "ipcrypt-deterministic", "ipcrypt-nd":
        if len(key) != 16 {
            return nil, fmt.Errorf("%s requires 16-byte key, got %d", algoLower, len(key))
        }
    case "ipcrypt-ndx", "ipcrypt-pfx":
        if len(key) != 32 {
            return nil, fmt.Errorf("%s requires 32-byte key, got %d", algoLower, len(key))
        }
    default:
        return nil, fmt.Errorf("%w: %s", ErrUnsupportedAlgo, algorithm)
    }

    return &IPCryptConfig{
        Key:       key,
        Algorithm: algoLower,
    }, nil
}

// EncryptIP encrypts a net.IP using the configured encryption.
// Note: Prefer EncryptIPString if you start with a string to avoid allocation.
func (config *IPCryptConfig) EncryptIP(ip net.IP) (string, error) {
    if config == nil {
        return ip.String(), nil
    }

    // Optimization: Convert net.IP to netip.Addr for faster handling if needed,
    // but legacy net.IP is required by the ipcrypt library for some calls.
    // We handle the modes explicitly.

    switch config.Algorithm {
    case "ipcrypt-deterministic":
        // Library takes net.IP
        encrypted, err := ipcrypt.EncryptIP(config.Key, ip)
        if err != nil {
            return "", err
        }
        return encrypted.String(), nil

    case "ipcrypt-nd":
        // Stack-allocate tweak (8 bytes)
        var tweak [8]byte
        if _, err := rand.Read(tweak[:]); err != nil {
            return "", ErrTweakGen
        }
        // Library takes string for ND mode
        encrypted, err := ipcrypt.EncryptIPNonDeterministic(ip.String(), config.Key, tweak[:])
        if err != nil {
            return "", err
        }
        return hex.EncodeToString(encrypted), nil

    case "ipcrypt-ndx":
        // Stack-allocate tweak (16 bytes)
        var tweak [16]byte
        if _, err := rand.Read(tweak[:]); err != nil {
            return "", ErrTweakGen
        }
        encrypted, err := ipcrypt.EncryptIPNonDeterministicX(ip.String(), config.Key, tweak[:])
        if err != nil {
            return "", err
        }
        return hex.EncodeToString(encrypted), nil

    case "ipcrypt-pfx":
        // Library takes net.IP
        encrypted, err := ipcrypt.EncryptIPPfx(ip, config.Key)
        if err != nil {
            return "", err
        }
        return encrypted.String(), nil

    default:
        return "", ErrUnsupportedAlgo
    }
}

// EncryptIPString encrypts an IP address string.
// Optimized to avoid parsing overhead for non-deterministic modes.
func (config *IPCryptConfig) EncryptIPString(ipStr string) string {
    if config == nil || ipStr == "" {
        return ipStr
    }

    switch config.Algorithm {
    // For ND modes, the library accepts strings directly.
    // We skip the ParseIP -> String() roundtrip.
    case "ipcrypt-nd":
        var tweak [8]byte
        if _, err := rand.Read(tweak[:]); err != nil {
            dlog.Warnf("Failed to generate tweak: %v", err)
            return ipStr
        }
        encrypted, err := ipcrypt.EncryptIPNonDeterministic(ipStr, config.Key, tweak[:])
        if err != nil {
            dlog.Warnf("Failed to encrypt IP %s: %v", ipStr, err)
            return ipStr
        }
        return hex.EncodeToString(encrypted)

    case "ipcrypt-ndx":
        var tweak [16]byte
        if _, err := rand.Read(tweak[:]); err != nil {
            dlog.Warnf("Failed to generate tweak: %v", err)
            return ipStr
        }
        encrypted, err := ipcrypt.EncryptIPNonDeterministicX(ipStr, config.Key, tweak[:])
        if err != nil {
            dlog.Warnf("Failed to encrypt IP %s: %v", ipStr, err)
            return ipStr
        }
        return hex.EncodeToString(encrypted)

    // For modes requiring net.IP, use netip for faster parsing
    case "ipcrypt-deterministic", "ipcrypt-pfx":
        addr, err := netip.ParseAddr(ipStr)
        if err != nil {
            // Fallback or return as is
            return ipStr
        }
        
        // Convert netip.Addr to net.IP (slice) as required by library
        // AsSlice() allocates, but it's unavoidable if library demands net.IP
        ipSlice := addr.AsSlice()
        // ipcrypt expects net.IP which is []byte
        
        if config.Algorithm == "ipcrypt-deterministic" {
            encrypted, err := ipcrypt.EncryptIP(config.Key, net.IP(ipSlice[:]))
            if err != nil {
                dlog.Warnf("Failed to encrypt IP: %v", err)
                return ipStr
            }
            return encrypted.String()
        } else {
            encrypted, err := ipcrypt.EncryptIPPfx(net.IP(ipSlice[:]), config.Key)
            if err != nil {
                dlog.Warnf("Failed to encrypt IP: %v", err)
                return ipStr
            }
            return encrypted.String()
        }

    default:
        return ipStr
    }
}

// DecryptIP decrypts an encrypted IP address string.
func (config *IPCryptConfig) DecryptIP(encryptedStr string) (string, error) {
    if config == nil {
        return encryptedStr, nil
    }

    switch config.Algorithm {
    case "ipcrypt-deterministic":
        // Use netip for faster parsing, then convert
        addr, err := netip.ParseAddr(encryptedStr)
        if err != nil {
            return "", fmt.Errorf("%w: %s", ErrInvalidIP, encryptedStr)
        }
        ipSlice := addr.AsSlice()
        decrypted, err := ipcrypt.DecryptIP(config.Key, net.IP(ipSlice[:]))
        if err != nil {
            return "", err
        }
        return decrypted.String(), nil

    case "ipcrypt-nd":
        // Decode hex directly
        encrypted, err := hex.DecodeString(encryptedStr)
        if err != nil {
            return "", err
        }
        decrypted, err := ipcrypt.DecryptIPNonDeterministic(encrypted, config.Key)
        if err != nil {
            return "", err
        }
        return decrypted, nil

    case "ipcrypt-ndx":
        encrypted, err := hex.DecodeString(encryptedStr)
        if err != nil {
            return "", err
        }
        decrypted, err := ipcrypt.DecryptIPNonDeterministicX(encrypted, config.Key)
        if err != nil {
            return "", err
        }
        return decrypted, nil

    case "ipcrypt-pfx":
        addr, err := netip.ParseAddr(encryptedStr)
        if err != nil {
            return "", fmt.Errorf("%w: %s", ErrInvalidIP, encryptedStr)
        }
        ipSlice := addr.AsSlice()
        decrypted, err := ipcrypt.DecryptIPPfx(net.IP(ipSlice[:]), config.Key)
        if err != nil {
            return "", err
        }
        return decrypted.String(), nil

    default:
        return "", ErrUnsupportedAlgo
    }
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

	case "ipcrypt-pfx":
		// Prefix-preserving encryption
		if len(key) != 32 {
			return nil, fmt.Errorf("ipcrypt-pfx requires a 32-byte (64 hex chars) key, got %d bytes", len(key))
		}

	default:
		return nil, fmt.Errorf("unsupported IP encryption algorithm: %s (must be 'ipcrypt-deterministic', 'ipcrypt-nd', 'ipcrypt-ndx', 'ipcrypt-pfx', or 'none')", algorithm)
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

	case "ipcrypt-pfx":
		// Prefix-preserving encryption
		encrypted, err := ipcrypt.EncryptIPPfx(ip, config.Key)
		if err != nil {
			return "", fmt.Errorf("failed to encrypt IP (pfx): %w", err)
		}
		return encrypted.String(), nil

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

	case "ipcrypt-pfx":
		// Decrypt prefix-preserving encrypted IP
		ip := net.ParseIP(encryptedStr)
		if ip == nil {
			return "", fmt.Errorf("invalid encrypted IP address: %s", encryptedStr)
		}
		decrypted, err := ipcrypt.DecryptIPPfx(ip, config.Key)
		if err != nil {
			return "", fmt.Errorf("failed to decrypt IP (pfx): %w", err)
		}
		return decrypted.String(), nil

	default:
		return "", fmt.Errorf("unsupported algorithm: %s", config.Algorithm)
	}
}
