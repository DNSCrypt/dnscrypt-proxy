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
    ErrNoKey              = errors.New("IP encryption algorithm set but no key provided")
    ErrInvalidKeyHex      = errors.New("invalid IP encryption key (must be hex)")
    ErrInvalidIP          = errors.New("invalid IP address")
    ErrTweakGen           = errors.New("failed to generate random tweak")
    ErrUnsupportedAlgo    = errors.New("unsupported IP encryption algorithm")
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
func (config *IPCryptConfig) EncryptIP(ip net.IP) (string, error) {
    if config == nil {
        return ip.String(), nil
    }

    switch config.Algorithm {
    case "ipcrypt-deterministic":
        encrypted, err := ipcrypt.EncryptIP(config.Key, ip)
        if err != nil {
            return "", err
        }
        return encrypted.String(), nil

    case "ipcrypt-nd":
        var tweak [8]byte
        if _, err := rand.Read(tweak[:]); err != nil {
            return "", ErrTweakGen
        }
        encrypted, err := ipcrypt.EncryptIPNonDeterministic(ip.String(), config.Key, tweak[:])
        if err != nil {
            return "", err
        }
        return hex.EncodeToString(encrypted), nil

    case "ipcrypt-ndx":
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

    case "ipcrypt-deterministic", "ipcrypt-pfx":
        addr, err := netip.ParseAddr(ipStr)
        if err != nil {
            return ipStr
        }

        // Convert netip.Addr to net.IP (slice) as required by library
        ip16 := addr.As16()
        ipSlice := ip16[:]
        
        // Handle IPv4 mapped in IPv6 if necessary, but As16 covers generic cases 
        // that the library should handle.

        if config.Algorithm == "ipcrypt-deterministic" {
            encrypted, err := ipcrypt.EncryptIP(config.Key, net.IP(ipSlice))
            if err != nil {
                dlog.Warnf("Failed to encrypt IP: %v", err)
                return ipStr
            }
            return encrypted.String()
        } else {
            encrypted, err := ipcrypt.EncryptIPPfx(net.IP(ipSlice), config.Key)
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
        addr, err := netip.ParseAddr(encryptedStr)
        if err != nil {
            return "", fmt.Errorf("%w: %s", ErrInvalidIP, encryptedStr)
        }
        ip16 := addr.As16()
        decrypted, err := ipcrypt.DecryptIP(config.Key, net.IP(ip16[:]))
        if err != nil {
            return "", err
        }
        return decrypted.String(), nil

    case "ipcrypt-nd":
        encrypted, err := hex.DecodeString(encryptedStr)
        if err != nil {
            return "", err
        }
        decrypted, err := ipcrypt.DecryptIPNonDeterministic(encrypted, config.Key)
        if err != nil {
            return "", err
        }
        // Assuming decrypted is string or converts to string cleanly
        return fmt.Sprintf("%s", decrypted), nil

    case "ipcrypt-ndx":
        encrypted, err := hex.DecodeString(encryptedStr)
        if err != nil {
            return "", err
        }
        decrypted, err := ipcrypt.DecryptIPNonDeterministicX(encrypted, config.Key)
        if err != nil {
            return "", err
        }
        return fmt.Sprintf("%s", decrypted), nil

    case "ipcrypt-pfx":
        addr, err := netip.ParseAddr(encryptedStr)
        if err != nil {
            return "", fmt.Errorf("%w: %s", ErrInvalidIP, encryptedStr)
        }
        ip16 := addr.As16()
        decrypted, err := ipcrypt.DecryptIPPfx(net.IP(ip16[:]), config.Key)
        if err != nil {
            return "", err
        }
        return decrypted.String(), nil

    default:
        return "", ErrUnsupportedAlgo
    }
}
