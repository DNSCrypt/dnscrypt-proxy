package main

import (
	"net"
	"testing"
)

func TestNewIPCryptConfig(t *testing.T) {
	tests := []struct {
		name      string
		keyHex    string
		algorithm string
		wantErr   bool
	}{
		{
			name:      "none algorithm config",
			keyHex:    "",
			algorithm: "none",
			wantErr:   false,
		},
		{
			name:      "valid ipcrypt-deterministic config",
			keyHex:    "1234567890abcdef1234567890abcdef",
			algorithm: "ipcrypt-deterministic",
			wantErr:   false,
		},
		{
			name:      "valid ipcrypt-nd config",
			keyHex:    "1234567890abcdef1234567890abcdef",
			algorithm: "ipcrypt-nd",
			wantErr:   false,
		},
		{
			name:      "valid ipcrypt-ndx config",
			keyHex:    "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
			algorithm: "ipcrypt-ndx",
			wantErr:   false,
		},
		{
			name:      "empty algorithm defaults to none",
			keyHex:    "",
			algorithm: "",
			wantErr:   false,
		},
		{
			name:      "algorithm without key",
			keyHex:    "",
			algorithm: "ipcrypt-deterministic",
			wantErr:   true,
		},
		{
			name:      "invalid hex key",
			keyHex:    "invalid-hex",
			algorithm: "ipcrypt-deterministic",
			wantErr:   true,
		},
		{
			name:      "wrong key length",
			keyHex:    "1234567890abcdef",
			algorithm: "ipcrypt-deterministic",
			wantErr:   true,
		},
		{
			name:      "unsupported algorithm",
			keyHex:    "1234567890abcdef1234567890abcdef",
			algorithm: "unknown",
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config, err := NewIPCryptConfig(tt.keyHex, tt.algorithm)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error but got nil")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				// For "none" algorithm, config should be nil
				if tt.algorithm == "none" || tt.algorithm == "" {
					if config != nil {
						t.Errorf("expected nil config for algorithm='%s', got %+v", tt.algorithm, config)
					}
				} else {
					if config == nil {
						t.Errorf("expected config but got nil")
					} else if config.Algorithm != tt.algorithm {
						t.Errorf("expected algorithm=%v, got %v", tt.algorithm, config.Algorithm)
					}
				}
			}
		})
	}
}

func TestIPCryptConfig_EncryptIP(t *testing.T) {
	// Create a valid config
	config, err := NewIPCryptConfig("1234567890abcdef1234567890abcdef", "ipcrypt-deterministic")
	if err != nil {
		t.Fatalf("failed to create config: %v", err)
	}

	tests := []struct {
		name    string
		ip      string
		wantErr bool
	}{
		{
			name:    "IPv4 address",
			ip:      "192.168.1.1",
			wantErr: false,
		},
		{
			name:    "IPv4 localhost",
			ip:      "127.0.0.1",
			wantErr: false,
		},
		{
			name:    "IPv4 public",
			ip:      "8.8.8.8",
			wantErr: false,
		},
		{
			name:    "IPv6 address",
			ip:      "2001:db8::1",
			wantErr: false, // Currently returns original for IPv6
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("failed to parse IP: %s", tt.ip)
			}

			encrypted, err := config.EncryptIP(ip)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error but got nil")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if encrypted == "" {
					t.Errorf("expected encrypted IP but got empty string")
				}

				// For IPv4, verify it's different from original
				if ip.To4() != nil && encrypted == tt.ip {
					t.Errorf("IPv4 encryption should change the IP, got same: %s", encrypted)
				}
			}
		})
	}
}

func TestIPCryptConfig_EncryptDecryptRoundTrip(t *testing.T) {
	config, err := NewIPCryptConfig("1234567890abcdef1234567890abcdef", "ipcrypt-deterministic")
	if err != nil {
		t.Fatalf("failed to create config: %v", err)
	}

	testIPs := []string{
		"192.168.1.1",
		"10.0.0.1",
		"172.16.0.1",
		"8.8.8.8",
		"1.1.1.1",
	}

	for _, ipStr := range testIPs {
		t.Run(ipStr, func(t *testing.T) {
			// Encrypt
			encrypted := config.EncryptIPString(ipStr)
			if encrypted == ipStr {
				t.Errorf("expected encrypted IP to be different from original")
			}

			// Decrypt
			decrypted, err := config.DecryptIP(encrypted)
			if err != nil {
				t.Errorf("failed to decrypt: %v", err)
			}

			// Verify round-trip
			if decrypted != ipStr {
				t.Errorf("round-trip failed: original=%s, encrypted=%s, decrypted=%s",
					ipStr, encrypted, decrypted)
			}
		})
	}
}

func TestIPCryptConfig_DisabledConfig(t *testing.T) {
	// Create a disabled config (none algorithm)
	config, err := NewIPCryptConfig("", "none")
	if err != nil {
		t.Fatalf("failed to create disabled config: %v", err)
	}

	testIP := "192.168.1.1"

	// Encryption should return original when disabled
	encrypted := config.EncryptIPString(testIP)
	if encrypted != testIP {
		t.Errorf("disabled config should return original IP, got %s", encrypted)
	}

	// Decryption should return original when disabled
	decrypted, err := config.DecryptIP(testIP)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if decrypted != testIP {
		t.Errorf("disabled config should return original IP, got %s", decrypted)
	}
}

func TestExtractClientIPStrEncrypted(t *testing.T) {
	// Create test configs
	enabledConfig, _ := NewIPCryptConfig("1234567890abcdef1234567890abcdef", "ipcrypt-deterministic")
	disabledConfig, _ := NewIPCryptConfig("", "none")

	// Create test addresses
	testIP := "192.168.1.100"
	udpAddr, _ := net.ResolveUDPAddr("udp", testIP+":53")
	tcpAddr, _ := net.ResolveTCPAddr("tcp", testIP+":53")

	tests := []struct {
		name          string
		pluginsState  *PluginsState
		ipCryptConfig *IPCryptConfig
		wantOriginal  bool
	}{
		{
			name: "UDP with encryption",
			pluginsState: &PluginsState{
				clientProto: "udp",
				clientAddr:  func() *net.Addr { var addr net.Addr = udpAddr; return &addr }(),
			},
			ipCryptConfig: enabledConfig,
			wantOriginal:  false,
		},
		{
			name: "TCP with encryption",
			pluginsState: &PluginsState{
				clientProto: "tcp",
				clientAddr:  func() *net.Addr { var addr net.Addr = tcpAddr; return &addr }(),
			},
			ipCryptConfig: enabledConfig,
			wantOriginal:  false,
		},
		{
			name: "UDP without encryption",
			pluginsState: &PluginsState{
				clientProto: "udp",
				clientAddr:  func() *net.Addr { var addr net.Addr = udpAddr; return &addr }(),
			},
			ipCryptConfig: disabledConfig,
			wantOriginal:  true,
		},
		{
			name: "UDP with nil config",
			pluginsState: &PluginsState{
				clientProto: "udp",
				clientAddr:  func() *net.Addr { var addr net.Addr = udpAddr; return &addr }(),
			},
			ipCryptConfig: nil,
			wantOriginal:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, ok := ExtractClientIPStrEncrypted(tt.pluginsState, tt.ipCryptConfig)
			if !ok {
				t.Errorf("expected ok=true, got false")
			}

			if tt.wantOriginal {
				if result != testIP {
					t.Errorf("expected original IP %s, got %s", testIP, result)
				}
			} else {
				if result == testIP {
					t.Errorf("expected encrypted IP, got original %s", result)
				}
			}
		})
	}
}
