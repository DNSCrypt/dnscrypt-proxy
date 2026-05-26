package main

import (
	"net"
	"testing"
)

func TestExtractClientIPStr(t *testing.T) {
	tests := []struct {
		name         string
		pluginsState *PluginsState
		wantIP       string
		wantOK       bool
	}{
		{
			name: "nil clientAddr should return empty",
			pluginsState: &PluginsState{
				clientProto: "tcp",
				clientAddr:  nil,
			},
			wantIP: "",
			wantOK: false,
		},
		{
			name: "valid UDP address",
			pluginsState: &PluginsState{
				clientProto: "udp",
				clientAddr: func() *net.Addr {
					addr := net.Addr(
						&net.UDPAddr{
							IP:   net.ParseIP("192.168.1.1"),
							Port: 53,
						},
					)
					return &addr
				}(),
			},
			wantIP: "192.168.1.1",
			wantOK: true,
		},
		{
			name: "valid TCP address",
			pluginsState: &PluginsState{
				clientProto: "tcp",
				clientAddr: func() *net.Addr {
					addr := net.Addr(
						&net.TCPAddr{
							IP:   net.ParseIP("10.0.0.1"),
							Port: 53,
						},
					)
					return &addr
				}(),
			},
			wantIP: "10.0.0.1",
			wantOK: true,
		},
		{
			name:         "nil pluginsState should return empty",
			pluginsState: nil,
			wantIP:       "",
			wantOK:       false,
		},
		{
			name: "valid local_doh address",
			pluginsState: &PluginsState{
				clientProto: "local_doh",
				clientAddr: func() *net.Addr {
					addr := net.Addr(
						&net.TCPAddr{
							IP:   net.ParseIP("127.0.0.1"),
							Port: 443,
						},
					)
					return &addr
				}(),
			},
			wantIP: "127.0.0.1",
			wantOK: true,
		},
		{
			name: "valid IPv6 UDP address",
			pluginsState: &PluginsState{
				clientProto: "udp",
				clientAddr: func() *net.Addr {
					addr := net.Addr(
						&net.UDPAddr{
							IP:   net.ParseIP("::1"),
							Port: 53,
						},
					)
					return &addr
				}(),
			},
			wantIP: "::1",
			wantOK: true,
		},
		{
			name: "valid IPv6 TCP address",
			pluginsState: &PluginsState{
				clientProto: "tcp",
				clientAddr: func() *net.Addr {
					addr := net.Addr(
						&net.TCPAddr{
							IP:   net.ParseIP("2001:db8::1"),
							Port: 53,
						},
					)
					return &addr
				}(),
			},
			wantIP: "2001:db8::1",
			wantOK: true,
		},
		{
			name: "UDP protocol with TCPAddr type mismatch",
			pluginsState: &PluginsState{
				clientProto: "udp",
				clientAddr: func() *net.Addr {
					addr := net.Addr(
						&net.TCPAddr{
							IP:   net.ParseIP("10.0.0.1"),
							Port: 53,
						},
					)
					return &addr
				}(),
			},
			wantIP: "",
			wantOK: false,
		},
		{
			name: "TCP protocol with UDPAddr type mismatch",
			pluginsState: &PluginsState{
				clientProto: "tcp",
				clientAddr: func() *net.Addr {
					addr := net.Addr(
						&net.UDPAddr{
							IP:   net.ParseIP("10.0.0.1"),
							Port: 53,
						},
					)
					return &addr
				}(),
			},
			wantIP: "",
			wantOK: false,
		},
		{
			name: "unknown protocol",
			pluginsState: &PluginsState{
				clientProto: "unknown",
				clientAddr: func() *net.Addr {
					addr := net.Addr(
						&net.TCPAddr{
							IP:   net.ParseIP("10.0.0.1"),
							Port: 53,
						},
					)
					return &addr
				}(),
			},
			wantIP: "",
			wantOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotIP, gotOK := ExtractClientIPStr(tt.pluginsState)
			if gotIP != tt.wantIP {
				t.Errorf("ExtractClientIPStr() IP = %v, want %v", gotIP, tt.wantIP)
			}
			if gotOK != tt.wantOK {
				t.Errorf("ExtractClientIPStr() OK = %v, want %v", gotOK, tt.wantOK)
			}
		})
	}
}
