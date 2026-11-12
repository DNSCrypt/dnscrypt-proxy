package main

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestWebSocketOriginBehindProxy checks the origin of WebSocket handshakes
// against the scheme reported by a reverse proxy, which can be ws or wss.
func TestWebSocketOriginBehindProxy(t *testing.T) {
	ui := NewMonitoringUI(&Proxy{})
	if ui == nil {
		t.Fatal("Failed to create monitoring UI")
	}
	for _, tt := range []struct {
		name      string
		forwarded string
		tls       bool
		origin    string
		want      bool
	}{
		{"direct http", "", false, "http://ui.example", true},
		{"direct https", "", true, "https://ui.example", true},
		{"direct https, http origin", "", true, "http://ui.example", false},
		{"https proxy", "https", false, "https://ui.example", true},
		{"https proxy, http origin", "https", false, "http://ui.example", false},
		{"wss proxy", "wss", false, "https://ui.example", true},
		{"wss proxy, uppercase", "WSS", false, "https://ui.example", true},
		{"wss proxy chain", "wss, ws", false, "https://ui.example", true},
		{"wss proxy, http origin", "wss", false, "http://ui.example", false},
		{"wss proxy, other host", "wss", false, "https://other.example", false},
		{"ws proxy", "ws", false, "http://ui.example", true},
		{"ws proxy to a TLS listener", "ws", true, "http://ui.example", true},
		{"ws proxy, https origin", "ws", true, "https://ui.example", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "http://ui.example/api/ws", nil)
			r.Header.Set("Origin", tt.origin)
			if tt.forwarded != "" {
				r.Header.Set("X-Forwarded-Proto", tt.forwarded)
			}
			if tt.tls {
				r.TLS = &tls.ConnectionState{}
			}
			if got := ui.upgrader.CheckOrigin(r); got != tt.want {
				t.Errorf("origin %q with X-Forwarded-Proto %q accepted: %v, want %v", tt.origin, tt.forwarded, got, tt.want)
			}
		})
	}
}
