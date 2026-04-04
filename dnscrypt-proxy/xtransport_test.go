//go:build linux

package main

import (
	"context"
	"net/http"
	"net/netip"
	"net/url"
	"testing"
	"time"
)

// TestFormatDialTarget verifies that formatDialTarget produces the correct
// "host:port" and "[ipv6]:port" strings and that results are cached.
func TestFormatDialTarget(t *testing.T) {
	tests := []struct {
		name string
		ip   string
		port uint16
		want string
	}{
		{"IPv4", "192.168.1.1", 443, "192.168.1.1:443"},
		{"IPv4 port 80", "10.0.0.1", 80, "10.0.0.1:80"},
		{"IPv6", "2001:db8::1", 443, "[2001:db8::1]:443"},
		{"IPv6 loopback", "::1", 53, "[::1]:53"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr, err := netip.ParseAddr(tt.ip)
			if err != nil {
				t.Fatalf("ParseAddr(%q): %v", tt.ip, err)
			}
			got := formatDialTarget(addr, tt.port)
			if got != tt.want {
				t.Errorf("formatDialTarget(%q, %d) = %q, want %q", tt.ip, tt.port, got, tt.want)
			}
			// Second call must return identical string (cache hit).
			got2 := formatDialTarget(addr, tt.port)
			if got2 != tt.want {
				t.Errorf("cached formatDialTarget(%q, %d) = %q, want %q", tt.ip, tt.port, got2, tt.want)
			}
		})
	}
}

// TestParseIPAddr verifies that parseIPAddr correctly parses plain and
// bracketed IP strings, and returns the zero Addr for invalid input.
func TestParseIPAddr(t *testing.T) {
	tests := []struct {
		input string
		valid bool
		want  string
	}{
		{"1.2.3.4", true, "1.2.3.4"},
		{"[1.2.3.4]", true, "1.2.3.4"},
		{"::1", true, "::1"},
		{"[::1]", true, "::1"},
		{"::ffff:192.168.1.1", true, "192.168.1.1"}, // Unmap strips IPv4-in-IPv6
		{"not-an-ip", false, ""},
		{"", false, ""},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := parseIPAddr(tt.input)
			if got.IsValid() != tt.valid {
				t.Errorf("parseIPAddr(%q).IsValid() = %v, want %v", tt.input, got.IsValid(), tt.valid)
			}
			if tt.valid && got.String() != tt.want {
				t.Errorf("parseIPAddr(%q) = %q, want %q", tt.input, got.String(), tt.want)
			}
		})
	}
}

// TestUniqueNormalizedAddrs verifies deduplication, nil handling, and
// IPv4-in-IPv6 normalisation.
func TestUniqueNormalizedAddrs(t *testing.T) {
	mustAddr := func(s string) netip.Addr {
		a, err := netip.ParseAddr(s)
		if err != nil {
			t.Helper()
			t.Fatalf("ParseAddr(%q): %v", s, err)
		}
		return a
	}

	t.Run("empty", func(t *testing.T) {
		if got := uniqueNormalizedAddrs(nil); got != nil {
			t.Errorf("got %v, want nil", got)
		}
	})

	t.Run("single valid", func(t *testing.T) {
		in := []netip.Addr{mustAddr("1.2.3.4")}
		got := uniqueNormalizedAddrs(in)
		if len(got) != 1 || got[0].String() != "1.2.3.4" {
			t.Errorf("got %v", got)
		}
	})

	t.Run("duplicates removed", func(t *testing.T) {
		in := []netip.Addr{mustAddr("1.2.3.4"), mustAddr("1.2.3.4"), mustAddr("5.6.7.8")}
		got := uniqueNormalizedAddrs(in)
		if len(got) != 2 {
			t.Errorf("got %d entries, want 2: %v", len(got), got)
		}
	})

	t.Run("IPv4-in-IPv6 deduplicated with plain IPv4", func(t *testing.T) {
		in := []netip.Addr{mustAddr("1.2.3.4"), mustAddr("::ffff:1.2.3.4")}
		got := uniqueNormalizedAddrs(in)
		if len(got) != 1 {
			t.Errorf("got %d entries, want 1 (unmap dedup): %v", len(got), got)
		}
	})
}

// TestIsAltSvcExpired verifies expiry logic for altSvcEntry.
func TestIsAltSvcExpired(t *testing.T) {
	now := time.Now()

	t.Run("noExpiry is never expired", func(t *testing.T) {
		e := altSvcEntry{noExpiry: true, validTo: now.Add(-time.Hour)}
		if isAltSvcExpired(e, now) {
			t.Error("expected not expired for noExpiry=true")
		}
	})

	t.Run("zero validTo is not expired", func(t *testing.T) {
		e := altSvcEntry{}
		if isAltSvcExpired(e, now) {
			t.Error("expected not expired for zero validTo")
		}
	})

	t.Run("past validTo is expired", func(t *testing.T) {
		e := altSvcEntry{validTo: now.Add(-time.Second)}
		if !isAltSvcExpired(e, now) {
			t.Error("expected expired for past validTo")
		}
	})

	t.Run("future validTo is not expired", func(t *testing.T) {
		e := altSvcEntry{validTo: now.Add(time.Hour)}
		if isAltSvcExpired(e, now) {
			t.Error("expected not expired for future validTo")
		}
	})
}

// TestFetchNilURL verifies that Fetch returns a clean error on nil or
// host-less URLs rather than panicking.
func TestFetchNilURL(t *testing.T) {
	x := NewXTransport()
	x.rebuildTransport()

	t.Run("nil URL", func(t *testing.T) {
		_, _, _, _, err := x.Fetch(context.Background(), http.MethodGet, nil, "", "", nil, time.Second, false)
		if err == nil {
			t.Error("expected error for nil URL, got nil")
		}
	})

	t.Run("empty host", func(t *testing.T) {
		u := &url.URL{Scheme: "https", Host: ""}
		_, _, _, _, err := x.Fetch(context.Background(), http.MethodGet, u, "", "", nil, time.Second, false)
		if err == nil {
			t.Error("expected error for empty host, got nil")
		}
	})
}

// TestParseAndCacheAltSvc verifies that parseAndCacheAltSvc correctly
// extracts an h3= port from an Alt-Svc header and caches it.
func TestParseAndCacheAltSvc(t *testing.T) {
	x := NewXTransport()

	t.Run("h3 port cached", func(t *testing.T) {
		// The parser expects h3="<port>" (bare port number, not ":<port>").
		hdr := http.Header{
			"Alt-Svc": []string{`h3="443"; ma=86400`},
		}
		x.parseAndCacheAltSvc("example.com", 443, hdr)

		x.altSupport.RLock()
		e, ok := x.altSupport.cache["example.com"]
		x.altSupport.RUnlock()

		if !ok {
			t.Fatal("expected Alt-Svc entry to be cached")
		}
		if e.port != 443 {
			t.Errorf("cached port = %d, want 443", e.port)
		}
		if !e.noExpiry {
			t.Error("expected noExpiry=true for a valid h3 advertisement")
		}
	})

	t.Run("no h3 field not cached", func(t *testing.T) {
		x2 := NewXTransport()
		hdr := http.Header{
			"Alt-Svc": []string{`h2=":443"`},
		}
		x2.parseAndCacheAltSvc("other.example.com", 443, hdr)

		x2.altSupport.RLock()
		_, ok := x2.altSupport.cache["other.example.com"]
		x2.altSupport.RUnlock()

		if ok {
			t.Error("expected no cache entry for non-h3 Alt-Svc")
		}
	})

	t.Run("absent Alt-Svc header not cached", func(t *testing.T) {
		x3 := NewXTransport()
		x3.parseAndCacheAltSvc("absent.example.com", 443, http.Header{})

		x3.altSupport.RLock()
		_, ok := x3.altSupport.cache["absent.example.com"]
		x3.altSupport.RUnlock()

		if ok {
			t.Error("expected no cache entry when Alt-Svc header is absent")
		}
	})
}

// BenchmarkFormatDialTarget measures the hot-path performance of the
// dial-target string cache (cache hit case).
func BenchmarkFormatDialTarget(b *testing.B) {
	addr := netip.MustParseAddr("1.2.3.4")
	port := uint16(443)
	// Prime the cache.
	_ = formatDialTarget(addr, port)
	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		_ = formatDialTarget(addr, port)
	}
}

// BenchmarkUniqueNormalizedAddrs measures deduplication of a small slice.
func BenchmarkUniqueNormalizedAddrs(b *testing.B) {
	addrs := []netip.Addr{
		netip.MustParseAddr("1.2.3.4"),
		netip.MustParseAddr("5.6.7.8"),
		netip.MustParseAddr("1.2.3.4"),
		netip.MustParseAddr("::1"),
	}
	b.ReportAllocs()
	for b.Loop() {
		_ = uniqueNormalizedAddrs(addrs)
	}
}
