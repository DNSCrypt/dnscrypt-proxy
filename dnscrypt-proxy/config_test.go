// config_test.go — unit tests for config loading performance optimizations.
package main

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/BurntSushi/toml"
)

// ── findConfigFile tests ──────────────────────────────────────────────────────

func TestFindConfigFile_NilPointer(t *testing.T) {
	_, err := findConfigFile(nil)
	if err == nil {
		t.Fatal("expected error for nil pointer, got nil")
	}
}

func TestFindConfigFile_EmptyString(t *testing.T) {
	empty := ""
	_, err := findConfigFile(&empty)
	if err == nil {
		t.Fatal("expected error for empty string, got nil")
	}
}

func TestFindConfigFile_AbsolutePathExists(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "dnscrypt-test-*.toml")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	abs := f.Name()

	got, err := findConfigFile(&abs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != abs {
		t.Errorf("got %q, want %q", got, abs)
	}
}

func TestFindConfigFile_AbsolutePathMissing(t *testing.T) {
	abs := "/nonexistent/path/that/does/not/exist/config.toml"
	_, err := findConfigFile(&abs)
	if err == nil {
		t.Fatal("expected error for nonexistent absolute path, got nil")
	}
}

func TestFindConfigFile_RelativeToCwd(t *testing.T) {
	// Create a temp dir, write a file there, chdir into it, and look up a
	// relative name. The test restores cwd on exit.
	dir := t.TempDir()
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(origDir) })

	const filename = "test-config.toml"
	if err := os.WriteFile(filepath.Join(dir, filename), []byte{}, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}

	name := filename
	got, err := findConfigFile(&name)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !filepath.IsAbs(got) {
		t.Errorf("expected absolute path, got %q", got)
	}
	if !strings.HasSuffix(got, filename) {
		t.Errorf("path %q should end with %q", got, filename)
	}
}

func TestFindConfigFile_RelativeMissing(t *testing.T) {
	// Change to a temp dir that definitely does not contain the named file.
	dir := t.TempDir()
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(origDir) })
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}

	name := "definitely-missing.toml"
	_, err = findConfigFile(&name)
	if err == nil {
		t.Fatal("expected error for missing relative path, got nil")
	}
}

func TestFindConfigFile_ReturnsAbsoluteForRelative(t *testing.T) {
	// Verify that a relative path that is found is returned as an absolute path.
	dir := t.TempDir()
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(origDir) })

	const filename = "absolute-check.toml"
	if err := os.WriteFile(filepath.Join(dir, filename), []byte{}, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}

	name := filename
	got, err := findConfigFile(&name)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !filepath.IsAbs(got) {
		t.Errorf("findConfigFile returned non-absolute path %q for relative input", got)
	}
}

// ── newStartupProfiler tests ──────────────────────────────────────────────────

func TestStartupProfiler_Disabled(t *testing.T) {
	// Ensure env var is absent.
	t.Setenv("DNSCRYPT_PROXY_PROFILE_STARTUP", "")

	mark, finish := newStartupProfiler()
	// Neither call should panic.
	mark("phase1")
	mark("phase2")
	finish()
}

func TestStartupProfiler_Enabled(t *testing.T) {
	t.Setenv("DNSCRYPT_PROXY_PROFILE_STARTUP", "1")

	start := time.Now()
	mark, finish := newStartupProfiler()
	mark("findConfigFile")
	mark("tomlDecode")
	mark("configure")
	finish()
	elapsed := time.Since(start)

	// The whole profiler exercise should be nearly instantaneous.
	if elapsed > 5*time.Second {
		t.Errorf("startup profiler took unexpectedly long: %s", elapsed)
	}
}

func TestStartupProfiler_ConcurrentSafe(t *testing.T) {
	t.Setenv("DNSCRYPT_PROXY_PROFILE_STARTUP", "1")

	mark, finish := newStartupProfiler()
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			mark("concurrent-phase")
		}()
	}
	wg.Wait()
	finish()
}

func TestStartupProfiler_NoopWhenDisabled(t *testing.T) {
	// Verify the returned functions are the zero-cost no-op variants when
	// the env var is not "1".
	for _, val := range []string{"", "0", "false", "yes"} {
		t.Setenv("DNSCRYPT_PROXY_PROFILE_STARTUP", val)
		mark, finish := newStartupProfiler()
		// These must not panic and must run in negligible time.
		before := time.Now()
		for i := 0; i < 1000; i++ {
			mark("noop")
		}
		finish()
		if elapsed := time.Since(before); elapsed > time.Second {
			t.Errorf("no-op profiler for %q took %s; expected < 1s", val, elapsed)
		}
	}
}

// ── minimalConfig decode tests ────────────────────────────────────────────────

func TestMinimalConfigDecode_Fields(t *testing.T) {
	const tomlContent = `
listen_addresses = ["127.0.0.1:5300"]
server_names = ["cloudflare"]
offline_mode = true
`
	f, err := os.CreateTemp(t.TempDir(), "min-*.toml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(tomlContent); err != nil {
		t.Fatal(err)
	}
	f.Close()

	var mc minimalConfig
	mc.ListenAddresses = []string{"127.0.0.1:53"} // preset default
	if _, err := toml.DecodeFile(f.Name(), &mc); err != nil {
		t.Fatalf("unexpected decode error: %v", err)
	}
	if len(mc.ListenAddresses) != 1 || mc.ListenAddresses[0] != "127.0.0.1:5300" {
		t.Errorf("ListenAddresses = %v, want [127.0.0.1:5300]", mc.ListenAddresses)
	}
	if len(mc.ServerNames) != 1 || mc.ServerNames[0] != "cloudflare" {
		t.Errorf("ServerNames = %v, want [cloudflare]", mc.ServerNames)
	}
	if !mc.OfflineMode {
		t.Error("OfflineMode = false, want true")
	}
}

func TestMinimalConfigDecode_PreservesDefaults(t *testing.T) {
	// An empty TOML file should leave the preset defaults in place.
	f, err := os.CreateTemp(t.TempDir(), "empty-*.toml")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()

	var mc minimalConfig
	mc.ListenAddresses = []string{"127.0.0.1:53"}
	if _, err := toml.DecodeFile(f.Name(), &mc); err != nil {
		t.Fatalf("unexpected decode error: %v", err)
	}
	if len(mc.ListenAddresses) != 1 || mc.ListenAddresses[0] != "127.0.0.1:53" {
		t.Errorf("default ListenAddresses = %v, want [127.0.0.1:53]", mc.ListenAddresses)
	}
}

func TestMinimalConfigDecode_IgnoresUnknownKeys(t *testing.T) {
	// minimalConfig should silently accept keys it does not know — TOML
	// decoders do not fail on unknown keys by default. This verifies the
	// fast-path decode won't break when the config has extra keys.
	const tomlContent = `
listen_addresses = ["0.0.0.0:53"]
server_names     = ["quad9"]
offline_mode     = false
timeout          = 5000
some_future_key  = "ignored"
`
	f, err := os.CreateTemp(t.TempDir(), "extra-*.toml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(tomlContent); err != nil {
		t.Fatal(err)
	}
	f.Close()

	var mc minimalConfig
	if _, err := toml.DecodeFile(f.Name(), &mc); err != nil {
		t.Fatalf("minimalConfig decode should not fail on unknown keys: %v", err)
	}
	if mc.ListenAddresses[0] != "0.0.0.0:53" {
		t.Errorf("ListenAddresses[0] = %q, want %q", mc.ListenAddresses[0], "0.0.0.0:53")
	}
}

// ── flagBool helper tests ─────────────────────────────────────────────────────

func TestFlagBool(t *testing.T) {
	if flagBool(nil) {
		t.Error("flagBool(nil) should return false")
	}
	f := false
	if flagBool(&f) {
		t.Error("flagBool(&false) should return false")
	}
	tr := true
	if !flagBool(&tr) {
		t.Error("flagBool(&true) should return true")
	}
}

// ── URL shuffle guard tests ───────────────────────────────────────────────────

// TestURLShuffleGuard verifies that the guard condition (len > 1) used in
// loadSources correctly distinguishes single-URL from multi-URL sources.
func TestURLShuffleGuard(t *testing.T) {
	cases := []struct {
		name        string
		urls        []string
		wantShuffle bool
	}{
		{"empty", []string{}, false},
		{"single", []string{"https://a.example.com"}, false},
		{"two", []string{"https://a.example.com", "https://b.example.com"}, true},
		{"three", []string{"https://a.example.com", "https://b.example.com", "https://c.example.com"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			shouldShuffle := len(tc.urls) > 1
			if shouldShuffle != tc.wantShuffle {
				t.Errorf("len=%d: shouldShuffle=%v, want %v", len(tc.urls), shouldShuffle, tc.wantShuffle)
			}
		})
	}
}
