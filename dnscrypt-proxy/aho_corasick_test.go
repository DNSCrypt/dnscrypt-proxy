package main

import "testing"

func TestAhoCorasickBasic(t *testing.T) {
	ac := NewAhoCorasick()
	ac.AddPattern("ads")
	ac.AddPattern("tracking")
	ac.AddPattern("malware")
	ac.Build()

	tests := []struct {
		text    string
		found   bool
		pattern string
	}{
		{"example-ads.com", true, "ads"},
		{"tracking.example.com", true, "tracking"},
		{"malware-site.org", true, "malware"},
		{"clean.example.com", false, ""},
		{"example.com", false, ""},
		{"", false, ""},
		{"a", false, ""},
		{"ad", false, ""},
		{"adserver.com", true, "ads"},
	}

	for _, tt := range tests {
		found, idx := ac.ContainsAny(tt.text)
		if found != tt.found {
			t.Errorf("ContainsAny(%q) = %v, want %v", tt.text, found, tt.found)
		}
		if found && ac.Pattern(idx) != tt.pattern {
			t.Errorf("ContainsAny(%q) matched %q, want %q", tt.text, ac.Pattern(idx), tt.pattern)
		}
	}
}

func TestAhoCorasickEmpty(t *testing.T) {
	ac := NewAhoCorasick()
	ac.Build()

	found, _ := ac.ContainsAny("test")
	if found {
		t.Error("Empty automaton should not match anything")
	}
}

func TestAhoCorasickOverlapping(t *testing.T) {
	ac := NewAhoCorasick()
	ac.AddPattern("he")
	ac.AddPattern("she")
	ac.AddPattern("his")
	ac.AddPattern("hers")
	ac.Build()

	tests := []struct {
		text  string
		found bool
	}{
		{"ushers", true},
		{"she", true},
		{"his", true},
		{"hers", true},
		{"other", true}, // contains "he"
		{"xyz", false},
	}

	for _, tt := range tests {
		found, _ := ac.ContainsAny(tt.text)
		if found != tt.found {
			t.Errorf("ContainsAny(%q) = %v, want %v", tt.text, found, tt.found)
		}
	}
}

func TestAhoCorasickSingleChar(t *testing.T) {
	ac := NewAhoCorasick()
	ac.AddPattern("x")
	ac.Build()

	found, idx := ac.ContainsAny("example")
	if !found {
		t.Error("Should find 'x' in 'example'")
	}
	if ac.Pattern(idx) != "x" {
		t.Errorf("Expected pattern 'x', got %q", ac.Pattern(idx))
	}

	found, _ = ac.ContainsAny("ample")
	if found {
		t.Error("Should not find 'x' in 'ample'")
	}
}

func BenchmarkPatternMatcherSubstringLinear(b *testing.B) {
	pm := NewPatternMatcher()
	patterns := []string{"ads", "tracking", "malware", "spam", "phishing", "banner", "popup", "analytics", "telemetry", "pixel"}
	for i, p := range patterns {
		pm.Add("*"+p+"*", nil, i+1)
	}
	// Don't build AC, to test linear scan
	b.ResetTimer()
	for b.Loop() {
		pm.Eval("clean.example.com")
	}
}

func BenchmarkPatternMatcherSubstringAC(b *testing.B) {
	pm := NewPatternMatcher()
	patterns := []string{"ads", "tracking", "malware", "spam", "phishing", "banner", "popup", "analytics", "telemetry", "pixel"}
	for i, p := range patterns {
		pm.Add("*"+p+"*", nil, i+1)
	}
	pm.Build() // Build AC automaton
	b.ResetTimer()
	for b.Loop() {
		pm.Eval("clean.example.com")
	}
}
