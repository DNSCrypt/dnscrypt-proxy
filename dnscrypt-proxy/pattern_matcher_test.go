package main

import (
	"math/rand"
	"strings"
	"testing"
)

func TestPatternMatcherSuffixLabelBoundary(t *testing.T) {
	tests := []struct {
		name       string
		rules      []string
		qName      string
		wantReject bool
		wantReason string
	}{
		{
			name:       "zone rule matches a name in the zone",
			rules:      []string{"example.com"},
			qName:      "www.xads.example.com",
			wantReject: true,
			wantReason: "*.example.com",
		},
		{
			name:       "a more specific rule does not hide the zone rule",
			rules:      []string{"example.com", "ads.example.com"},
			qName:      "www.xads.example.com",
			wantReject: true,
			wantReason: "*.example.com",
		},
		{
			name:       "the most specific matching rule wins",
			rules:      []string{"example.com", "ads.example.com"},
			qName:      "www.ads.example.com",
			wantReject: true,
			wantReason: "*.ads.example.com",
		},
		{
			name:       "several unaligned rules still fall back to the zone rule",
			rules:      []string{"example.com", "ads.example.com", "s.example.com"},
			qName:      "a.b.xads.example.com",
			wantReject: true,
			wantReason: "*.example.com",
		},
		{
			name:       "a rule is not matched in the middle of a label",
			rules:      []string{"ads.example.com"},
			qName:      "www.xads.example.com",
			wantReject: false,
			wantReason: "",
		},
		{
			name:       "a rule matches the zone apex itself",
			rules:      []string{"example.com", "ads.example.com"},
			qName:      "example.com",
			wantReject: true,
			wantReason: "*.example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			patternMatcher := NewPatternMatcher()
			for lineNo, rule := range tt.rules {
				if err := patternMatcher.Add(rule, rule, lineNo+1); err != nil {
					t.Fatalf("Add(%q) returned error: %v", rule, err)
				}
			}
			gotReject, gotReason, _ := patternMatcher.Eval(tt.qName)
			if gotReject != tt.wantReject {
				t.Errorf("Eval(%q) reject = %v, want %v", tt.qName, gotReject, tt.wantReject)
			}
			if gotReason != tt.wantReason {
				t.Errorf("Eval(%q) reason = %v, want %v", tt.qName, gotReason, tt.wantReason)
			}
		})
	}
}

// evalSuffixRules is a deliberately naive implementation of the suffix rule
// semantics documented in example-blocked-names.txt: a rule matches the name it
// names, and every name below it. The differential test below compares the
// matcher against it.
func evalSuffixRules(rules []string, qName string) (bool, string) {
	longest := ""
	for _, rule := range rules {
		if qName != rule && !strings.HasSuffix(qName, "."+rule) {
			continue
		}
		if len(rule) > len(longest) {
			longest = rule
		}
	}
	if longest == "" {
		return false, ""
	}
	return true, "*." + longest
}

func TestPatternMatcherSuffixDifferential(t *testing.T) {
	const cases = 20000

	// Labels chosen so that one rule is frequently a byte suffix of a query
	// without being a label of it ("ads" inside "xads", "ex" inside "xex").
	labels := []string{"a", "xa", "ad", "ads", "xads", "ex", "xex", "example"}
	tlds := []string{"com", "net"}

	random := rand.New(rand.NewSource(20260731))
	pick := func(list []string) string { return list[random.Intn(len(list))] }
	prefix := func(count int) []string {
		parts := make([]string, 0, count)
		for range count {
			parts = append(parts, pick(labels))
		}
		return parts
	}

	mismatches := 0
	for range cases {
		rules := make([]string, 0, 4)
		for range 1 + random.Intn(4) {
			rules = append(rules, strings.Join(append(prefix(1+random.Intn(2)), pick(tlds)), "."))
		}
		// Half of the queries are built below an existing rule, so that a
		// missed match is a rule that silently stopped working.
		base := strings.Join(append(prefix(1), pick(tlds)), ".")
		if random.Intn(2) == 0 {
			base = pick(rules)
		}
		qName := strings.Join(append(prefix(random.Intn(3)), base), ".")

		patternMatcher := NewPatternMatcher()
		for lineNo, rule := range rules {
			if err := patternMatcher.Add(rule, rule, lineNo+1); err != nil {
				t.Fatalf("Add(%q) returned error: %v", rule, err)
			}
		}
		gotReject, gotReason, _ := patternMatcher.Eval(qName)
		wantReject, wantReason := evalSuffixRules(rules, qName)
		if gotReject == wantReject && gotReason == wantReason {
			continue
		}
		mismatches++
		if mismatches <= 5 {
			t.Errorf(
				"rules %v, Eval(%q) = (%v, %v), want (%v, %v)",
				rules, qName, gotReject, gotReason, wantReject, wantReason,
			)
		}
	}
	if mismatches != 0 {
		t.Errorf("%d of %d generated cases disagree with the reference implementation", mismatches, cases)
	} else {
		t.Logf("%d generated cases, no disagreement with the reference implementation", cases)
	}
}
