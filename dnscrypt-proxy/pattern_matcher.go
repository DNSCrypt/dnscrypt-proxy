package main

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/k-sone/critbitgo"

	"github.com/jedisct1/dlog"
)

type PatternType int

const (
	PatternTypeNone PatternType = iota
	PatternTypePrefix
	PatternTypeSuffix
	PatternTypeSubstring
	PatternTypePattern
	PatternTypeExact
)

type PatternMatcher struct {
	prefixes     *critbitgo.Trie
	suffixes     *critbitgo.Trie
	substrings   []string
	patterns     []string
	exact        map[string]any
	indirectVals map[string]any
}

func NewPatternMatcher() *PatternMatcher {
	patternMatcher := PatternMatcher{
		prefixes:     critbitgo.NewTrie(),
		suffixes:     critbitgo.NewTrie(),
		exact:        make(map[string]any),
		indirectVals: make(map[string]any),
	}
	return &patternMatcher
}

func isGlobCandidate(str string) bool {
	for i, c := range str {
		if c == '?' || c == '[' {
			return true
		} else if c == '*' && i != 0 && i != len(str)-1 {
			return true
		}
	}
	return false
}

func (patternMatcher *PatternMatcher) Add(pattern string, val any, position int) error {
	// Determine pattern type based on wildcards and special characters
	leadingStar := strings.HasPrefix(pattern, "*")
	trailingStar := strings.HasSuffix(pattern, "*")
	exact := strings.HasPrefix(pattern, "=")
	patternType := PatternTypeNone

	// Check for glob pattern with wildcard characters
	if isGlobCandidate(pattern) {
		patternType = PatternTypePattern
		_, err := filepath.Match(pattern, "example.com") // Validate pattern syntax
		if len(pattern) < 2 || err != nil {
			return fmt.Errorf("Syntax error in the rule file at line %d", position)
		}
	} else if leadingStar && trailingStar {
		// Substring match (*contains*)
		patternType = PatternTypeSubstring
		if len(pattern) < 3 {
			return fmt.Errorf("Syntax error in the rule file at line %d", position)
		}
		pattern = pattern[1 : len(pattern)-1] // Remove stars
	} else if trailingStar {
		// Prefix match (starts*)
		patternType = PatternTypePrefix
		if len(pattern) < 2 {
			return fmt.Errorf("Syntax error in the rule file at line %d", position)
		}
		pattern = pattern[:len(pattern)-1] // Remove trailing star
	} else if exact {
		// Exact match (=example.com)
		patternType = PatternTypeExact
		if len(pattern) < 2 {
			return fmt.Errorf("Syntax error in the rule file at line %d", position)
		}
		pattern = pattern[1:] // Remove = prefix
	} else {
		// Default: suffix match (*ends or .ends)
		patternType = PatternTypeSuffix
		if leadingStar {
			pattern = pattern[1:] // Remove leading star
		}
		pattern = strings.TrimPrefix(pattern, ".") // Remove leading dot if present
	}
	if len(pattern) == 0 {
		dlog.Errorf("Syntax error in the rule file at line %d", position)
	}

	pattern = strings.ToLower(pattern)
	switch patternType {
	case PatternTypeSubstring:
		patternMatcher.substrings = append(patternMatcher.substrings, pattern)
		if val != nil {
			patternMatcher.indirectVals[pattern] = val
		}
	case PatternTypePattern:
		patternMatcher.patterns = append(patternMatcher.patterns, pattern)
		if val != nil {
			patternMatcher.indirectVals[pattern] = val
		}
	case PatternTypePrefix:
		patternMatcher.prefixes.Insert([]byte(pattern), val)
	case PatternTypeSuffix:
		patternMatcher.suffixes.Insert([]byte(StringReverse(pattern)), val)
	case PatternTypeExact:
		patternMatcher.exact[pattern] = val
	default:
		dlog.Fatal("Unexpected rule pattern type")
	}
	return nil
}

func (patternMatcher *PatternMatcher) Eval(qName string) (reject bool, reason string, val any) {
	if len(qName) < 2 {
		return false, "", nil
	}

	if xval := patternMatcher.exact[qName]; xval != nil {
		return true, qName, xval
	}

	revQname := StringReverse(qName)
	if match, xval, found := patternMatcher.suffixes.LongestPrefix([]byte(revQname)); found {
		if len(match) == len(revQname) || revQname[len(match)] == '.' {
			return true, "*." + StringReverse(string(match)), xval
		}
		if len(match) < len(revQname) && len(revQname) > 0 {
			if i := strings.LastIndex(revQname, "."); i > 0 {
				pName := revQname[:i]
				if match, _, found := patternMatcher.suffixes.LongestPrefix([]byte(pName)); found {
					if len(match) == len(pName) || pName[len(match)] == '.' {
						return true, "*." + StringReverse(string(match)), xval
					}
				}
			}
		}
	}

	if match, xval, found := patternMatcher.prefixes.LongestPrefix([]byte(qName)); found {
		return true, string(match) + "*", xval
	}

	for _, substring := range patternMatcher.substrings {
		if strings.Contains(qName, substring) {
			return true, "*" + substring + "*", patternMatcher.indirectVals[substring]
		}
	}

	for _, pattern := range patternMatcher.patterns {
		if found, _ := filepath.Match(pattern, qName); found {
			return true, pattern, patternMatcher.indirectVals[pattern]
		}
	}

	return false, "", nil
}
