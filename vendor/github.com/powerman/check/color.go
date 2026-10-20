package check

import (
	"os"
	"strings"
)

//nolint:gochecknoglobals // By design.
var (
	ansiGreen  = "\033[32m"
	ansiYellow = "\033[33m"
	ansiRed    = "\033[31m"
	ansiReset  = "\033[0m"
)

func init() { //nolint:gochecknoinits // By design.
	if !wantColor(os.Getenv, isTerminal()) {
		ansiGreen, ansiYellow, ansiRed, ansiReset = "", "", "", ""
	}
}

func isTerminal() bool {
	fi, err := os.Stderr.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

// wantColor reports whether coloured output should be enabled.
//
// Precedence (first match wins):
//  1. NO_COLOR set (any non-empty value) → no colour.
//  2. CLICOLOR_FORCE set and not "0"    → colour.
//  3. FORCE_COLOR set and not "0"       → colour.
//  4. GO_TEST_COLOR set (any non-empty) → colour (legacy; superseded by FORCE_COLOR).
//  5. isTTY and TERM != "dumb" and TERM != "" → colour.
//  6. Otherwise → no colour.
func wantColor(getenv func(string) string, isTTY bool) bool {
	switch {
	case getenv("NO_COLOR") != "":
		return false
	case getenv("CLICOLOR_FORCE") != "" && getenv("CLICOLOR_FORCE") != "0":
		return true
	case getenv("FORCE_COLOR") != "" && getenv("FORCE_COLOR") != "0":
		return true
	case getenv("GO_TEST_COLOR") != "":
		return true
	default:
		term := getenv("TERM")
		return isTTY && term != "dumb" && term != ""
	}
}

func colouredDiff(diff string) string {
	lines := strings.SplitAfter(diff, "\n")
	for i := range lines {
		switch {
		case strings.HasPrefix(lines[i], "--- "):
		case strings.HasPrefix(lines[i], "+++ "):
		case strings.HasPrefix(lines[i], "-"):
			lines[i] = ansiGreen + lines[i] + ansiReset
		case strings.HasPrefix(lines[i], "+"):
			lines[i] = ansiRed + lines[i] + ansiReset
		}
	}
	return strings.Join(lines, "")
}
