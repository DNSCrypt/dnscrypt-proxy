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
	if !wantColor() {
		ansiGreen, ansiYellow, ansiRed, ansiReset = "", "", "", ""
	}
}

func wantColor() bool {
	return strings.Contains(os.Getenv("TERM"), "color") &&
		(isTerminal() || os.Getenv("GO_TEST_COLOR") != "")
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
