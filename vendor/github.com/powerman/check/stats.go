package check

import (
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
)

type counter struct {
	name  string
	value int
	force bool
	color string
	size  int
}

func (c counter) String() (s string) {
	if c.value != 0 || c.force {
		color := c.color
		if c.value == 0 {
			color = ansiReset
		}
		s = fmt.Sprintf("%s%*d %s%s", color, c.size, c.value, c.name, ansiReset)
	} else {
		s = strings.Repeat(" ", c.size+1+len(c.name))
	}
	return s
}

type testStat struct {
	name   string
	passed counter
	forged counter
	failed counter
}

func newTestStat(desc string, force bool) *testStat {
	return &testStat{
		name:   desc,
		passed: counter{force: force, name: "passed", color: ansiGreen},
		forged: counter{force: force, name: "todo", color: ansiYellow},
		failed: counter{force: force, name: "failed", color: ansiRed},
	}
}

func (c testStat) String() string {
	return fmt.Sprintf("checks:  %s  %s  %s\t%s", c.passed, c.forged, c.failed, c.name)
}

//nolint:gochecknoglobals // By design.
var (
	statsMu sync.Mutex
	stats   = make(map[string]*testStat) // Keyed by test name, see [checks.stat].
)

// Report output statistics about passed/failed checks to stderr.
// It should be called from TestMain after m.Run(), for ex.:
//
//	func TestMain(m *testing.M) {
//		code := m.Run()
//		check.Report()
//		os.Exit(code)
//	}
//
// If this is all you need - just use TestMain instead.
//
// Using stderr ensures the output does not interfere with
// `go test -json` (which expects only valid JSON on stdout).
func Report() {
	statsMu.Lock()
	defer statsMu.Unlock()

	total := newTestStat("(total)", true)
	for _, stat := range stats {
		total.passed.value += stat.passed.value
		total.forged.value += stat.forged.value
		total.failed.value += stat.failed.value
	}

	total.passed.size = digits(total.passed.value)
	total.forged.size = digits(total.forged.value)
	total.failed.size = digits(total.failed.value)

	if testing.Verbose() {
		for _, name := range slices.Sorted(maps.Keys(stats)) {
			stats[name].passed.size = total.passed.size
			stats[name].forged.size = total.forged.size
			stats[name].failed.size = total.failed.size
			fmt.Fprintf(os.Stderr, "  %s\n", stats[name])
		}
	}
	fmt.Fprintf(os.Stderr, "  %s\n", total)
}

// TestMain provides same default implementation as used by testing
// package with extra Report call to output statistics to stderr.
// Usage:
//
//	func TestMain(m *testing.M) { check.TestMain(m) }
//
// Using stderr ensures the statistics output does not interfere with
// `go test -json` (which expects only valid JSON on stdout).
func TestMain(m *testing.M) {
	code := m.Run()
	Report()
	os.Exit(code) //nolint:revive // By design.
}
