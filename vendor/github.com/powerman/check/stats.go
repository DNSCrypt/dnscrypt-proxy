package check

import (
	"fmt"
	"os"
	"sort"
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
	stats   = make(map[*testing.T]*testStat)
)

// Report output statistics about passed/failed checks.
// It should be called from TestMain after m.Run(), for ex.:
//
//	func TestMain(m *testing.M) {
//		code := m.Run()
//		check.Report()
//		os.Exit(code)
//	}
//
// If this is all you need - just use TestMain instead.
func Report() {
	statsMu.Lock()
	defer statsMu.Unlock()

	total := newTestStat("(total)", true)
	ts := make([]*testing.T, 0, len(stats))
	for t := range stats {
		ts = append(ts, t)
		total.passed.value += stats[t].passed.value
		total.forged.value += stats[t].forged.value
		total.failed.value += stats[t].failed.value
	}

	total.passed.size = digits(total.passed.value)
	total.forged.size = digits(total.forged.value)
	total.failed.size = digits(total.failed.value)

	if testing.Verbose() {
		sort.Slice(ts, func(a, b int) bool { return ts[a].Name() < ts[b].Name() })
		for _, t := range ts {
			stats[t].passed.size = total.passed.size
			stats[t].forged.size = total.forged.size
			stats[t].failed.size = total.failed.size
			fmt.Printf("  %s\n", stats[t])
		}
	}
	fmt.Printf("  %s\n", total)
}

// TestMain provides same default implementation as used by testing
// package with extra Report call to output statistics. Usage:
//
//	func TestMain(m *testing.M) { check.TestMain(m) }
func TestMain(m *testing.M) {
	code := m.Run()
	Report()
	os.Exit(code) //nolint:revive // By design.
}
