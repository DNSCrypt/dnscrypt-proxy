package check

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/powerman/check/internal/contextx"
)

// checks holds all check-specific state and the whole checker/report machinery
// (Nil, Equal, ..., Must, Should, TODO/MustAll bookkeeping).
// It is embedded anonymously in both [TB] and [C],
// which is what gives each of them the full checker API for free.
//
// checks deliberately does NOT implement any [testing.TB] method
// (Error, Errorf, Fail, FailNow, Context, Helper, Cleanup, ...):
// every call into the real test/benchmark/fuzz target
// goes through the explicit tb field instead of through embedding.
// TB and C each separately embed their own single,
// unambiguous [testing.TB]-implementing source
// (the wrapped [testing.TB] for TB, the wrapped [*testing.T] for C) -
// since checks never claims any of the same method names,
// embedding it alongside that source never creates an ambiguous selector,
// and - just as important - Helper/Cleanup/etc. promoted from that single source
// stay genuinely zero-cost (no synthetic wrapper frame),
// so a caller-defined helper that itself calls t.Helper()
// correctly hides its own frame from failure locations.
type checks struct {
	tb testing.TB

	todo bool
	must bool
	ctx  context.Context // Non-nil only after MergeContext.
}

func (c *checks) withTODO() *checks {
	d := *c
	d.todo = true
	return &d
}

func (c *checks) withMustAll() *checks {
	d := *c
	d.must = true
	return &d
}

// context returns the context associated with c:
// the one merged in by the most recent MergeContext call if any, otherwise tb's own Context().
func (c *checks) context() context.Context {
	if c.ctx != nil {
		return c.ctx
	}
	return c.tb.Context()
}

// mergeContext returns a *checks derived from c
// whose context() combines ctx with the current context():
// values are looked up in ctx first, falling back to the current context();
// cancellation/deadline come from both, whichever happens first.
// Calling it again merges in one more context.
// The returned cancel must be registered by the caller (TB/C),
// since only they know which Cleanup to call it through.
func (c *checks) mergeContext(ctx context.Context) (*checks, context.CancelFunc) {
	merged, cancel := contextx.Merge(ctx, c.context())
	d := *c
	d.ctx = merged
	return &d, cancel
}

func (c *checks) pass() {
	statsMu.Lock()
	defer statsMu.Unlock()

	if stats[c.tb] == nil {
		stats[c.tb] = newTestStat(c.tb.Name(), false)
	}
	if c.todo {
		stats[c.tb].forged.value++
	} else {
		stats[c.tb].passed.value++
	}
}

func (c *checks) fail() {
	statsMu.Lock()
	defer statsMu.Unlock()

	if stats[c.tb] == nil {
		stats[c.tb] = newTestStat(c.tb.Name(), false)
	}
	stats[c.tb].failed.value++
}

func (c *checks) report(ok bool, msg []any, checker string, name []string, args []any) bool { //nolint:revive // False positive.
	c.tb.Helper()

	if ok != c.todo {
		c.pass()
		return ok
	}

	if c.todo {
		checker = "TODO " + checker
	}

	dump := make([]dump, 0, len(args))
	for _, arg := range args {
		dump = append(dump, newDump(arg))
	}

	failure := new(bytes.Buffer)
	fmt.Fprintf(failure, "%s\nChecker:  %s%s%s\n",
		format(msg...),
		ansiYellow, checker, ansiReset,
	)
	// Reverse order to show Actual: last.
	for i, v := range slices.Backward(dump) {
		fmt.Fprintf(failure, "%-10s", name[i]+":")
		switch name[i] {
		case nameActual:
			fmt.Fprint(failure, ansiRed)
		default:
			fmt.Fprint(failure, ansiGreen)
		}
		fmt.Fprintf(failure, "%s%s", v, ansiReset)
	}

	wantDiff := len(dump) == 2 && name[0] == nameActual && name[1] == nameExpected
	if wantDiff {
		fmt.Fprintf(failure, "\n%s", colouredDiff(dump[0].diff(dump[1])))
	}
	c.tb.Errorf("%s\n", failure)

	c.fail()

	if c.must {
		c.tb.FailNow() // Already counted above: bypass the counting FailNow wrapper.
	}
	return ok
}

func (c *checks) reportShould1(funcName string, actual any, msg []any, ok bool) bool {
	c.tb.Helper()
	return c.report(ok, msg,
		"Should "+funcName,
		[]string{nameActual},
		[]any{actual})
}

func (c *checks) reportShould2(funcName string, actual, expected any, msg []any, ok bool) bool {
	c.tb.Helper()
	return c.report(ok, msg,
		"Should "+funcName,
		[]string{nameActual, nameExpected},
		[]any{actual, expected})
}

func (c *checks) report0(msg []any, ok bool) bool {
	c.tb.Helper()
	return c.report(ok, msg,
		callerFuncName(1),
		[]string{},
		[]any{})
}

func (c *checks) report1(actual any, msg []any, ok bool) bool {
	c.tb.Helper()
	return c.report(ok, msg,
		callerFuncName(1),
		[]string{nameActual},
		[]any{actual})
}

func (c *checks) report2(actual, expected any, msg []any, ok bool) bool {
	c.tb.Helper()
	checker, arg2Name := callerFuncName(1), nameExpected
	if strings.Contains(checker, "Match") {
		arg2Name = "Regex"
	}
	return c.report(ok, msg,
		checker,
		[]string{nameActual, arg2Name},
		[]any{actual, expected})
}

func (c *checks) report3(actual, expected1, expected2 any, msg []any, ok bool) bool {
	c.tb.Helper()
	checker, arg2Name, arg3Name := callerFuncName(1), "arg1", "arg2"
	switch {
	case strings.Contains(checker, "Between"):
		arg2Name, arg3Name = "Min", "Max"
	case strings.Contains(checker, "Delta"):
		arg2Name, arg3Name = nameExpected, "Delta"
	case strings.Contains(checker, "SMAPE"):
		arg2Name, arg3Name = nameExpected, "SMAPE"
	}
	return c.report(ok, msg,
		checker,
		[]string{nameActual, arg2Name, arg3Name},
		[]any{actual, expected1, expected2})
}

// Must interrupt test using t.FailNow if called with false value.
//
// This provides an easy way to turn any check into assertion:
//
//	t.Must(t.Nil(err))
func (c *checks) Must(continueTest bool, msg ...any) { //nolint:revive // False positive.
	c.tb.Helper()
	c.report0(msg, continueTest)
	if !continueTest {
		c.tb.FailNow() // Already counted above: bypass the counting FailNow wrapper.
	}
}

// TB wraps [testing.TB] to make it convenient to call checkers in tests,
// benchmarks and fuzz targets.
//
// Use [New] or [Must] to create it.
// [C] is a thin, [*testing.T]-only compatibility shell built on top of the same machinery.
type TB struct {
	testing.TB
	*checks
}

var _ testing.TB = (*TB)(nil)

type (
	// ShouldFunc1 is like Nil or Zero.
	ShouldFunc1 func(t *TB, actual any) bool
	// ShouldFunc2 is like Equal or Match.
	ShouldFunc2 func(t *TB, actual, expected any) bool
)

// Should use user-provided check function to do actual check.
//
// anyShouldFunc must have type ShouldFunc1 or ShouldFunc2.
// It should return true if check was successful.
// There is no need to call t.Error in anyShouldFunc -
// this will be done automatically when it returns.
//
// args must contain at least 1 element for ShouldFunc1 and at least 2 elements for ShouldFunc2.
// Rest of elements will be processed as usual msg ...interface{} param.
//
// Example:
//
//	func bePositive(_ *check.TB, actual interface{}) bool {
//		return actual.(int) > 0
//	}
//	func TestCustomCheck(tt *testing.T) {
//		t := check.T(tt)
//		t.Should(bePositive, 42, "custom check!!!")
//	}
func (t *TB) Should(anyShouldFunc any, args ...any) bool {
	t.Helper()
	switch f := anyShouldFunc.(type) {
	case func(t *TB, actual any) bool:
		return t.should1(f, args...)
	case func(t *TB, actual, expected any) bool:
		return t.should2(f, args...)
	default:
		panic("anyShouldFunc is not a ShouldFunc1 or ShouldFunc2")
	}
}

func (t *TB) should1(f ShouldFunc1, args ...any) bool {
	t.Helper()
	if len(args) < 1 {
		panic("not enough params for " + funcName(f))
	}
	actual, msg := args[0], args[1:]
	return t.reportShould1(funcName(f), actual, msg,
		f(t, actual))
}

func (t *TB) should2(f ShouldFunc2, args ...any) bool {
	t.Helper()
	const minArgs = 2
	if len(args) < minArgs {
		panic("not enough params for " + funcName(f))
	}
	actual, expected, msg := args[0], args[1], args[2:]
	return t.reportShould2(funcName(f), actual, expected, msg,
		f(t, actual, expected))
}

// New creates and returns new *TB, which wraps given tb and supposed to be used inplace of it,
// providing you with access to many useful helpers in addition to standard methods
// of [testing.TB].
//
// A failed check does not stop the test - use [TB.MustAll] or [TB.Must](continueTest)
// to turn checks into assertions. See [Must] for a fail-fast alternative.
//
// TB doesn't provide Run/Parallel: call tb.Run/tb.Parallel on the original
// [*testing.T]/[*testing.B]/[*testing.F].
func New(tb testing.TB) *TB { //nolint:thelper // With check we name it tb, not t!
	return &TB{TB: tb, checks: &checks{tb: tb}}
}

// Must creates and returns new *TB like [New],
// but every failed check will interrupt the test using [TB.FailNow].
//
// This is the recommended default constructor for new tests.
func Must(tb testing.TB) *TB { //nolint:thelper // With check we name it tb, not t!
	return &TB{TB: tb, checks: &checks{tb: tb, must: true}}
}

// TODO creates and returns new *TB, which have only one difference from original one:
// every passing check is now handled as failed and vice versa
// (this doesn't affect boolean value returned by check).
// You can continue using both old and new *TB at same time.
//
// Swapping passed/failed gives you ability to temporary mark some failed test as passed.
// For example, this may be useful to avoid broken builds in CI.
// This is often better than commenting, deleting or skipping broken test
// because it will continue to execute,
// and eventually when reason why it fails will be fixed this test will became failed again -
// notifying you the mark can and should be removed from this test now.
func (t *TB) TODO() *TB {
	return &TB{TB: t.TB, checks: t.withTODO()}
}

// MustAll creates and returns new *TB, which have only one difference from original one:
// every failed check will interrupt test using t.FailNow.
// You can continue using both old and new *TB at same time.
//
// This provides an easy way to turn all checks into assertion.
func (t *TB) MustAll() *TB {
	return &TB{TB: t.TB, checks: t.withMustAll()}
}

// Context returns the context associated with t:
// the context merged in by the most recent [TB.MergeContext] call if any,
// otherwise the standard [testing.TB.Context]().
func (t *TB) Context() context.Context {
	return t.context()
}

// MergeContext returns a derived *TB whose Context() combines ctx with the current Context():
// values are looked up in ctx first, falling back to the current Context();
// cancellation/deadline come from both, whichever happens first.
// Calling MergeContext again merges in one more context.
//
// This is meant for injecting an application base context (e.g. one carrying a slog handler)
// into tests, on top of the per-test cancellation/deadline testing.TB.Context() already provides.
func (t *TB) MergeContext(ctx context.Context) *TB {
	merged, cancel := t.mergeContext(ctx)
	t.Cleanup(cancel)
	return &TB{TB: t.TB, checks: merged}
}

// Error is equivalent to Log followed by Fail.
//
// It is like t.Errorf with TODO() and statistics support.
func (t *TB) Error(args ...any) {
	t.Helper()
	t.report0(args, false)
}

// Errorf is equivalent to Logf followed by Fail.
//
// It is like t.Errorf with TODO() and statistics support.
func (t *TB) Errorf(format string, args ...any) {
	t.Helper()
	t.report0(append([]any{format}, args...), false)
}

// Fatal is equivalent to Log followed by FailNow.
//
// It is like t.Fatal with TODO() and statistics support.
func (t *TB) Fatal(args ...any) {
	t.Helper()
	t.report0(args, false)
	if !t.todo {
		t.TB.FailNow() // Already counted above: bypass the counting FailNow wrapper.
	}
}

// Fatalf is equivalent to Logf followed by FailNow.
//
// It is like t.Fatalf with TODO() and statistics support.
func (t *TB) Fatalf(format string, args ...any) {
	t.Helper()
	t.report0(append([]any{format}, args...), false)
	if !t.todo {
		t.TB.FailNow() // Already counted above: bypass the counting FailNow wrapper.
	}
}

// Fail marks the function as having failed but continues execution.
//
// Unlike plain [testing.TB.Fail], calling it directly (rather than through
// a checker) is still counted in check's pass/fail statistics.
func (t *TB) Fail() {
	t.fail()
	t.TB.Fail()
}

// FailNow marks the function as having failed and stops its execution.
//
// Unlike plain [testing.TB.FailNow], calling it directly (rather than
// through a checker) is still counted in check's pass/fail statistics.
func (t *TB) FailNow() {
	t.fail()
	t.TB.FailNow()
}
