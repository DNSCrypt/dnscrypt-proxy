# check

[![License MIT](https://img.shields.io/badge/license-MIT-royalblue.svg)](LICENSE)
[![Go version](https://img.shields.io/github/go-mod/go-version/powerman/check?color=blue)](https://go.dev/)
[![Test](https://img.shields.io/github/actions/workflow/status/powerman/check/test.yml?label=test)](https://github.com/powerman/check/actions/workflows/test.yml)
[![Coverage Status](https://raw.githubusercontent.com/powerman/check/gh-badges/coverage.svg)](https://github.com/powerman/check/actions/workflows/test.yml)
[![Release](https://img.shields.io/github/v/release/powerman/check?color=blue)](https://github.com/powerman/check/releases/latest)
[![Go Reference](https://pkg.go.dev/badge/github.com/powerman/check.svg)](https://pkg.go.dev/github.com/powerman/check)

![Linux | amd64 arm64 armv7 ppc64le s390x riscv64](https://img.shields.io/badge/Linux-amd64%20arm64%20armv7%20ppc64le%20s390x%20riscv64-royalblue)
![macOS | amd64 arm64](https://img.shields.io/badge/macOS-amd64%20arm64-royalblue)
![Windows | amd64 arm64](https://img.shields.io/badge/Windows-amd64%20arm64-royalblue)

Helpers to complement Go [testing](https://pkg.go.dev/testing) package.

Write tests with ease and fun!

## Rationale

Plain Go tests force a choice between two extremes:
verbose `if got != want { t.Fatalf(...) }` boilerplate for every comparison,
or reaching for a heavier test framework
that replaces `go test` with its own runner and vocabulary.
This project avoids both:

- It never introduces a new concept - no suites, no custom runner, no dot-import.
  Every wrapped value is still a real `*testing.T`/`*testing.B`/`*testing.F` underneath,
  so `tt.Run`, `tt.Parallel`, `t.Log`, `t.Cleanup`
  and everything else you already know keep working exactly as before.
- Checkers already know what "nil", "equal" or "contains" means for the type you handed them,
  so you rarely write the type-specific comparison yourself: `t.Nil(err)` handles
  typed-nil pointers correctly (see the `Nil` doc comment for the classic gotcha),
  `t.Len(v, 3)` works the same for a map, slice, string, channel or array,
  `t.Err(err, io.EOF)` unwraps and compares by value instead of just by chain membership.
- A failed check prints a full, readable dump of both values plus a text diff,
  so `t.DeepEqual(got, want)` on a whole struct/slice/map actually shows you what's wrong,
  instead of the `got X, want Y` you'd hand-roll around `==`.
  See [Failure Output](#failure-output) below.
- `check.Must()`/`check.New()` let you pick, per test,
  whether a failed check should stop the test (`testify/require`-like)
  or just record the failure and continue (`testify/assert`-like),
  without importing two different packages for that.
- `check.TestMain` adds a per-test and grand-total pass/fail/todo counter to every run,
  so you get a sense of overall test health beyond individual PASS/FAIL lines -
  see the `checks:` lines in [Failure Output](#failure-output).

> [!NOTE]
>
> The first `check` commit dates back to December 2017 —
> a time when [testify](https://github.com/stretchr/testify)
> had seen no activity for five months, with 40+ pull requests piling up
> and the organization's domain parked for sale
> ([issue #526](https://github.com/stretchr/testify/issues/526)).
> testify has since recovered, but `check` was born from the uncertainty
> of that period and took a different approach from the start.

## Features

- Zero required external dependencies.
  Protobuf/gRPC comparison support pulls its (much heavier) dependencies in
  only if you opt into the [companion submodules](#protobuf-grpc-support).
- Compelling output from failed tests:
  - Very easy-to-read dumps for expected and actual values.
  - Same text diff you loved in testify.
- Statistics with amount of passed/failed checks.
- Colored output in terminal.
- 100% compatible with testing package - check package just provides convenient wrappers
  for `*testing.T`/`*testing.B`/`*testing.F` methods without an unusual execution flow
  (see [Non-goals](#non-goals)).
- All checks you may ever need! :)
- Very easy to add your own check functions.
- Concise, handy and consistent API, without dot-import!

## Quickstart

Wrap each (including subtests) `*testing.T`/`*testing.B`/`*testing.F`
using `check.Must()` and write tests as usually with testing package.
Call new methods provided by this package to have more clean/concise test code
and cool dump/diff.

`check.Must()` is the recommended default: it stops the test on the first failed check
(like `testify/require`). Use `check.New()` instead for the softer,
`testify/assert`-like behavior where a failed check doesn't stop the test.

> [!NOTE]
>
> Call `tb.Run()`/`tb.Parallel()` on the original `*testing.T`/`*testing.B`
> before wrapping it with `check.Must()`/`check.New()` —
> these two aren't available on the wrapped value
> (this also satisfies the `paralleltest` linter):

```go
import "github.com/powerman/check"

func TestSomething(tt *testing.T) {
    tt.Parallel()
    t := check.Must(tt)
    t.Equal(2, 2)
    t.Log("You can use new t just like usual *testing.T")
    tt.Run("Subtests/Parallel example", func(tt *testing.T) {
        tt.Parallel()
        t := check.Must(tt)
        t.NotEqual(2, 3, "should not be 3!")
        obj, err := NewObj()
        if t.Nil(err) {
            t.Match(obj.field, `^\d+$`)
        }
    })
}
```

To get optional statistics about executed checkers add:

```go
func TestMain(m *testing.M) { check.TestMain(m) }
```

See the [package examples](https://pkg.go.dev/github.com/powerman/check#pkg-examples)
for more runnable snippets: table-driven subtests, soft checks with `New`, `TODO`,
custom `Should` checkers, `Err`/`ErrIs`/`ErrAs`/`Match` side by side, and `MergeContext`.

### Legacy `check.T()`

`check.T(tt *testing.T) *check.C` is the original, soft-mode by default constructor
kept for backward compatibility - `*check.C` behaves exactly like it always did,
including direct access to the wrapped `*testing.T` via its `T` field.
New code should prefer `check.New()`/`check.Must()`.

## Installation

```sh
go get github.com/powerman/check
```

## Failure Output

Here's what a failed `DeepEqual` looks like (from `testdata/demo/demo_test.go`,
run with `go test -tags demo -v ./testdata/demo/`).
Only `Total` actually differs - `ID`, `Customer` and `Items` match -
so `Diff` singles out the one line that's wrong
instead of making you eyeball two full dumps for what changed.
The `checks:` lines at the end are `check.TestMain`'s pass/fail/todo counters
(one passing `Equal` plus this failing `DeepEqual`):

```text
=== RUN   TestDemoFailure
    demo_test.go:41: order total should match after checkout
        Checker:  DeepEqual
        Expected: (demo.Order) {
          ID: (string) (len=3) "A-1",
          Customer: (string) (len=3) "Ann",
          Total: (int) 40,
          Items: ([]string) (len=2) {
            (string) (len=3) "pen",
            (string) (len=3) "cup"
          }
        }
        Actual:   (demo.Order) {
          ID: (string) (len=3) "A-1",
          Customer: (string) (len=3) "Ann",
          Total: (int) 42,
          Items: ([]string) (len=2) {
            (string) (len=3) "pen",
            (string) (len=3) "cup"
          }
        }

        Diff:
        --- Expected
        +++ Actual
        @@ -3,3 +3,3 @@
           Customer: (string) (len=3) "Ann",
        -  Total: (int) 40,
        +  Total: (int) 42,
           Items: ([]string) (len=2) {

--- FAIL: TestDemoFailure (0.00s)
  checks:  1 passed          1 failed	TestDemoFailure
  checks:  1 passed  0 todo  1 failed	(total)
```

With a color terminal (see `doc.go` for the `FORCE_COLOR`/`NO_COLOR` environment variables)
the same failure looks like this:

![Colored failure output](.github/assets/demo-failure.png)

## Custom Checkers

You can extend `DeepEqual`/`NotDeepEqual` and `Err`/`NotErr`
with custom comparison logic via `RegisterEqualChecker` and `RegisterErrChecker`.

- This package enables [validator](https://github.com/go-playground/validator)
  `FieldError` and `[]FieldError` comparison by `Namespace()`+`Tag()`
  via `check.Err`/`check.NotErr`.

### Protobuf / gRPC Support

Protobuf message comparison and gRPC status error comparison have been extracted
into separate modules to keep the core dependency-light:

- **[checkproto](https://github.com/powerman/checkproto)** — enables
  `proto.Equal` via `check.DeepEqual`/`check.NotDeepEqual` for protobuf messages.
- **[checkgrpc](https://github.com/powerman/checkgrpc)** — enables
  gRPC status comparison via `check.Err`/`check.NotErr`.
  It also imports checkproto, so a single blank import covers both.

Usage: just add a blank import in your test file or `TestMain`:

```go
import _ "github.com/powerman/checkgrpc"
```

## Comparison

A few honest notes on how check compares to other assertion libraries,
so you can pick the right one instead of the one you found first.

### vs [testify](https://github.com/stretchr/testify)

testify's `assert`/`require` packages solve the same problem:
convenience wrappers around `*testing.T` with a soft/hard mode split,
and (via `assert.New(t)`/`require.New(t)`) a method-style API too,
so that's not a real difference. Where check does differ:

- Argument order: check and go-quicktest/qt put the actual value first,
  matching `if got != want` (`t.Equal(got, want)`)
  and the `got = %v, want %v` shape of Go's own idiomatic test failure messages.
  testify and shoenig/test put the expected value first instead
  (`assert.Equal(t, want, got)`, `must.Eq(t, want, got)`),
  which only really makes sense if you're already used to it:
  `got` is usually a separate variable set by calling the code under test,
  often on its own long line, while `want` is often a short literal written inline -
  `want, got` order buries the value to check at the end of the call.
- Dump + diff is the default failure output, not an opt-in - you don't need
  `assert.EqualExportedValues` or a separate diff helper to get a readable struct comparison.
- No suite package, no mock package - check stays a pure assertion/checker library.
  Use `testify/mock` (or anything else) alongside it if you need mocks.

A few UX differences side by side:

- Error is nil: `t.Nil(err)` vs `assert.NoError(t, err)` or `assert.Nil(t, err)` -
  two names for one idea.
- Error unwraps to & value-equals a sentinel/custom error: `t.Err(err, io.EOF)` vs
  no direct equivalent - `assert.ErrorIs` only checks chain membership,
  not value equality of a freshly-constructed error.
- Length of a map/slice/string/channel: `t.Len(v, 3)` vs `assert.Len(t, v, 3)`,
  but `len == 0` needs the separate `assert.Empty`/`NotEmpty`.

check does not cover 100% of testify's `assert`/`require` surface.
Beyond `Eventually`/`Never` and the HTTP handler helpers
(deliberately left out, see [Non-goals](#non-goals)),
testify's `IsIncreasing`/`IsDecreasing`/`IsNonIncreasing`/`IsNonDecreasing`
(sequence monotonicity) and `YAMLEq` have no check equivalent - not deliberately,
just not needed yet. (Open an issue if you need them.)
Everything else (`Same`, `EqualValues`, `Positive`, `Negative`, ...)
is one line via an existing checker
(`t.Equal` already compares pointers by identity, `t.Greater(x, 0)` covers `Positive`).

### vs [go-quicktest/qt](https://github.com/go-quicktest/qt) and [shoenig/test](https://github.com/shoenig/test)

go-quicktest/qt and shoenig/test are newer, generics-first libraries:
`qt.Assert(t, got, qt.Equals(want))` and `must.Eq(t, want, got)`
are package-level generic functions, so a type mistake (comparing `int` to `int32`)
is often a compile error instead of a runtime panic or failed check.

In practice that payoff is smaller than it sounds: a type mistake fails the test either way,
the only question is whether you see it as a `go build`/`go vet` error
before running `go test` (qt/shoenig/test) or as a panic/failed check while it runs (check) -
not whether it's caught.
check is deliberately not generic for a more concrete reason:
part of its convenience only works with `any`
(`Match` accepts string/`[]byte`/error/`fmt.Stringer`; `Equal` special-cases `time.Time`),
and Go doesn't yet support generic methods,
so a generic `check.TB` isn't possible without splitting the API into free functions.
Pick qt or shoenig/test if you want compile-time typed assertions as package functions;
pick check if you want a method-style API and check's dump/diff by default.

### vs [gotest.tools/v3](https://github.com/gotestyourself/gotest.tools)

`gotest.tools/v3/assert` is close in spirit
(wraps `*testing.T`-style helpers, diffs with `go-cmp`)
but keeps the package-function shape
(`assert.Equal(t, x, y)`, `assert.DeepEqual(t, x, y, opts...)`)
and leans on go-cmp's option system for custom comparisons,
where check uses a small `RegisterEqualChecker`/`RegisterErrChecker` registry instead.
If you already rely on go-cmp's options (unexported fields, custom comparers, ...),
it plugs into check just as easily: register it once with
`check.RegisterEqualChecker(func(a, b any) (bool, bool) { return cmp.Equal(a, b), true })`
to make it check's default, or call it ad hoc with `t.True(cmp.Equal(got, want))`
(no dump/diff for that one call, but full access to go-cmp's own options).

## Non-goals

- No BDD/suites - check stays inside `go test`, `t.Run` and `t.Parallel`;
  see [Rationale](#rationale).
- No `Eventually`/`Never` polling helpers - Go's `testing/synctest`
  covers that class of test better (deterministic virtual time, no flaky sleeps).
- No HTTP handler assertions (testify's `HTTPSuccess`/`HTTPRedirect`/`HTTPBodyContains`/...) -
  `net/http/httptest` plus check's own checkers already cover that ground, e.g.
  `t.Match(rec.Body.String(), pattern)` or `t.Equal(rec.Code, http.StatusOK)`.
- No mocking - pair check with whatever mocking library you already use.

## TODO

- Questionable:
  - [ ] Provide a way to force binary dump for utf8.Valid `string`/`[]byte`?
  - [ ] Count skipped tests (will have to overload `Skip`, `Skipf`, `SkipNow`)?
- Complicated:
  - [ ] Show line of source_test.go with failed test.
