// Package check provide helpers to complement Go testing package.
//
// # Features
//
// This package is like testify/assert on steroids. :)
//
//   - Compelling output from failed tests:
//   - Very easy-to-read dumps for expected and actual values.
//   - Same text diff you loved in testify/assert.
//   - Statistics with amount of passed/failed checks.
//   - Colored output in terminal.
//   - 100% compatible with testing package - check package just provide
//     convenient wrappers for [*testing.T] methods and doesn't introduce
//     new concepts like BDD, custom test suite or unusual execution flow.
//   - All checks you may ever need! :)
//   - Very easy to add your own check functions.
//   - Concise, handy and consistent API, without dot-import!
//
// # Quickstart
//
// Wrap each (including subtests) [*testing.T]/[*testing.B]/[*testing.F]
// using [Must] and write tests as usually with testing package.
// Call new methods provided by this package to have more clean/concise test code
// and cool dump/diff.
//
// [Must] stops the test on the first failed check (like testify/require).
// Use [New] instead for the softer, testify/assert-like behavior
// where a failed check doesn't stop the test.
//
//	import "github.com/powerman/check"
//
//	func TestSomething(tt *testing.T) {
//		tt.Parallel()
//		t := check.Must(tt)
//		t.Equal(2, 2)
//		t.Log("You can use new t just like usual *testing.T")
//		tt.Run("Subtests/Parallel example", func(tt *testing.T) {
//			tt.Parallel()
//			t := check.Must(tt)
//			t.NotEqual(2, 3, "should not be 3!")
//			obj, err := NewObj()
//			if t.Nil(err) {
//				t.Match(obj.field, `^\d+$`)
//			}
//		})
//	}
//
// To get optional statistics about executed checkers add:
//
//	func TestMain(m *testing.M) { check.TestMain(m) }
//
// [TB] (returned by [New]/[Must]) doesn't provide Run/Parallel:
// call tb.Run()/tb.Parallel() on the original
// [*testing.T]/[*testing.B]/[*testing.F] before wrapping it
// (this also satisfies the paralleltest linter).
//
// [C] (returned by the legacy [T]) is a soft-mode by default,
// [*testing.T]-only compatibility shell kept for old code:
// it behaves exactly like it always did,
// including direct access to the wrapped [*testing.T] via its T field,
// and does provide Run/Parallel. New code should prefer [New]/[Must].
//
// # Hints
//
// ★ How to check for errors:
//
//	// If you just want nil:
//	t.Nil(err)
//	t.Err(err, nil)
//
//	// Check for (absence of) concrete (possibly wrapped) error:
//	t.Err(err, io.EOF)
//	t.NotErr(err, io.EOF) // nil is not io.EOF, so it's ok too
//
//	// When need to match by error's text:
//	t.Match(err, `file.*permission`)
//
//	// Use Equal ONLY when checking for same instance:
//	t.Equal(io.EOF, io.EOF)                // this works
//	t.Equal(io.EOF, errors.New("EOF"))     // this doesn't work!
//	t.Err(io.EOF, errors.New("EOF"))       // this works
//	t.DeepEqual(io.EOF, errors.New("EOF")) // this works too
//
//	// ErrIs/ErrAs are pure errors.Is/errors.As wrappers:
//	t.ErrIs(err, io.EOF)            // errors.Is(err, io.EOF)
//	t.ErrAs(err, &targetType)       // errors.As(err, &targetType)
//
// When to use which:
//
//   - Err    — same type and value (unwraps to root, compares by value),
//     support for extra custom error types (e.g. gRPC status or validator.FieldError)
//   - ErrIs  — standard [errors.Is] (not value comparison)
//   - ErrAs  — extract the first matching error type
//   - Match  — check by error text against a regexp
//
// ★ Each check returns bool, so you can easily skip problematic code:
//
//	if t.Nil(err) {
//		t.Match(obj.field, `^\d+$`)
//	}
//
// ★ You can turn any soft ([New], legacy [T]) check into assertion to stop test immediately:
//
//	t.Must(t.Nil(err))
//
// ★ You can turn all soft checks into assertions to stop test immediately (or just use [Must]):
//
//	t = t.MustAll()
//	t.Nil(err)
//
// ★ You can provide extra description to each check:
//
//	t.Equal(got, want, "Just msg: will Print(), % isn't special")
//	t.Equal(got, want, "Msg with args: will Printf(): %v", extra)
//
// ★ There are short synonyms for checks implementing usual ==, !=, etc.:
//
//	t.EQ(got, want) // same as t.Equal
//	t.NE(got, want) // same as t.NotEqual
//	t.LT(got, want) // same as t.Less
//	t.LE(got, want) // same as t.LessOrEqual
//	t.GT(got, want) // same as t.Greater
//	t.GE(got, want) // same as t.GreaterOrEqual
//
// ★ If you need custom check, which isn't available out-of-box - see
// [Should] checker, it'll let you plug in your own checker with ease.
//
// ★ It will panic when called with arg of wrong type - because this
// means bug in your test.
//
// ★ If you don't see colors in `go test` output it may happen because
// either you're not running in a terminal or your $TERM is set to "dumb"
// (or empty). To force colored output set one of these variables:
//
//	export FORCE_COLOR=1
//	export CLICOLOR_FORCE=1
//	export GO_TEST_COLOR=1
//
// To disable colors (overrides all other variables):
//
//	export NO_COLOR=1
//
// ★ With the legacy [T] (whose [C] does provide Run/Parallel),
// if you use t.Parallel() inside a subtest,
// prefer calling tt.Parallel() on the original *[testing.T] before wrapping with check.T() —
// this satisfies the paralleltest linter:
//
//	t.Run("subtest", func(tt *testing.T) {
//		tt.Parallel()
//		t := check.T(tt)
//		t.Equal(2, 2)
//	})
//
// ★ Inject an application base context (e.g. one carrying a slog handler)
// into a test on top of the per-test cancellation/deadline
// [testing.TB.Context] already provides:
//
//	t := check.Must(tt).MergeContext(appCtx)
//	t.Context() // merged values and cancellation from both contexts
//
// ★ Enable Protobuf message comparison and gRPC status error comparison by:
//
//	import _ "github.com/powerman/checkgrpc"
//
// This enables proto.Equal for protobuf messages in [DeepEqual]/[NotDeepEqual]
// and gRPC status comparison in [Err]/[NotErr].
//
// # Contents
//
// Constructors:
//
//	New   Must   T
//
// Other special methods (assertion, context, custom checkers, etc.).
//
//	Context   MergeContext
//	Error     Errorf
//	Fatal     Fatalf
//	Fail      FailNow
//	Must      MustAll
//	Should
//	TODO
//
// Everything else are just trivial (mostly) checkers which works in
// obvious way and accept values of any types which makes sense (and
// panics on everything else).
//
//	Nil             NotNil
//	Zero            NotZero
//	True            False
//
//	Equal           NotEqual           EQ  NE
//	DeepEqual       NotDeepEqual
//	Err             NotErr
//	ErrIs           NotErrIs
//	ErrAs           NotErrAs
//	BytesEqual      NotBytesEqual
//	JSONEqual
//
//	Greater         LessOrEqual        GT  LE
//	Less            GreaterOrEqual     LT  GE
//	Between         NotBetween
//	BetweenOrEqual  NotBetweenOrEqual
//	InDelta         NotInDelta
//	InSMAPE         NotInSMAPE
//
//	Len             NotLen
//	Match           NotMatch
//	HasPrefix       NotHasPrefix
//	HasSuffix       NotHasSuffix
//	HasKey          NotHasKey
//	Contains        NotContains
//	SortEqual       NotSortEqual
//	Subset          NotSubset
//
//	HasType         NotHasType
//	Implements      NotImplements
//
//	FileExists      NotFileExists
//	DirExists       NotDirExists
//
//	Panic           NotPanic
//	PanicMatch      PanicNotMatch
package check
