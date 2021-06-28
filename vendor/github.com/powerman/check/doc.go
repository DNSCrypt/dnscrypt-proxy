// Package check provide helpers to complement Go testing package.
//
// Features
//
// This package is like testify/assert on steroids. :)
//
//   - Compelling output from failed tests:
//     - Very easy-to-read dumps for expected and actual values.
//     - Same text diff you loved in testify/assert.
//     - Also visual diff in GoConvey web UI, if you use it (recommended).
//   - Statistics with amount of passed/failed checks.
//   - Colored output in terminal.
//   - 100% compatible with testing package - check package just provide
//     convenient wrappers for *testing.T methods and doesn't introduce
//     new concepts like BDD, custom test suite or unusual execution flow.
//   - All checks you may ever need! :)
//   - Very easy to add your own check functions.
//   - Concise, handy and consistent API, without dot-import!
//
// Quickstart
//
// Just wrap each (including subtests) *testing.T using check.T() and write
// tests as usually with testing package. Call new methods provided by
// this package to have more clean/concise test code and cool dump/diff.
//
//	import "github.com/powerman/check"
//
//	func TestSomething(tt *testing.T) {
//		t := check.T(tt)
//		t.Equal(2, 2)
//		t.Log("You can use new t just like usual *testing.T")
//		t.Run("Subtests/Parallel example", func(tt *testing.T) {
//			t := check.T(tt)
//			t.Parallel()
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
// When use goconvey tool, to get nice diff in web UI add:
//
//	import _ "github.com/smartystreets/goconvey/convey"
//
// Hints
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
//	t.Match(err, "file.*permission")
//
//	// Use Equal ONLY when checking for same instance:
//	t.Equal(io.EOF, io.EOF)                // this works
//	t.Equal(io.EOF, errors.New("EOF"))     // this doesn't work!
//	t.Err(io.EOF, errors.New("EOF"))       // this works
//	t.DeepEqual(io.EOF, errors.New("EOF")) // this works too
//
// ★ Each check returns bool, so you can easily skip problematic code:
//
//	if t.Nil(err) {
//		t.Match(obj.field, `^\d+$`)
//	}
//
// ★ You can turn any check into assertion to stop test immediately:
//
//	t.Must(t.Nil(err))
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
// Should checker, it'll let you plug in your own checker with ease.
//
// ★ It will panic when called with arg of wrong type - because this
// means bug in your test.
//
// ★ If you don't see colors in `go test` output it may happens because of
// two reasons: either your $TERM doesn't contain substring "color" or
// you're running `go test path/to/your/package`. To force colored output
// in last case just set this environment variable:
//
//	export GO_TEST_COLOR=1
//
// Contents
//
// There are few special functions (assertion, custom checkers, etc.).
//
//	Error
//	Must
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
//
//	HasType         NotHasType
//	Implements      NotImplements
//
//	Panic           NotPanic
//	PanicMatch      PanicNotMatch
package check
