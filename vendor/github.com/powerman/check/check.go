package check

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/powerman/check/internal/deepequal"
)

//nolint:gochecknoglobals // Const.
var (
	typString  = reflect.TypeFor[string]()
	typBytes   = reflect.TypeFor[[]byte]()
	typFloat64 = reflect.TypeFor[float64]()
)

// C wraps [*testing.T] to make it convenient to call checkers in test.
type C struct {
	// C is a thin [*testing.T]-only compatibility shell built on the same machinery as [TB]:
	// it embeds [*testing.T] (its sole, unambiguous [testing.TB] source -
	// so Helper/Cleanup/Log/... and friends stay genuinely zero-cost)
	// and *checks (which provides the wide checker API for free
	// and never collides with [*testing.T]'s own method names).
	// Error, Errorf, Fatal, Fatalf, Fail, FailNow and Context are the one exception:
	// check needs to intercept them (for statistics/TODO/Must and the merged Context),
	// so each gets a short explicit override below - direct declarations always win
	// over promoted ones, so this doesn't reintroduce any ambiguity.
	*checks
	*testing.T
}

const (
	nameActual   = "Actual"
	nameExpected = "Expected"
)

var _ testing.TB = (*C)(nil)

// T creates and returns new *C, which wraps given tt and supposed to be
// used inplace of it, providing you with access to many useful helpers in
// addition to standard methods of [*testing.T].
//
// It's convenient to rename Test function's arg from t to something
// else, create wrapped variable with usual name t and use only t:
//
//	func TestSomething(tt *testing.T) {
//		t := check.T(tt)
//		// use only t in test and don't touch tt anymore
//	}
//
// T is a soft-mode, [*testing.T]-only legacy constructor kept for backward compatibility.
// For new tests prefer [Must], which also works with [*testing.B] and [*testing.F].
func T(tt *testing.T) *C { //nolint:thelper // With check we name it tt!
	return &C{checks: &checks{tb: tt}, T: tt}
}

// TODO is like [TB.TODO], but keeps working with *C and [*testing.T].
func (t *C) TODO() *C {
	return &C{checks: t.withTODO(), T: t.T}
}

// MustAll is like [TB.MustAll], but keeps working with *C and [*testing.T].
func (t *C) MustAll() *C {
	return &C{checks: t.withMustAll(), T: t.T}
}

// Context returns the context associated with t:
// the context merged in by the most recent [C.MergeContext] call if any,
// otherwise the standard [*testing.T.Context]().
func (t *C) Context() context.Context {
	return t.context()
}

// MergeContext is like [TB.MergeContext], but keeps working with *C and [*testing.T].
func (t *C) MergeContext(ctx context.Context) *C {
	merged, cancel := t.mergeContext(ctx)
	t.Cleanup(cancel)
	return &C{checks: merged, T: t.T}
}

// Error is equivalent to Log followed by Fail.
//
// It is like t.Errorf with TODO() and statistics support.
func (t *C) Error(args ...any) {
	t.Helper()
	t.report0(args, false)
}

// Errorf is equivalent to Logf followed by Fail.
//
// It is like t.Errorf with TODO() and statistics support.
func (t *C) Errorf(format string, args ...any) {
	t.Helper()
	t.report0(append([]any{format}, args...), false)
}

// Fatal is equivalent to Log followed by FailNow.
//
// It is like t.Fatal with TODO() and statistics support.
func (t *C) Fatal(args ...any) {
	t.Helper()
	t.report0(args, false)
	if !t.todo {
		t.T.FailNow() // Already counted above: bypass the counting FailNow wrapper.
	}
}

// Fatalf is equivalent to Logf followed by FailNow.
//
// It is like t.Fatalf with TODO() and statistics support.
func (t *C) Fatalf(format string, args ...any) {
	t.Helper()
	t.report0(append([]any{format}, args...), false)
	if !t.todo {
		t.T.FailNow() // Already counted above: bypass the counting FailNow wrapper.
	}
}

// Fail marks the function as having failed but continues execution.
//
// Unlike plain [*testing.T.Fail], calling it directly (rather than through a checker)
// is still counted in check's pass/fail statistics.
func (t *C) Fail() {
	t.fail()
	t.T.Fail()
}

// FailNow marks the function as having failed and stops its execution.
//
// Unlike plain [*testing.T.FailNow], calling it directly (rather than through a checker)
// is still counted in check's pass/fail statistics.
func (t *C) FailNow() {
	t.fail()
	t.T.FailNow()
}

// Should is like [TB.Should], but keeps working with *C and [*testing.T].
//
// [ShouldFunc1]/[ShouldFunc2] callbacks always receive a *[TB] (never *C):
// there's only one pair of callback types, shared by TB and C alike.
func (t *C) Should(anyShouldFunc any, args ...any) bool {
	t.Helper()
	tb := &TB{TB: t.T, checks: t.checks}
	switch f := anyShouldFunc.(type) {
	case func(t *TB, actual any) bool:
		return tb.should1(f, args...)
	case func(t *TB, actual, expected any) bool:
		return tb.should2(f, args...)
	default:
		panic("anyShouldFunc is not a ShouldFunc1 or ShouldFunc2")
	}
}

// Nil checks for actual == nil.
//
// There is one subtle difference between this check and Go `== nil` (if
// this surprises you then you should read
// https://golang.org/doc/faq#nil_error first):
//
//	var intPtr *int
//	var empty interface{}
//	var notEmpty interface{} = intPtr
//	t.True(intPtr == nil)   // TRUE
//	t.True(empty == nil)    // TRUE
//	t.True(notEmpty == nil) // FALSE
//
// When you call this function your actual value will be stored in
// interface{} argument, and this makes any typed nil pointer value `!=
// nil` inside this function (just like in example above happens with
// notEmpty variable).
//
// As it is very common case to check some typed pointer using Nil this
// check has to work around and detect nil even if usual `== nil` return
// false. But this has nasty side effect: if actual value already was of
// interface type and contains some typed nil pointer (which is usually
// bad thing and should be avoid) then Nil check will pass (which may be
// not what you want/expect):
//
//	t.Nil(nil)              // TRUE
//	t.Nil(intPtr)           // TRUE
//	t.Nil(empty)            // TRUE
//	t.Nil(notEmpty)         // WARNING: also TRUE!
//
// Second subtle case is less usual: uintptr(0) is sorta nil, but not
// really, so Nil(uintptr(0)) will fail. Nil(unsafe.Pointer(nil)) will
// also fail, for the same reason. Please do not use this and consider
// this behaviour undefined, because it may change in the future.
func (t *checks) Nil(actual any, msg ...any) bool {
	t.tb.Helper()
	return t.report1(actual, msg,
		isNil(actual))
}

func isNil(actual any) bool {
	switch val := reflect.ValueOf(actual); val.Kind() {
	case reflect.Invalid:
		return actual == nil
	case reflect.Chan, reflect.Func, reflect.Map, reflect.Pointer, reflect.Slice:
		return val.IsNil()
	case reflect.Uintptr, reflect.UnsafePointer, // Subtle cases documented above.
		reflect.Interface, // ???
		// Can't be nil:
		reflect.Struct, reflect.Array, reflect.Bool, reflect.String,
		reflect.Complex128, reflect.Complex64, reflect.Float32, reflect.Float64,
		reflect.Int, reflect.Int16, reflect.Int32, reflect.Int64, reflect.Int8,
		reflect.Uint, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uint8:
	}
	return false
}

// NotNil checks for actual != nil.
//
// See Nil about subtle case in check logic.
func (t *checks) NotNil(actual any, msg ...any) bool {
	t.tb.Helper()
	return t.report0(msg,
		!isNil(actual))
}

// True checks for cond == true.
//
// This can be useful to use your own custom checks, but this way you
// won't get nice dump/diff for actual/expected values. You'll still have
// statistics about passed/failed checks and it's shorter than usual:
//
//	if !cond {
//		t.Errorf(msg...)
//	}
func (t *checks) True(cond bool, msg ...any) bool {
	t.tb.Helper()
	return t.report0(msg,
		cond)
}

// False checks for cond == false.
func (t *checks) False(cond bool, msg ...any) bool {
	t.tb.Helper()
	return t.report0(msg,
		!cond)
}

// Equal checks for actual == expected.
//
// Note: For [time.Time] it uses actual.Equal(expected) instead.
func (t *checks) Equal(actual, expected any, msg ...any) bool {
	t.tb.Helper()
	return t.report2(actual, expected, msg,
		isEqual(actual, expected))
}

func isEqual(actual, expected any) bool {
	switch actual := actual.(type) {
	case time.Time:
		return actual.Equal(expected.(time.Time))
	default:
		return actual == expected
	}
}

// EQ is a synonym for Equal.
func (t *checks) EQ(actual, expected any, msg ...any) bool {
	t.tb.Helper()
	return t.Equal(actual, expected, msg...)
}

// NotEqual checks for actual != expected.
func (t *checks) NotEqual(actual, expected any, msg ...any) bool {
	t.tb.Helper()
	return t.report2(actual, expected, msg,
		!isEqual(actual, expected))
}

// NE is a synonym for NotEqual.
func (t *checks) NE(actual, expected any, msg ...any) bool {
	t.tb.Helper()
	return t.NotEqual(actual, expected, msg...)
}

// BytesEqual checks for [bytes.Equal](actual, expected).
//
// Hint: BytesEqual([]byte{}, []byte(nil)) is true (unlike DeepEqual).
func (t *checks) BytesEqual(actual, expected []byte, msg ...any) bool {
	t.tb.Helper()
	return t.report2(actual, expected, msg,
		bytes.Equal(actual, expected))
}

// NotBytesEqual checks for !bytes.Equal(actual, expected).
//
// Hint: NotBytesEqual([]byte{}, []byte(nil)) is false (unlike NotDeepEqual).
func (t *checks) NotBytesEqual(actual, expected []byte, msg ...any) bool {
	t.tb.Helper()
	return t.report1(actual, msg,
		!bytes.Equal(actual, expected))
}

// hasMethod reports whether v has a method with the given name.
func hasMethod(v any, name string) bool {
	t := reflect.TypeOf(v)
	if t == nil {
		return false
	}
	_, found := t.MethodByName(name)
	return found
}

// DeepEqual checks for [deepequal.DeepEqual](actual, expected).
// It will use Equal method for types which implements it
// (e.g. [time.Time], decimal.Decimal, etc.).
//
// Custom equal checkers registered via [RegisterEqualChecker] run first.
func (t *checks) DeepEqual(actual, expected any, msg ...any) bool {
	t.tb.Helper()
	equal, claimed := runEqualCheckers(actual, expected)
	if !claimed {
		if hasMethod(actual, "ProtoReflect") || hasMethod(expected, "ProtoReflect") {
			panic("check: protobuf message detected; " +
				"import github.com/powerman/checkproto to compare protobuf messages")
		}
		equal = deepequal.DeepEqual(actual, expected)
	}
	return t.report2(actual, expected, msg, equal)
}

// NotDeepEqual checks for ![deepequal.DeepEqual](actual, expected).
// It will use Equal method for types which implements it
// (e.g. [time.Time], decimal.Decimal, etc.).
//
// Custom equal checkers registered via [RegisterEqualChecker] run first.
func (t *checks) NotDeepEqual(actual, expected any, msg ...any) bool {
	t.tb.Helper()
	equal, claimed := runEqualCheckers(actual, expected)
	if claimed {
		return t.report1(actual, msg, !equal)
	}
	if hasMethod(actual, "ProtoReflect") || hasMethod(expected, "ProtoReflect") {
		panic("check: protobuf message detected; " +
			"import github.com/powerman/checkproto to compare protobuf messages")
	}
	return t.report1(actual, msg,
		!deepequal.DeepEqual(actual, expected))
}

// Match checks for regex.MatchString(actual).
//
// Regex type can be either [*regexp.Regexp] or string.
//
// Actual type can be:
//   - string       - will match with actual
//   - []byte       - will match with string(actual)
//   - []rune       - will match with string(actual)
//   - [fmt.Stringer] - will match with actual.String()
//   - error        - will match with actual.Error()
//   - nil          - will not match (even with empty regex)
func (t *checks) Match(actual, regex any, msg ...any) bool {
	t.tb.Helper()
	ok := isMatch(&actual, regex)
	return t.report2(actual, regex, msg,
		ok)
}

// isMatch updates actual to be a real string used for matching, to make
// dump easier to understand, but this result in losing type information.
func isMatch(actual *any, regex any) bool {
	if *actual == nil {
		return false
	}
	if !stringify(actual) {
		panic("actual is not a string, []byte, []rune, fmt.Stringer, error or nil")
	}
	s := (*actual).(string) //nolint:forcetypeassert // False positive.

	switch v := regex.(type) {
	case *regexp.Regexp:
		return v.MatchString(s)
	case string:
		return regexp.MustCompile(v).MatchString(s)
	}
	panic("regex is not a *regexp.Regexp or string")
}

func stringify(arg *any) bool {
	switch v := (*arg).(type) {
	case nil:
		return false
	case error:
		*arg = v.Error()
	case fmt.Stringer:
		*arg = v.String()
	default:
		typ := reflect.TypeOf(*arg)
		switch typ.Kind() { //nolint:exhaustive // Covered by default case.
		case reflect.String:
		case reflect.Slice:
			switch typ.Elem().Kind() { //nolint:exhaustive // Covered by default case.
			case reflect.Uint8, reflect.Int32:
			default:
				return false
			}
		default:
			return false
		}
		*arg = reflect.ValueOf(*arg).Convert(typString).Interface()
	}
	return true
}

// NotMatch checks for !regex.MatchString(actual).
//
// See Match about supported actual/regex types and check logic.
func (t *checks) NotMatch(actual, regex any, msg ...any) bool {
	t.tb.Helper()
	ok := !isMatch(&actual, regex)
	return t.report2(actual, regex, msg,
		ok)
}

// Contains checks is actual contains substring/element expected.
//
// Element of array/slice/map is checked using == expected.
//
// Type of expected depends on type of actual:
//   - if actual is a string, then expected should be a string
//   - if actual is an array, then expected should have array's element type
//   - if actual is a slice,  then expected should have slice's element type
//   - if actual is a map,    then expected should have map's value type
//
// Hint: In a map it looks for a value, if you need to look for a key -
// use HasKey instead.
func (t *checks) Contains(actual, expected any, msg ...any) bool {
	t.tb.Helper()
	return t.report2(actual, expected, msg,
		isContains(actual, expected))
}

func isContains(actual, expected any) (found bool) {
	switch valActual := reflect.ValueOf(actual); valActual.Kind() { //nolint:exhaustive // Covered by default case.
	case reflect.String:
		strActual := valActual.Convert(typString).Interface().(string) //nolint:forcetypeassert // False positive.
		valExpected := reflect.ValueOf(expected)
		if valExpected.Kind() != reflect.String {
			panic("expected underlying type is not a string")
		}
		strExpected := valExpected.Convert(typString).Interface().(string) //nolint:forcetypeassert // False positive.
		found = strings.Contains(strActual, strExpected)

	case reflect.Map:
		if valActual.Type().Elem() != reflect.TypeOf(expected) {
			panic("expected type not match actual element type")
		}
		keys := valActual.MapKeys()
		for i := 0; i < len(keys) && !found; i++ {
			found = valActual.MapIndex(keys[i]).Interface() == expected
		}

	case reflect.Slice, reflect.Array:
		if valActual.Type().Elem() != reflect.TypeOf(expected) {
			panic("expected type not match actual element type")
		}
		for i := 0; i < valActual.Len() && !found; i++ {
			found = valActual.Index(i).Interface() == expected
		}

	default:
		panic("actual is not a string, array, slice or map")
	}
	return found
}

// NotContains checks is actual not contains substring/element expected.
//
// See Contains about supported actual/expected types and check logic.
func (t *checks) NotContains(actual, expected any, msg ...any) bool {
	t.tb.Helper()
	return t.report2(actual, expected, msg,
		!isContains(actual, expected))
}

// HasKey checks is actual has key expected.
func (t *checks) HasKey(actual, expected any, msg ...any) bool {
	t.tb.Helper()
	return t.report2(actual, expected, msg,
		hasKey(actual, expected))
}

func hasKey(actual, expected any) bool {
	return reflect.ValueOf(actual).MapIndex(reflect.ValueOf(expected)).IsValid()
}

// NotHasKey checks is actual has no key expected.
func (t *checks) NotHasKey(actual, expected any, msg ...any) bool {
	t.tb.Helper()
	return t.report2(actual, expected, msg,
		!hasKey(actual, expected))
}

// Zero checks is actual is zero value of it's type.
func (t *checks) Zero(actual any, msg ...any) bool {
	t.tb.Helper()
	return t.report1(actual, msg,
		isZero(actual))
}

func isZero(actual any) bool {
	if isNil(actual) {
		return true
	} else if typ := reflect.TypeOf(actual); typ.Comparable() {
		// Not Func, Map, Slice, Array with non-comparable
		// elements, Struct with non-comparable fields.
		return actual == reflect.Zero(typ).Interface()
	} else if typ.Kind() == reflect.Array {
		zero := true
		val := reflect.ValueOf(actual)
		for i := 0; i < val.Len() && zero; i++ {
			zero = isZero(val.Index(i).Interface())
		}
		return zero
	}
	// Func, Struct with non-comparable fields.
	// Non-nil Map, Slice.
	return false
}

// NotZero checks is actual is not zero value of it's type.
func (t *checks) NotZero(actual any, msg ...any) bool {
	t.tb.Helper()
	return t.report1(actual, msg,
		!isZero(actual))
}

// Len checks is len(actual) == expected.
func (t *checks) Len(actual any, expected int, msg ...any) bool {
	t.tb.Helper()
	l := reflect.ValueOf(actual).Len()
	return t.report2(l, expected, msg,
		l == expected)
}

// NotLen checks is len(actual) != expected.
func (t *checks) NotLen(actual any, expected int, msg ...any) bool {
	t.tb.Helper()
	l := reflect.ValueOf(actual).Len()
	return t.report2(l, expected, msg,
		l != expected)
}

// Err checks is actual error is the same as expected error.
//
// Custom error checkers registered via [RegisterErrChecker] run first.
// If none claims the pair the built-in comparison operates on the
// original error found by recursively unwrapping actual with
// [errors.Unwrap]() and [github.com/pkg/errors.Cause]()
// (multi-error takes only the first),
// and then compares it using Equal() method or same type and value ([deepequal.DeepEqual]),
// so they may be different instances, but must have the same type and value.
//
// If both of these fail the comparison falls back to [errors.Is]()
// on the original actual (not the unwrapped one).
//
// Checking for nil is okay, but using Nil(actual) instead is more clean.
func (t *checks) Err(actual, expected error, msg ...any) bool {
	t.tb.Helper()
	equal, claimed := runCheckers(actual, expected)
	if !claimed {
		actual2 := unwrapErr(actual)
		if hasMethod(actual2, "GRPCStatus") || hasMethod(expected, "GRPCStatus") {
			panic("check: gRPC status error detected; " +
				"import github.com/powerman/checkgrpc to compare gRPC status errors")
		}
		equal = reflect.TypeOf(actual2) == reflect.TypeOf(expected) &&
			deepequal.DeepEqual(actual2, expected)
	}
	if !equal {
		equal = errors.Is(actual, expected)
	}
	return t.report2(actual, expected, msg, equal)
}

// cause replicates github.com/pkg/errors.Cause using duck typing,
// to support that (archived) package without depending on it.
func cause(err error) error {
	for err != nil {
		c, ok := err.(interface{ Cause() error })
		if !ok {
			break
		}
		err = c.Cause()
	}
	return err
}

func unwrapErr(err error) (actual error) {
	defer func() { _ = recover() }()
	actual = err
	for {
		actual = cause(actual)
		var unwrapped error
		switch wrapped := actual.(type) { //nolint:errorlint // False positive.
		case interface{ Unwrap() error }:
			unwrapped = wrapped.Unwrap()
		case interface{ Unwrap() []error }:
			unwrappeds := wrapped.Unwrap()
			if len(unwrappeds) > 0 {
				unwrapped = unwrappeds[0]
			}
		}
		if unwrapped == nil {
			break
		}
		actual = unwrapped
	}
	return actual
}

// NotErr checks is actual error is not the same as expected error.
//
// It tries to recursively unwrap actual before checking using
// [errors.Unwrap]() and [github.com/pkg/errors.Cause]().
// In case of multi-error (Unwrap() []error) it use only first error.
//
// They must have either different types or values (or one should be nil).
// Different instances with same type and value will be considered the
// same error, and so is both nil.
//
// Finally it'll use ![errors.Is]().
func (t *checks) NotErr(actual, expected error, msg ...any) bool {
	t.tb.Helper()
	equal, claimed := runCheckers(actual, expected)
	var notEqual bool
	if claimed {
		notEqual = !equal
	} else {
		actual2 := unwrapErr(actual)
		if hasMethod(actual2, "GRPCStatus") || hasMethod(expected, "GRPCStatus") {
			panic("check: gRPC status error detected; " +
				"import github.com/powerman/checkgrpc to compare gRPC status errors")
		}
		notEqual = reflect.TypeOf(actual2) != reflect.TypeOf(expected) ||
			!deepequal.DeepEqual(actual2, expected)
	}
	if notEqual {
		notEqual = !errors.Is(actual, expected)
	}
	return t.report1(actual, msg, notEqual)
}

// ErrIs checks for [errors.Is]().
//
// Unlike Err which tries to unwrap to root cause and compare values,
// ErrIs uses pure [errors.Is] semantics for exact error matching.
//
// See Err for value-equality checks. ErrIs is preferred when you want
// the standard Go unwrapping semantics without value comparison.
func (t *checks) ErrIs(actual, expected error, msg ...any) bool {
	t.tb.Helper()
	return t.report2(actual, expected, msg,
		errors.Is(actual, expected))
}

// NotErrIs checks for ![errors.Is]().
//
// See ErrIs for details. Note that nil is not matched by [errors.Is]
// against any non-nil error, so NotErrIs(nil, [io.EOF]) passes.
func (t *checks) NotErrIs(actual, expected error, msg ...any) bool {
	t.tb.Helper()
	return t.report1(actual, msg,
		!errors.Is(actual, expected))
}

// ErrAs checks for [errors.As].
//
// target must be a non-nil pointer to an error type or to an interface,
// as required by [errors.As]. On success target is filled
// with the matched error value. See [errors.As] documentation for details.
func (t *checks) ErrAs(actual error, target any, msg ...any) bool {
	t.tb.Helper()
	return t.report2(actual, target, msg,
		errors.As(actual, target))
}

// NotErrAs checks for ![errors.As].
//
// target must be a non-nil pointer to an error type or to an interface,
// as required by [errors.As]. Note that [errors.As] may still fill target
// with a matched error even when this check returns true,
// because [errors.As] is always called regardless of the negated result.
func (t *checks) NotErrAs(actual error, target any, msg ...any) bool {
	t.tb.Helper()
	return t.report1(actual, msg,
		!errors.As(actual, target))
}

// Panic checks is actual() panics.
//
// It is able to detect panic(nil)… but you should try to avoid using this.
func (t *checks) Panic(actual func(), msg ...any) bool {
	t.tb.Helper()
	didPanic := true
	func() {
		defer func() { _ = recover() }()
		actual()
		didPanic = false
	}()
	return t.report0(msg,
		didPanic)
}

// NotPanic checks is actual() don't panics.
//
// It is able to detect panic(nil)… but you should try to avoid using this.
func (t *checks) NotPanic(actual func(), msg ...any) bool {
	t.tb.Helper()
	didPanic := true
	func() {
		defer func() { _ = recover() }()
		actual()
		didPanic = false
	}()
	return t.report0(msg,
		!didPanic)
}

// PanicMatch checks is actual() panics and panic text match regex.
//
// Regex type can be either [*regexp.Regexp] or string.
//
// In case of panic(nil) it will match like panic("<nil>").
func (t *checks) PanicMatch(actual func(), regex any, msg ...any) bool {
	t.tb.Helper()
	var panicVal any
	didPanic := true
	func() {
		defer func() { panicVal = recover() }()
		actual()
		didPanic = false
	}()
	if !didPanic {
		return t.report0(msg,
			false)
	}

	switch panicVal.(type) {
	case string, error:
	default:
		panicVal = fmt.Sprintf("%#v", panicVal)
	}

	ok := isMatch(&panicVal, regex)
	return t.report2(panicVal, regex, msg,
		ok)
}

// PanicNotMatch checks is actual() panics and panic text not match regex.
//
// Regex type can be either [*regexp.Regexp] or string.
//
// In case of panic(nil) it will match like panic("<nil>").
func (t *checks) PanicNotMatch(actual func(), regex any, msg ...any) bool {
	t.tb.Helper()
	var panicVal any
	didPanic := true
	func() {
		defer func() { panicVal = recover() }()
		actual()
		didPanic = false
	}()
	if !didPanic {
		return t.report0(msg,
			false)
	}

	switch panicVal.(type) {
	case string, error:
	default:
		panicVal = fmt.Sprintf("%#v", panicVal)
	}

	ok := !isMatch(&panicVal, regex)
	return t.report2(panicVal, regex, msg,
		ok)
}

// Less checks for actual < expected.
//
// Both actual and expected must be either:
//   - signed integers
//   - unsigned integers
//   - floats
//   - strings
//   - [time.Time]
func (t *checks) Less(actual, expected any, msg ...any) bool {
	t.tb.Helper()
	return t.report2(actual, expected, msg,
		isLess(actual, expected))
}

func isLess(actual, expected any) bool {
	switch v1, v2 := reflect.ValueOf(actual), reflect.ValueOf(expected); v1.Kind() { //nolint:exhaustive // Covered by default case.
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return v1.Int() < v2.Int()
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return v1.Uint() < v2.Uint()
	case reflect.Float32, reflect.Float64:
		return v1.Float() < v2.Float()
	case reflect.String:
		return v1.String() < v2.String()
	default:
		if actualTime, ok := actual.(time.Time); ok {
			return actualTime.Before(expected.(time.Time))
		}
	}
	panic("actual is not a number, string or time.Time")
}

// LT is a synonym for Less.
func (t *checks) LT(actual, expected any, msg ...any) bool {
	t.tb.Helper()
	return t.Less(actual, expected, msg...)
}

// LessOrEqual checks for actual <= expected.
//
// Both actual and expected must be either:
//   - signed integers
//   - unsigned integers
//   - floats
//   - strings
//   - [time.Time]
func (t *checks) LessOrEqual(actual, expected any, msg ...any) bool {
	t.tb.Helper()
	return t.report2(actual, expected, msg,
		!isGreater(actual, expected))
}

func isGreater(actual, expected any) bool {
	switch v1, v2 := reflect.ValueOf(actual), reflect.ValueOf(expected); v1.Kind() { //nolint:exhaustive // Covered by default case.
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return v1.Int() > v2.Int()
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return v1.Uint() > v2.Uint()
	case reflect.Float32, reflect.Float64:
		return v1.Float() > v2.Float()
	case reflect.String:
		return v1.String() > v2.String()
	default:
		if actualTime, ok := actual.(time.Time); ok {
			return actualTime.After(expected.(time.Time))
		}
	}
	panic("actual is not a number, string or time.Time")
}

// LE is a synonym for LessOrEqual.
func (t *checks) LE(actual, expected any, msg ...any) bool {
	t.tb.Helper()
	return t.LessOrEqual(actual, expected, msg...)
}

// Greater checks for actual > expected.
//
// Both actual and expected must be either:
//   - signed integers
//   - unsigned integers
//   - floats
//   - strings
//   - [time.Time]
func (t *checks) Greater(actual, expected any, msg ...any) bool {
	t.tb.Helper()
	return t.report2(actual, expected, msg,
		isGreater(actual, expected))
}

// GT is a synonym for Greater.
func (t *checks) GT(actual, expected any, msg ...any) bool {
	t.tb.Helper()
	return t.Greater(actual, expected, msg...)
}

// GreaterOrEqual checks for actual >= expected.
//
// Both actual and expected must be either:
//   - signed integers
//   - unsigned integers
//   - floats
//   - strings
//   - [time.Time]
func (t *checks) GreaterOrEqual(actual, expected any, msg ...any) bool {
	t.tb.Helper()
	return t.report2(actual, expected, msg,
		!isLess(actual, expected))
}

// GE is a synonym for GreaterOrEqual.
func (t *checks) GE(actual, expected any, msg ...any) bool {
	t.tb.Helper()
	return t.GreaterOrEqual(actual, expected, msg...)
}

// Between checks for min < actual < max.
//
// All three actual, min and max must be either:
//   - signed integers
//   - unsigned integers
//   - floats
//   - strings
//   - [time.Time]
func (t *checks) Between(actual, minimum, maximum any, msg ...any) bool {
	t.tb.Helper()
	return t.report3(actual, minimum, maximum, msg,
		isBetween(actual, minimum, maximum))
}

func isBetween(actual, minimum, maximum any) bool {
	switch v, vmin, vmax := reflect.ValueOf(actual), reflect.ValueOf(minimum), reflect.ValueOf(maximum); v.Kind() { //nolint:exhaustive // Covered by default case.
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return vmin.Int() < v.Int() && v.Int() < vmax.Int()
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return vmin.Uint() < v.Uint() && v.Uint() < vmax.Uint()
	case reflect.Float32, reflect.Float64:
		return vmin.Float() < v.Float() && v.Float() < vmax.Float()
	case reflect.String:
		return vmin.String() < v.String() && v.String() < vmax.String()
	default:
		if actualTime, ok := actual.(time.Time); ok {
			minTime := minimum.(time.Time) //nolint:forcetypeassert // Want panic.
			maxTime := maximum.(time.Time) //nolint:forcetypeassert // Want panic.
			return minTime.Before(actualTime) && actualTime.Before(maxTime)
		}
	}
	panic("actual is not a number, string or time.Time")
}

// NotBetween checks for actual <= min or max <= actual.
//
// All three actual, min and max must be either:
//   - signed integers
//   - unsigned integers
//   - floats
//   - strings
//   - [time.Time]
func (t *checks) NotBetween(actual, minimum, maximum any, msg ...any) bool {
	t.tb.Helper()
	return t.report3(actual, minimum, maximum, msg,
		!isBetween(actual, minimum, maximum))
}

// BetweenOrEqual checks for min <= actual <= max.
//
// All three actual, min and max must be either:
//   - signed integers
//   - unsigned integers
//   - floats
//   - strings
//   - [time.Time]
func (t *checks) BetweenOrEqual(actual, minimum, maximum any, msg ...any) bool {
	t.tb.Helper()
	return t.report3(actual, minimum, maximum, msg,
		isBetween(actual, minimum, maximum) || isEqual(actual, minimum) || isEqual(actual, maximum))
}

// NotBetweenOrEqual checks for actual < min or max < actual.
//
// All three actual, min and max must be either:
//   - signed integers
//   - unsigned integers
//   - floats
//   - strings
//   - [time.Time]
func (t *checks) NotBetweenOrEqual(actual, minimum, maximum any, msg ...any) bool {
	t.tb.Helper()
	return t.report3(actual, minimum, maximum, msg,
		!isBetween(actual, minimum, maximum) && !isEqual(actual, minimum) && !isEqual(actual, maximum))
}

// InDelta checks for expected-delta <= actual <= expected+delta.
//
// All three actual, expected and delta must be either:
//   - signed integers
//   - unsigned integers
//   - floats
//   - [time.Time] (in this case delta must be [time.Duration])
func (t *checks) InDelta(actual, expected, delta any, msg ...any) bool {
	t.tb.Helper()
	return t.report3(actual, expected, delta, msg,
		isInDelta(actual, expected, delta))
}

func isInDelta(actual, expected, delta any) bool {
	switch v, e, d := reflect.ValueOf(actual), reflect.ValueOf(expected), reflect.ValueOf(delta); v.Kind() { //nolint:exhaustive // Covered by default case.
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		dd := d.Int()
		if dd < 0 {
			return false // negative delta: preserve old always-false behavior
		}
		a, e2 := v.Int(), e.Int()
		var diff uint64 // |a-e2| computed without overflow via two's complement
		if a >= e2 {
			diff = uint64(a) - uint64(e2) //nolint:gosec // Two's complement: exact even when a-e2 overflows int64.
		} else {
			diff = uint64(e2) - uint64(a) //nolint:gosec // Two's complement: exact even when e2-a overflows int64.
		}
		return diff <= uint64(dd)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		a, e2, dd := v.Uint(), e.Uint(), d.Uint()
		var diff uint64
		if a >= e2 {
			diff = a - e2
		} else {
			diff = e2 - a
		}
		return diff <= dd
	case reflect.Float32, reflect.Float64:
		minimum, maximum := e.Float()-d.Float(), e.Float()+d.Float()
		return minimum <= v.Float() && v.Float() <= maximum
	default:
		if actualTime, ok := actual.(time.Time); ok {
			expectedTime := expected.(time.Time) //nolint:forcetypeassert // Want panic.
			dur := delta.(time.Duration)         //nolint:forcetypeassert // Want panic.
			minTime, maxTime := expectedTime.Add(-dur), expectedTime.Add(dur)
			return minTime.Before(actualTime) && actualTime.Before(maxTime) ||
				actualTime.Equal(minTime) ||
				actualTime.Equal(maxTime)
		}
	}
	panic("actual is not a number or time.Time")
}

// NotInDelta checks for actual < expected-delta or expected+delta < actual.
//
// All three actual, expected and delta must be either:
//   - signed integers
//   - unsigned integers
//   - floats
//   - [time.Time] (in this case delta must be [time.Duration])
func (t *checks) NotInDelta(actual, expected, delta any, msg ...any) bool {
	t.tb.Helper()
	return t.report3(actual, expected, delta, msg,
		!isInDelta(actual, expected, delta))
}

// InSMAPE checks that actual and expected have a symmetric mean absolute
// percentage error (SMAPE) is less than given smape.
//
// Both actual and expected must be either:
//   - signed integers
//   - unsigned integers
//   - floats
//
// Allowed smape values are: 0.0 < smape < 100.0.
//
// Used formula returns SMAPE value between 0 and 100 (percents):
//   - 0.0   when actual == expected
//   - ~0.5  when they differs in ~1%
//   - ~5    when they differs in ~10%
//   - ~20   when they differs in 1.5 times
//   - ~33   when they differs in 2 times
//   - 50.0  when they differs in 3 times
//   - ~82   when they differs in 10 times
//   - 99.0+ when actual and expected differs in 200+ times
//   - 100.0 when only one of actual or expected is 0 or one of them is
//     positive while another is negative
func (t *checks) InSMAPE(actual, expected any, smape float64, msg ...any) bool {
	t.tb.Helper()
	return t.report3(actual, expected, smape, msg,
		isInSMAPE(actual, expected, smape))
}

func isInSMAPE(actual, expected any, smape float64) bool {
	if !(0 < smape && smape < 100) {
		panic("smape is not in allowed range: 0 < smape < 100")
	}
	a := reflect.ValueOf(actual).Convert(typFloat64).Float()
	e := reflect.ValueOf(expected).Convert(typFloat64).Float()
	if a == 0 && e == 0 {
		return true // avoid division by zero in legal use case
	}
	return 100*math.Abs(e-a)/(math.Abs(e)+math.Abs(a)) < smape
}

// NotInSMAPE checks that actual and expected have a symmetric mean
// absolute percentage error (SMAPE) is greater than or equal to given
// smape.
//
// See InSMAPE about supported actual/expected types and check logic.
func (t *checks) NotInSMAPE(actual, expected any, smape float64, msg ...any) bool {
	t.tb.Helper()
	return t.report3(actual, expected, smape, msg,
		!isInSMAPE(actual, expected, smape))
}

// HasPrefix checks for [strings.HasPrefix](actual, expected).
//
// Both actual and expected may have any of these types:
//   - string       - will use as is
//   - []byte       - will convert with string()
//   - []rune       - will convert with string()
//   - [fmt.Stringer] - will convert with actual.String()
//   - error        - will convert with actual.Error()
//   - nil          - check will always fail
func (t *checks) HasPrefix(actual, expected any, msg ...any) bool {
	t.tb.Helper()
	ok := isHasPrefix(&actual, &expected)
	return t.report2(actual, expected, msg,
		ok)
}

// isHasPrefix updates actual and expected to be a real string used for check,
// to make dump easier to understand, but this result in losing type information.
func isHasPrefix(actual, expected *any) bool {
	if *actual == nil || *expected == nil {
		return false
	}
	if !stringify(actual) {
		panic("actual is not a string, []byte, []rune, fmt.Stringer, error or nil")
	}
	if !stringify(expected) {
		panic("expected is not a string, []byte, []rune, fmt.Stringer, error or nil")
	}
	return strings.HasPrefix((*actual).(string), (*expected).(string))
}

// NotHasPrefix checks for !strings.HasPrefix(actual, expected).
//
// See HasPrefix about supported actual/expected types and check logic.
func (t *checks) NotHasPrefix(actual, expected any, msg ...any) bool {
	t.tb.Helper()
	ok := !isHasPrefix(&actual, &expected)
	return t.report2(actual, expected, msg,
		ok)
}

// HasSuffix checks for [strings.HasSuffix](actual, expected).
//
// Both actual and expected may have any of these types:
//   - string       - will use as is
//   - []byte       - will convert with string()
//   - []rune       - will convert with string()
//   - [fmt.Stringer] - will convert with actual.String()
//   - error        - will convert with actual.Error()
//   - nil          - check will always fail
func (t *checks) HasSuffix(actual, expected any, msg ...any) bool {
	t.tb.Helper()
	ok := isHasSuffix(&actual, &expected)
	return t.report2(actual, expected, msg,
		ok)
}

// isHasSuffix updates actual and expected to be a real string used for check,
// to make dump easier to understand, but this result in losing type information.
func isHasSuffix(actual, expected *any) bool {
	if *actual == nil || *expected == nil {
		return false
	}
	if !stringify(actual) {
		panic("actual is not a string, []byte, []rune, fmt.Stringer, error or nil")
	}
	if !stringify(expected) {
		panic("expected is not a string, []byte, []rune, fmt.Stringer, error or nil")
	}
	return strings.HasSuffix((*actual).(string), (*expected).(string))
}

// NotHasSuffix checks for !strings.HasSuffix(actual, expected).
//
// See HasSuffix about supported actual/expected types and check logic.
func (t *checks) NotHasSuffix(actual, expected any, msg ...any) bool {
	t.tb.Helper()
	ok := !isHasSuffix(&actual, &expected)
	return t.report2(actual, expected, msg,
		ok)
}

// JSONEqual normalize formatting of actual and expected (if they're valid
// JSON) and then checks for [bytes.Equal](actual, expected).
//
// Both actual and expected may have any of these types:
//   - string
//   - []byte
//   - [json.RawMessage]
//   - [*json.RawMessage]
//   - nil
//
// In case any of actual or expected is nil or empty or (for string or
// []byte) is invalid JSON - check will fail.
func (t *checks) JSONEqual(actual, expected any, msg ...any) bool {
	t.tb.Helper()
	ok := isJSONEqual(actual, expected)
	if !ok {
		if buf := jsonify(actual); len(buf) != 0 {
			actual = buf
		}
		if buf := jsonify(expected); len(buf) != 0 {
			expected = buf
		}
	}
	return t.report2(actual, expected, msg,
		ok)
}

func isJSONEqual(actual, expected any) bool {
	jsonActual, jsonExpected := jsonify(actual), jsonify(expected)
	return len(jsonActual) != 0 && len(jsonExpected) != 0 &&
		bytes.Equal(jsonActual, jsonExpected)
}

func jsonify(arg any) json.RawMessage {
	switch v := (arg).(type) {
	case nil:
		return nil
	case json.RawMessage:
		return v
	case *json.RawMessage:
		if v == nil {
			return nil
		}
		return *v
	}
	buf := reflect.ValueOf(arg).Convert(typBytes).Interface().([]byte) //nolint:forcetypeassert // Want panic.

	var v any
	err := json.Unmarshal(buf, &v)
	if err != nil {
		return nil
	}
	buf, err = json.Marshal(v)
	if err != nil {
		return nil
	}
	return buf
}

// HasType checks is actual has same type as expected.
func (t *checks) HasType(actual, expected any, msg ...any) bool {
	t.tb.Helper()
	return t.report2(actual, expected, msg,
		reflect.TypeOf(actual) == reflect.TypeOf(expected))
}

// NotHasType checks is actual has not same type as expected.
func (t *checks) NotHasType(actual, expected any, msg ...any) bool {
	t.tb.Helper()
	return t.report2(actual, expected, msg,
		reflect.TypeOf(actual) != reflect.TypeOf(expected))
}

// Implements checks is actual implements interface pointed by expected.
//
// You must use pointer to interface type in expected:
//
//	t.Implements(os.Stdin, (*io.Reader)(nil))
func (t *checks) Implements(actual, expected any, msg ...any) bool {
	t.tb.Helper()
	return t.report2(actual, expected, msg,
		isImplements(actual, expected))
}

func isImplements(actual, expected any) bool {
	typActual := reflect.TypeOf(actual)
	if typActual.Kind() != reflect.Pointer {
		typActual = reflect.PointerTo(typActual)
	}
	return typActual.Implements(reflect.TypeOf(expected).Elem())
}

// NotImplements checks is actual does not implements interface pointed by expected.
//
// You must use pointer to interface type in expected:
//
//	t.NotImplements(os.Stdin, (*fmt.Stringer)(nil))
func (t *checks) NotImplements(actual, expected any, msg ...any) bool {
	t.tb.Helper()
	return t.report2(actual, expected, msg,
		!isImplements(actual, expected))
}

// SortEqual checks that actual and expected contain the same elements,
// ignoring order (multiset equality, duplicates counted).
//
// Both actual and expected must be slices or arrays.
// Elements need not be sortable and are compared like DeepEqual.
// Nil and empty slices are equal (like BytesEqual, unlike DeepEqual).
func (t *checks) SortEqual(actual, expected any, msg ...any) bool {
	t.tb.Helper()
	return t.report2(actual, expected, msg,
		isSortEqual(actual, expected))
}

// NotSortEqual checks !SortEqual(actual, expected).
//
// See SortEqual about supported actual/expected types and check logic.
func (t *checks) NotSortEqual(actual, expected any, msg ...any) bool {
	t.tb.Helper()
	return t.report1(actual, msg,
		!isSortEqual(actual, expected))
}

func isSortEqual(actual, expected any) bool {
	va, ve := reflect.ValueOf(actual), reflect.ValueOf(expected)
	if va.Kind() != reflect.Slice && va.Kind() != reflect.Array {
		panic("actual is not a slice or array")
	}
	if ve.Kind() != reflect.Slice && ve.Kind() != reflect.Array {
		panic("expected is not a slice or array")
	}
	if va.Len() != ve.Len() {
		return false
	}
	return isMultisetIn(va, ve)
}

// isMultisetIn reports whether every element of small has a distinct,
// not-yet-used matching element in big, i.e. small is a multiset-subset of big.
func isMultisetIn(small, big reflect.Value) bool {
	used := make([]bool, big.Len())
	for i := range small.Len() {
		found := false
		for j := range big.Len() {
			if !used[j] && elemEqual(small.Index(i).Interface(), big.Index(j).Interface()) {
				used[j], found = true, true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// Subset checks that actual contains all elements of expected:
// for slices/arrays - as multisets (duplicates counted), ignoring order;
// for maps - every key of expected exists in actual with an equal value.
//
// actual and expected must both be slices/arrays or both be maps.
// Elements/values are compared like DeepEqual.
// An empty/nil expected is a subset of anything of the same kind.
//
// Note: unlike testify's Subset, duplicates are counted, so [1,1] is not a subset of [1].
func (t *checks) Subset(actual, expected any, msg ...any) bool {
	t.tb.Helper()
	return t.report2(actual, expected, msg,
		isSubset(actual, expected))
}

// NotSubset checks !Subset(actual, expected).
//
// See Subset about supported actual/expected types and check logic.
func (t *checks) NotSubset(actual, expected any, msg ...any) bool {
	t.tb.Helper()
	return t.report1(actual, msg,
		!isSubset(actual, expected))
}

func isSubset(actual, expected any) bool {
	va, ve := reflect.ValueOf(actual), reflect.ValueOf(expected)
	switch ve.Kind() { //nolint:exhaustive // Covered by default case.
	case reflect.Map:
		if va.Kind() != reflect.Map {
			panic("actual is not a map")
		}
		return isMapSubset(va, ve)
	case reflect.Slice, reflect.Array:
		if va.Kind() != reflect.Slice && va.Kind() != reflect.Array {
			panic("actual is not a slice or array")
		}
		return isMultisetIn(ve, va)
	default:
		panic("expected is not a slice, array or map")
	}
}

func isMapSubset(actual, expected reflect.Value) bool {
	iter := expected.MapRange()
	for iter.Next() {
		v := actual.MapIndex(iter.Key())
		if !v.IsValid() || !elemEqual(v.Interface(), iter.Value().Interface()) {
			return false
		}
	}
	return true
}

// FileExists checks that path exists and is not a directory.
//
// A Stat error other than "not exists" (e.g. permission denied)
// counts as "does not exist", same as testify.
func (t *checks) FileExists(path string, msg ...any) bool {
	t.tb.Helper()
	fi, err := os.Stat(path)
	return t.report1(path, msg,
		err == nil && !fi.IsDir())
}

// NotFileExists checks that path does not exist or is a directory.
//
// See FileExists about Stat error handling.
func (t *checks) NotFileExists(path string, msg ...any) bool {
	t.tb.Helper()
	fi, err := os.Stat(path)
	return t.report1(path, msg,
		err != nil || fi.IsDir())
}

// DirExists checks that path exists and is a directory.
//
// See FileExists about Stat error handling.
func (t *checks) DirExists(path string, msg ...any) bool {
	t.tb.Helper()
	fi, err := os.Stat(path)
	return t.report1(path, msg,
		err == nil && fi.IsDir())
}

// NotDirExists checks that path does not exist or is not a directory.
//
// See FileExists about Stat error handling.
func (t *checks) NotDirExists(path string, msg ...any) bool {
	t.tb.Helper()
	fi, err := os.Stat(path)
	return t.report1(path, msg,
		err != nil || !fi.IsDir())
}
