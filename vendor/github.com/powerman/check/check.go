package check

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	pkgerrors "github.com/pkg/errors" //nolint:depguard // By design.
	"github.com/powerman/deepequal"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

//nolint:gochecknoglobals // Const.
var (
	typString  = reflect.TypeOf("")
	typBytes   = reflect.TypeOf([]byte(nil))
	typFloat64 = reflect.TypeOf(0.0)
)

// C wraps *testing.T to make it convenient to call checkers in test.
type C struct {
	*testing.T
	todo bool
	must bool
}

const (
	nameActual   = "Actual"
	nameExpected = "Expected"
)

// Parallel implements an internal workaround which have no visible
// effect, so you should just call t.Parallel() as you usually do - it
// will work as expected.
func (t *C) Parallel() {
	t.Helper()
	// Goconvey anyway doesn't provide -test.cpu= and mixed output of
	// parallel tests result in reporting failed tests at wrong places
	// and with wrong failed tests count in web UI.
	if !flags.detect().conveyJSON {
		t.T.Parallel()
	}
}

// T creates and returns new *C, which wraps given tt and supposed to be
// used inplace of it, providing you with access to many useful helpers in
// addition to standard methods of *testing.T.
//
// It's convenient to rename Test function's arg from t to something
// else, create wrapped variable with usual name t and use only t:
//
//	func TestSomething(tt *testing.T) {
//		t := check.T(tt)
//		// use only t in test and don't touch tt anymore
//	}
func T(tt *testing.T) *C { //nolint:thelper // With check we name it tt!
	return &C{T: tt}
}

// TODO creates and returns new *C, which have only one difference from
// original one: every passing check is now handled as failed and vice
// versa (this doesn't affect boolean value returned by check).
// You can continue using both old and new *C at same time.
//
// Swapping passed/failed gives you ability to temporary mark some failed
// test as passed. For example, this may be useful to avoid broken builds
// in CI. This is often better than commenting, deleting or skipping
// broken test because it will continue to execute, and eventually when
// reason why it fails will be fixed this test will became failed again -
// notifying you the mark can and should be removed from this test now.
//
//	func TestSomething(tt *testing.T) {
//		t := check.T(tt)
//		// Normal tests.
//		t.True(true)
//		// If you need to mark just one/few broken tests:
//		t.TODO().True(false)
//		t.True(true)
//		// If there are several broken tests mixed with working ones:
//		todo := t.TODO()
//		t.True(true)
//		todo.True(false)
//		t.True(true)
//		if todo.True(false) {
//			panic("never here")
//		}
//		// If all tests below this point are broken:
//		t = t.TODO()
//		t.True(false)
//		...
//	}
func (t *C) TODO() *C {
	return &C{T: t.T, todo: true, must: t.must}
}

// MustAll creates and returns new *C, which have only one difference from
// original one: every failed check will interrupt test using t.FailNow.
// You can continue using both old and new *C at same time.
//
// This provides an easy way to turn all checks into assertion.
func (t *C) MustAll() *C {
	return &C{T: t.T, todo: t.todo, must: true}
}

func (t *C) pass() {
	statsMu.Lock()
	defer statsMu.Unlock()

	if stats[t.T] == nil {
		stats[t.T] = newTestStat(t.Name(), false)
	}
	if t.todo {
		stats[t.T].forged.value++
	} else {
		stats[t.T].passed.value++
	}
}

func (t *C) fail() {
	statsMu.Lock()
	defer statsMu.Unlock()

	if stats[t.T] == nil {
		stats[t.T] = newTestStat(t.Name(), false)
	}
	stats[t.T].failed.value++
}

func (t *C) report(ok bool, msg []any, checker string, name []string, args []any) bool { //nolint:revive // False positive.
	t.Helper()

	if ok != t.todo {
		t.pass()
		return ok
	}

	if t.todo {
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
	failureShort := failure.String()
	// Reverse order to show Actual: last.
	for i := len(dump) - 1; i >= 0; i-- {
		fmt.Fprintf(failure, "%-10s", name[i]+":")
		switch name[i] {
		case nameActual:
			fmt.Fprint(failure, ansiRed)
		default:
			fmt.Fprint(failure, ansiGreen)
		}
		fmt.Fprintf(failure, "%s%s", dump[i], ansiReset)
	}
	failureLong := failure.String()

	wantDiff := len(dump) == 2 && name[0] == nameActual && name[1] == nameExpected //nolint:gosec // False positive.
	if wantDiff {                                                                  //nolint:nestif // No idea how to simplify.
		if reportToGoConvey(dump[0].String(), dump[1].String(), failureShort) == nil {
			t.Fail()
		} else {
			fmt.Fprintf(failure, "\n%s", colouredDiff(dump[0].diff(dump[1])))
			t.Errorf("%s\n", failure)
		}
	} else {
		if reportToGoConvey("", "", failureLong) == nil {
			t.Fail()
		} else {
			t.Errorf("%s\n", failure)
		}
	}

	t.fail()

	if t.must {
		t.FailNow()
	}
	return ok
}

func (t *C) reportShould1(funcName string, actual any, msg []any, ok bool) bool {
	t.Helper()
	return t.report(ok, msg,
		"Should "+funcName,
		[]string{nameActual},
		[]any{actual})
}

func (t *C) reportShould2(funcName string, actual, expected any, msg []any, ok bool) bool {
	t.Helper()
	return t.report(ok, msg,
		"Should "+funcName,
		[]string{nameActual, nameExpected},
		[]any{actual, expected})
}

func (t *C) report0(msg []any, ok bool) bool {
	t.Helper()
	return t.report(ok, msg,
		callerFuncName(1),
		[]string{},
		[]any{})
}

func (t *C) report1(actual any, msg []any, ok bool) bool {
	t.Helper()
	return t.report(ok, msg,
		callerFuncName(1),
		[]string{nameActual},
		[]any{actual})
}

func (t *C) report2(actual, expected any, msg []any, ok bool) bool {
	t.Helper()
	checker, arg2Name := callerFuncName(1), nameExpected
	if strings.Contains(checker, "Match") {
		arg2Name = "Regex"
	}
	return t.report(ok, msg,
		checker,
		[]string{nameActual, arg2Name},
		[]any{actual, expected})
}

func (t *C) report3(actual, expected1, expected2 any, msg []any, ok bool) bool {
	t.Helper()
	checker, arg2Name, arg3Name := callerFuncName(1), "arg1", "arg2"
	switch {
	case strings.Contains(checker, "Between"):
		arg2Name, arg3Name = "Min", "Max"
	case strings.Contains(checker, "Delta"):
		arg2Name, arg3Name = nameExpected, "Delta"
	case strings.Contains(checker, "SMAPE"):
		arg2Name, arg3Name = nameExpected, "SMAPE"
	}
	return t.report(ok, msg,
		checker,
		[]string{nameActual, arg2Name, arg3Name},
		[]any{actual, expected1, expected2})
}

// Must interrupt test using t.FailNow if called with false value.
//
// This provides an easy way to turn any check into assertion:
//
//	t.Must(t.Nil(err))
func (t *C) Must(continueTest bool, msg ...any) { //nolint:revive // False positive.
	t.Helper()
	t.report0(msg, continueTest)
	if !continueTest {
		t.FailNow()
	}
}

type (
	// ShouldFunc1 is like Nil or Zero.
	ShouldFunc1 func(t *C, actual any) bool
	// ShouldFunc2 is like Equal or Match.
	ShouldFunc2 func(t *C, actual, expected any) bool
)

// Should use user-provided check function to do actual check.
//
// anyShouldFunc must have type ShouldFunc1 or ShouldFunc2. It should
// return true if check was successful. There is no need to call t.Error
// in anyShouldFunc - this will be done automatically when it returns.
//
// args must contain at least 1 element for ShouldFunc1 and at least
// 2 elements for ShouldFunc2.
// Rest of elements will be processed as usual msg ...interface{} param.
//
// Example:
//
//	func bePositive(_ *check.C, actual interface{}) bool {
//		return actual.(int) > 0
//	}
//	func TestCustomCheck(tt *testing.T) {
//		t := check.T(tt)
//		t.Should(bePositive, 42, "custom check!!!")
//	}
func (t *C) Should(anyShouldFunc any, args ...any) bool {
	t.Helper()
	switch f := anyShouldFunc.(type) {
	case func(t *C, actual any) bool:
		return t.should1(f, args...)
	case func(t *C, actual, expected any) bool:
		return t.should2(f, args...)
	default:
		panic("anyShouldFunc is not a ShouldFunc1 or ShouldFunc2")
	}
}

func (t *C) should1(f ShouldFunc1, args ...any) bool {
	t.Helper()
	if len(args) < 1 {
		panic("not enough params for " + funcName(f))
	}
	actual, msg := args[0], args[1:]
	return t.reportShould1(funcName(f), actual, msg,
		f(t, actual))
}

func (t *C) should2(f ShouldFunc2, args ...any) bool {
	t.Helper()
	const minArgs = 2
	if len(args) < minArgs {
		panic("not enough params for " + funcName(f))
	}
	actual, expected, msg := args[0], args[1], args[2:]
	return t.reportShould2(funcName(f), actual, expected, msg,
		f(t, actual, expected))
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
func (t *C) Nil(actual any, msg ...any) bool {
	t.Helper()
	return t.report1(actual, msg,
		isNil(actual))
}

func isNil(actual any) bool {
	switch val := reflect.ValueOf(actual); val.Kind() {
	case reflect.Invalid:
		return actual == nil
	case reflect.Chan, reflect.Func, reflect.Map, reflect.Ptr, reflect.Slice:
		return val.IsNil()
	case reflect.Uintptr, reflect.UnsafePointer: // Subtle cases documented above.
	case reflect.Interface: // ???
	// Can't be nil:
	case reflect.Struct, reflect.Array, reflect.Bool, reflect.String:
	case reflect.Complex128, reflect.Complex64, reflect.Float32, reflect.Float64:
	case reflect.Int, reflect.Int16, reflect.Int32, reflect.Int64, reflect.Int8:
	case reflect.Uint, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uint8:
	}
	return false
}

// NotNil checks for actual != nil.
//
// See Nil about subtle case in check logic.
func (t *C) NotNil(actual any, msg ...any) bool {
	t.Helper()
	return t.report0(msg,
		!isNil(actual))
}

// Error is equivalent to Log followed by Fail.
//
// It is like t.Errorf with TODO() and statistics support.
func (t *C) Error(msg ...any) {
	t.Helper()
	t.report0(msg, false)
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
func (t *C) True(cond bool, msg ...any) bool {
	t.Helper()
	return t.report0(msg,
		cond)
}

// False checks for cond == false.
func (t *C) False(cond bool, msg ...any) bool {
	t.Helper()
	return t.report0(msg,
		!cond)
}

// Equal checks for actual == expected.
//
// Note: For time.Time it uses actual.Equal(expected) instead.
func (t *C) Equal(actual, expected any, msg ...any) bool {
	t.Helper()
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
func (t *C) EQ(actual, expected any, msg ...any) bool {
	t.Helper()
	return t.Equal(actual, expected, msg...)
}

// NotEqual checks for actual != expected.
func (t *C) NotEqual(actual, expected any, msg ...any) bool {
	t.Helper()
	return t.report2(actual, expected, msg,
		!isEqual(actual, expected))
}

// NE is a synonym for NotEqual.
func (t *C) NE(actual, expected any, msg ...any) bool {
	t.Helper()
	return t.NotEqual(actual, expected, msg...)
}

// BytesEqual checks for bytes.Equal(actual, expected).
//
// Hint: BytesEqual([]byte{}, []byte(nil)) is true (unlike DeepEqual).
func (t *C) BytesEqual(actual, expected []byte, msg ...any) bool {
	t.Helper()
	return t.report2(actual, expected, msg,
		bytes.Equal(actual, expected))
}

// NotBytesEqual checks for !bytes.Equal(actual, expected).
//
// Hint: NotBytesEqual([]byte{}, []byte(nil)) is false (unlike NotDeepEqual).
func (t *C) NotBytesEqual(actual, expected []byte, msg ...any) bool {
	t.Helper()
	return t.report1(actual, msg,
		!bytes.Equal(actual, expected))
}

// DeepEqual checks for reflect.DeepEqual(actual, expected).
// It will also use Equal method for types which implements it
// (e.g. time.Time, decimal.Decimal, etc.).
// It will use proto.Equal for protobuf messages.
func (t *C) DeepEqual(actual, expected any, msg ...any) bool {
	t.Helper()
	protoActual, proto1 := actual.(protoreflect.ProtoMessage)
	protoExpected, proto2 := expected.(protoreflect.ProtoMessage)
	if proto1 && proto2 {
		return t.report2(actual, expected, msg,
			proto.Equal(protoActual, protoExpected))
	}
	return t.report2(actual, expected, msg,
		deepequal.DeepEqual(actual, expected))
}

// NotDeepEqual checks for !reflect.DeepEqual(actual, expected).
// It will also use Equal method for types which implements it
// (e.g. time.Time, decimal.Decimal, etc.).
// It will use proto.Equal for protobuf messages.
func (t *C) NotDeepEqual(actual, expected any, msg ...any) bool {
	t.Helper()
	protoActual, proto1 := actual.(protoreflect.ProtoMessage)
	protoExpected, proto2 := expected.(protoreflect.ProtoMessage)
	if proto1 && proto2 {
		return t.report1(actual, msg,
			!proto.Equal(protoActual, protoExpected))
	}
	return t.report1(actual, msg,
		!deepequal.DeepEqual(actual, expected))
}

// Match checks for regex.MatchString(actual).
//
// Regex type can be either *regexp.Regexp or string.
//
// Actual type can be:
//   - string       - will match with actual
//   - []byte       - will match with string(actual)
//   - []rune       - will match with string(actual)
//   - fmt.Stringer - will match with actual.String()
//   - error        - will match with actual.Error()
//   - nil          - will not match (even with empty regex)
func (t *C) Match(actual, regex any, msg ...any) bool {
	t.Helper()
	ok := isMatch(&actual, regex)
	return t.report2(actual, regex, msg,
		ok)
}

// isMatch updates actual to be a real string used for matching, to make
// dump easier to understand, but this result in losing type information.
func isMatch(actual *any, regex any) bool { //nolint:gocritic // False positive.
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

func stringify(arg *any) bool { //nolint:gocritic // False positive.
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
func (t *C) NotMatch(actual, regex any, msg ...any) bool {
	t.Helper()
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
func (t *C) Contains(actual, expected any, msg ...any) bool {
	t.Helper()
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
func (t *C) NotContains(actual, expected any, msg ...any) bool {
	t.Helper()
	return t.report2(actual, expected, msg,
		!isContains(actual, expected))
}

// HasKey checks is actual has key expected.
func (t *C) HasKey(actual, expected any, msg ...any) bool {
	t.Helper()
	return t.report2(actual, expected, msg,
		hasKey(actual, expected))
}

func hasKey(actual, expected any) bool {
	return reflect.ValueOf(actual).MapIndex(reflect.ValueOf(expected)).IsValid()
}

// NotHasKey checks is actual has no key expected.
func (t *C) NotHasKey(actual, expected any, msg ...any) bool {
	t.Helper()
	return t.report2(actual, expected, msg,
		!hasKey(actual, expected))
}

// Zero checks is actual is zero value of it's type.
func (t *C) Zero(actual any, msg ...any) bool {
	t.Helper()
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
func (t *C) NotZero(actual any, msg ...any) bool {
	t.Helper()
	return t.report1(actual, msg,
		!isZero(actual))
}

// Len checks is len(actual) == expected.
func (t *C) Len(actual any, expected int, msg ...any) bool {
	t.Helper()
	l := reflect.ValueOf(actual).Len()
	return t.report2(l, expected, msg,
		l == expected)
}

// NotLen checks is len(actual) != expected.
func (t *C) NotLen(actual any, expected int, msg ...any) bool {
	t.Helper()
	l := reflect.ValueOf(actual).Len()
	return t.report2(l, expected, msg,
		l != expected)
}

// Err checks is actual error is the same as expected error.
//
// If errors.Is() fails then it'll use more sofiscated logic:
//
// It tries to recursively unwrap actual before checking using
// errors.Unwrap() and github.com/pkg/errors.Cause().
// In case of multi-error (Unwrap() []error) it use only first error.
//
// It will use proto.Equal for gRPC status errors.
//
// They may be a different instances, but must have same type and value.
//
// Checking for nil is okay, but using Nil(actual) instead is more clean.
func (t *C) Err(actual, expected error, msg ...any) bool {
	t.Helper()
	actual2 := unwrapErr(actual)
	equal := fmt.Sprintf("%#v", actual2) == fmt.Sprintf("%#v", expected)
	_, proto1 := actual2.(interface{ GRPCStatus() *status.Status })
	_, proto2 := expected.(interface{ GRPCStatus() *status.Status })
	if proto1 || proto2 {
		equal = proto.Equal(status.Convert(actual2).Proto(), status.Convert(expected).Proto())
	}
	if !equal {
		equal = errors.Is(actual, expected)
	}
	return t.report2(actual, expected, msg, equal)
}

func unwrapErr(err error) (actual error) {
	defer func() { _ = recover() }()
	actual = err
	for {
		actual = pkgerrors.Cause(actual)
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
// errors.Unwrap() and github.com/pkg/errors.Cause().
// In case of multi-error (Unwrap() []error) it use only first error.
//
// It will use !proto.Equal for gRPC status errors.
//
// They must have either different types or values (or one should be nil).
// Different instances with same type and value will be considered the
// same error, and so is both nil.
//
// Finally it'll use !errors.Is().
func (t *C) NotErr(actual, expected error, msg ...any) bool {
	t.Helper()
	actual2 := unwrapErr(actual)
	notEqual := fmt.Sprintf("%#v", actual2) != fmt.Sprintf("%#v", expected)
	_, proto1 := actual2.(interface{ GRPCStatus() *status.Status })
	_, proto2 := expected.(interface{ GRPCStatus() *status.Status })
	if proto1 || proto2 {
		notEqual = !proto.Equal(status.Convert(actual2).Proto(), status.Convert(expected).Proto())
	}
	if notEqual {
		notEqual = !errors.Is(actual, expected)
	}
	return t.report1(actual, msg, notEqual)
}

// Panic checks is actual() panics.
//
// It is able to detect panic(nil)… but you should try to avoid using this.
func (t *C) Panic(actual func(), msg ...any) bool {
	t.Helper()
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
func (t *C) NotPanic(actual func(), msg ...any) bool {
	t.Helper()
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
// Regex type can be either *regexp.Regexp or string.
//
// In case of panic(nil) it will match like panic("<nil>").
func (t *C) PanicMatch(actual func(), regex any, msg ...any) bool {
	t.Helper()
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
// Regex type can be either *regexp.Regexp or string.
//
// In case of panic(nil) it will match like panic("<nil>").
func (t *C) PanicNotMatch(actual func(), regex any, msg ...any) bool {
	t.Helper()
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
//   - time.Time
func (t *C) Less(actual, expected any, msg ...any) bool {
	t.Helper()
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
func (t *C) LT(actual, expected any, msg ...any) bool {
	t.Helper()
	return t.Less(actual, expected, msg...)
}

// LessOrEqual checks for actual <= expected.
//
// Both actual and expected must be either:
//   - signed integers
//   - unsigned integers
//   - floats
//   - strings
//   - time.Time
func (t *C) LessOrEqual(actual, expected any, msg ...any) bool {
	t.Helper()
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
func (t *C) LE(actual, expected any, msg ...any) bool {
	t.Helper()
	return t.LessOrEqual(actual, expected, msg...)
}

// Greater checks for actual > expected.
//
// Both actual and expected must be either:
//   - signed integers
//   - unsigned integers
//   - floats
//   - strings
//   - time.Time
func (t *C) Greater(actual, expected any, msg ...any) bool {
	t.Helper()
	return t.report2(actual, expected, msg,
		isGreater(actual, expected))
}

// GT is a synonym for Greater.
func (t *C) GT(actual, expected any, msg ...any) bool {
	t.Helper()
	return t.Greater(actual, expected, msg...)
}

// GreaterOrEqual checks for actual >= expected.
//
// Both actual and expected must be either:
//   - signed integers
//   - unsigned integers
//   - floats
//   - strings
//   - time.Time
func (t *C) GreaterOrEqual(actual, expected any, msg ...any) bool {
	t.Helper()
	return t.report2(actual, expected, msg,
		!isLess(actual, expected))
}

// GE is a synonym for GreaterOrEqual.
func (t *C) GE(actual, expected any, msg ...any) bool {
	t.Helper()
	return t.GreaterOrEqual(actual, expected, msg...)
}

// Between checks for min < actual < max.
//
// All three actual, min and max must be either:
//   - signed integers
//   - unsigned integers
//   - floats
//   - strings
//   - time.Time
func (t *C) Between(actual, minimum, maximum any, msg ...any) bool {
	t.Helper()
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
//   - time.Time
func (t *C) NotBetween(actual, minimum, maximum any, msg ...any) bool {
	t.Helper()
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
//   - time.Time
func (t *C) BetweenOrEqual(actual, minimum, maximum any, msg ...any) bool {
	t.Helper()
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
//   - time.Time
func (t *C) NotBetweenOrEqual(actual, minimum, maximum any, msg ...any) bool {
	t.Helper()
	return t.report3(actual, minimum, maximum, msg,
		!(isBetween(actual, minimum, maximum) || isEqual(actual, minimum) || isEqual(actual, maximum)))
}

// InDelta checks for expected-delta <= actual <= expected+delta.
//
// All three actual, expected and delta must be either:
//   - signed integers
//   - unsigned integers
//   - floats
//   - time.Time (in this case delta must be time.Duration)
func (t *C) InDelta(actual, expected, delta any, msg ...any) bool {
	t.Helper()
	return t.report3(actual, expected, delta, msg,
		isInDelta(actual, expected, delta))
}

func isInDelta(actual, expected, delta any) bool {
	switch v, e, d := reflect.ValueOf(actual), reflect.ValueOf(expected), reflect.ValueOf(delta); v.Kind() { //nolint:exhaustive // Covered by default case.
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		minimum, maximum := e.Int()-d.Int(), e.Int()+d.Int()
		return minimum <= v.Int() && v.Int() <= maximum
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		minimum, maximum := e.Uint()-d.Uint(), e.Uint()+d.Uint()
		return minimum <= v.Uint() && v.Uint() <= maximum
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
//   - time.Time (in this case delta must be time.Duration)
func (t *C) NotInDelta(actual, expected, delta any, msg ...any) bool {
	t.Helper()
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
func (t *C) InSMAPE(actual, expected any, smape float64, msg ...any) bool {
	t.Helper()
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
func (t *C) NotInSMAPE(actual, expected any, smape float64, msg ...any) bool {
	t.Helper()
	return t.report3(actual, expected, smape, msg,
		!isInSMAPE(actual, expected, smape))
}

// HasPrefix checks for strings.HasPrefix(actual, expected).
//
// Both actual and expected may have any of these types:
//   - string       - will use as is
//   - []byte       - will convert with string()
//   - []rune       - will convert with string()
//   - fmt.Stringer - will convert with actual.String()
//   - error        - will convert with actual.Error()
//   - nil          - check will always fail
func (t *C) HasPrefix(actual, expected any, msg ...any) bool {
	t.Helper()
	ok := isHasPrefix(&actual, &expected)
	return t.report2(actual, expected, msg,
		ok)
}

// isHasPrefix updates actual and expected to be a real string used for check,
// to make dump easier to understand, but this result in losing type information.
func isHasPrefix(actual, expected *any) bool { //nolint:gocritic // False positive.
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
func (t *C) NotHasPrefix(actual, expected any, msg ...any) bool {
	t.Helper()
	ok := !isHasPrefix(&actual, &expected)
	return t.report2(actual, expected, msg,
		ok)
}

// HasSuffix checks for strings.HasSuffix(actual, expected).
//
// Both actual and expected may have any of these types:
//   - string       - will use as is
//   - []byte       - will convert with string()
//   - []rune       - will convert with string()
//   - fmt.Stringer - will convert with actual.String()
//   - error        - will convert with actual.Error()
//   - nil          - check will always fail
func (t *C) HasSuffix(actual, expected any, msg ...any) bool {
	t.Helper()
	ok := isHasSuffix(&actual, &expected)
	return t.report2(actual, expected, msg,
		ok)
}

// isHasSuffix updates actual and expected to be a real string used for check,
// to make dump easier to understand, but this result in losing type information.
func isHasSuffix(actual, expected *any) bool { //nolint:gocritic // False positive.
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
func (t *C) NotHasSuffix(actual, expected any, msg ...any) bool {
	t.Helper()
	ok := !isHasSuffix(&actual, &expected)
	return t.report2(actual, expected, msg,
		ok)
}

// JSONEqual normalize formatting of actual and expected (if they're valid
// JSON) and then checks for bytes.Equal(actual, expected).
//
// Both actual and expected may have any of these types:
//   - string
//   - []byte
//   - json.RawMessage
//   - *json.RawMessage
//   - nil
//
// In case any of actual or expected is nil or empty or (for string or
// []byte) is invalid JSON - check will fail.
func (t *C) JSONEqual(actual, expected any, msg ...any) bool {
	t.Helper()
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
func (t *C) HasType(actual, expected any, msg ...any) bool {
	t.Helper()
	return t.report2(actual, expected, msg,
		reflect.TypeOf(actual) == reflect.TypeOf(expected))
}

// NotHasType checks is actual has not same type as expected.
func (t *C) NotHasType(actual, expected any, msg ...any) bool {
	t.Helper()
	return t.report2(actual, expected, msg,
		reflect.TypeOf(actual) != reflect.TypeOf(expected))
}

// Implements checks is actual implements interface pointed by expected.
//
// You must use pointer to interface type in expected:
//
//	t.Implements(os.Stdin, (*io.Reader)(nil))
func (t *C) Implements(actual, expected any, msg ...any) bool {
	t.Helper()
	return t.report2(actual, expected, msg,
		isImplements(actual, expected))
}

func isImplements(actual, expected any) bool {
	typActual := reflect.TypeOf(actual)
	if typActual.Kind() != reflect.Ptr {
		typActual = reflect.PointerTo(typActual)
	}
	return typActual.Implements(reflect.TypeOf(expected).Elem())
}

// NotImplements checks is actual does not implements interface pointed by expected.
//
// You must use pointer to interface type in expected:
//
//	t.NotImplements(os.Stdin, (*fmt.Stringer)(nil))
func (t *C) NotImplements(actual, expected any, msg ...any) bool {
	t.Helper()
	return t.report2(actual, expected, msg,
		!isImplements(actual, expected))
}
