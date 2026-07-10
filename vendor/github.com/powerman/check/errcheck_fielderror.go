package check

import (
	"errors"
	"reflect"
)

//nolint:gochecknoinits // Required for default CheckFieldError registration.
func init() {
	RegisterErrChecker(CheckFieldError)
}

// fieldError is a duck-typed interface for errors that carry per-field
// validation information, like validator.FieldError.
type fieldError interface {
	Namespace() string
	Tag() string
}

type fieldErrKey struct {
	ns, tag string
}

// CheckFieldError compares two errors that (possibly after [errors.As]-style unwrapping)
// are validator.FieldError-like values or slices of them,
// by an unordered multiset of (Namespace, Tag) pairs — order does not matter.
// Works with any type structurally providing Namespace()/Tag().
//
// Auto-registered on loading the package.
func CheckFieldError(actual, expected error) (equal, ok bool) {
	actualFEs, ok1 := extractFieldErrors(actual)
	expectedFEs, ok2 := extractFieldErrors(expected)
	if !ok1 || !ok2 {
		return false, false
	}
	if len(actualFEs) != len(expectedFEs) {
		return false, true
	}
	counts := make(map[fieldErrKey]int, len(expectedFEs))
	for _, fe := range expectedFEs {
		counts[fieldErrKey{fe.Namespace(), fe.Tag()}]++
	}
	for _, fe := range actualFEs {
		counts[fieldErrKey{fe.Namespace(), fe.Tag()}]--
	}
	for _, c := range counts {
		if c != 0 {
			return false, true
		}
	}
	return true, true
}

// extractFieldErrors walks the error tree looking for a value that
// (directly or after unwrapping) is a fieldError or a slice of fieldErrors.
// Returns the normalized slice and whether field errors were found.
func extractFieldErrors(err error) ([]fieldError, bool) {
	if err == nil {
		return nil, false
	}
	// Avoid calling methods on typed nil (e.g. (*net.OpError)(nil)) which may panic.
	v := reflect.ValueOf(err)
	if v.Kind() == reflect.Pointer && v.IsNil() {
		return nil, false
	}
	// Check if the error itself is a fieldError or a slice of fieldErrors.
	if fe, ok := err.(fieldError); ok {
		return []fieldError{fe}, true
	}
	if fes, ok := sliceFieldErrors(err); ok {
		return fes, true
	}
	// Walk the chain for a single fieldError.
	var fe fieldError
	if errors.As(err, &fe) {
		return []fieldError{fe}, true
	}
	// Walk the chain for a slice of fieldErrors.
	return walkFieldErrorSlice(err)
}

// sliceFieldErrors checks if err is a slice whose every element implements
// fieldError, and returns them as a normalized slice.
func sliceFieldErrors(err error) ([]fieldError, bool) {
	val := reflect.ValueOf(err)
	if val.Kind() != reflect.Slice {
		return nil, false
	}
	fes := make([]fieldError, 0, val.Len())
	for i := range val.Len() {
		elem := val.Index(i).Interface()
		fe, ok := elem.(fieldError)
		if !ok {
			return nil, false
		}
		fes = append(fes, fe)
	}
	return fes, true
}

// walkFieldErrorSlice walks the error chain looking for a slice of fieldErrors.
func walkFieldErrorSlice(err error) ([]fieldError, bool) {
	//nolint:errorlint // Structural interface checks, not error matching.
	switch u := err.(type) {
	case interface{ Unwrap() error }:
		return extractFieldErrors(u.Unwrap())
	case interface{ Unwrap() []error }:
		for _, e := range u.Unwrap() {
			if fes, ok := extractFieldErrors(e); ok {
				return fes, ok
			}
		}
	}
	return nil, false
}
