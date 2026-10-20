package check

import (
	"sync"
)

//nolint:gochecknoglobals // Registry of custom error checkers.
var (
	errCheckersMu sync.RWMutex
	errCheckers   []ErrChecker
)

// ErrChecker compares actual and expected errors.
// ok=false means "this checker does not apply to this pair"
// and the next registered checker (then the built-in logic) is consulted.
type ErrChecker func(actual, expected error) (equal, ok bool)

// ResetErrCheckers removes all registered error checkers,
// including the built-in CheckFieldError.
//
// Combine with RegisterErrChecker to define a custom chain in a specific order.
//
// Intended for TestMain.
// Not safe to call concurrently with running checks.
func ResetErrCheckers() {
	errCheckersMu.Lock()
	defer errCheckersMu.Unlock()
	errCheckers = nil
}

// RegisterErrChecker adds a custom error comparison strategy used by Err and NotErr.
// Checkers run in registration order before built-in logic.
//
// Intended to be called from init() or TestMain.
// Not safe to call concurrently with running checks.
func RegisterErrChecker(f ErrChecker) {
	errCheckersMu.Lock()
	defer errCheckersMu.Unlock()
	errCheckers = append(errCheckers, f)
}

// runCheckers iterates registered checkers with the original actual/expected errors.
// Returns (equal, ok) where ok=true means a checker claimed this pair.
func runCheckers(actual, expected error) (equal, ok bool) {
	errCheckersMu.RLock()
	defer errCheckersMu.RUnlock()
	for _, check := range errCheckers {
		if eq, claimed := check(actual, expected); claimed {
			return eq, true
		}
	}
	return false, false
}
