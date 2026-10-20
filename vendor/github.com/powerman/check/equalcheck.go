package check

import (
	"sync"

	"github.com/powerman/check/internal/deepequal"
)

//nolint:gochecknoglobals // Registry of custom equal checkers.
var (
	equalCheckersMu sync.RWMutex
	equalCheckers   []EqualChecker
)

// EqualChecker compares two values for DeepEqual/NotDeepEqual.
// ok=false means "this checker does not apply to this pair"
// and the next registered checker (then the built-in logic) is consulted.
type EqualChecker func(actual, expected any) (equal, ok bool)

// ResetEqualCheckers removes all registered equal checkers.
//
// Combine with RegisterEqualChecker to define a custom chain in a specific order.
//
// Intended for TestMain.
// Not safe to call concurrently with running checks.
func ResetEqualCheckers() {
	equalCheckersMu.Lock()
	defer equalCheckersMu.Unlock()
	equalCheckers = nil
}

// RegisterEqualChecker adds a custom equal comparison strategy
// used by DeepEqual and NotDeepEqual.
// Checkers run in registration order before built-in logic.
//
// Intended to be called from init() or TestMain.
// Not safe to call concurrently with running checks.
func RegisterEqualChecker(f EqualChecker) {
	equalCheckersMu.Lock()
	defer equalCheckersMu.Unlock()
	equalCheckers = append(equalCheckers, f)
}

// runEqualCheckers iterates registered checkers with the original actual/expected values.
// Returns (equal, ok) where ok=true means a checker claimed this pair.
func runEqualCheckers(actual, expected any) (equal, ok bool) {
	equalCheckersMu.RLock()
	defer equalCheckersMu.RUnlock()
	for _, check := range equalCheckers {
		if eq, claimed := check(actual, expected); claimed {
			return eq, true
		}
	}
	return false, false
}

// elemEqual reports whether a and b are equal for element/value comparison
// (used by SortEqual and Subset): registered EqualCheckers run first,
// falling back to [deepequal.DeepEqual], exactly like DeepEqual/NotDeepEqual do.
func elemEqual(a, b any) bool {
	equal, claimed := runEqualCheckers(a, b)
	if !claimed {
		if hasMethod(a, "ProtoReflect") || hasMethod(b, "ProtoReflect") {
			panic("check: protobuf message detected; " +
				"import github.com/powerman/checkproto to compare protobuf messages")
		}
		equal = deepequal.DeepEqual(a, b)
	}
	return equal
}
