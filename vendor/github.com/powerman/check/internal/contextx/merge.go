// Package contextx merges two [context.Context] values into one
// that looks up values in both and is cancelled when either one is.
//
// Vendored from github.com/powerman/contextx (MIT licensed, same author)
// to avoid an external dependency for check's own [check.TB.MergeContext].
package contextx

import (
	"context"
	"time"
)

// Values is an interface capturing only the value-lookup behavior of a [context.Context].
// It lets [MergeValues] accept any value carrier, not just a full context.
type Values interface {
	// Value returns the value associated with key, or nil if there is none.
	Value(key any) any
}

// Merge returns a context that combines parent and extra:
// it looks up values in both (parent takes precedence)
// and is cancelled as soon as either parent or extra is cancelled,
// or the returned cancel is called.
// Its deadline is the earlier of parent's and extra's.
//
// It is shorthand for MergeCancel(MergeValues(parent, extra), extra)
// and implements, for two contexts, the merge semantics of the rejected proposal
// https://github.com/golang/go/issues/36503.
//
// Always call cancel to release resources once the merged context is no longer needed,
// even if it has already been cancelled by parent or extra.
func Merge(parent, extra context.Context) (ctx context.Context, cancel context.CancelFunc) {
	return MergeCancel(MergeValues(parent, extra), extra)
}

type mergedValues struct {
	context.Context

	extra Values
}

// MergeValues returns a context that behaves exactly like parent
// but also looks up values in extra for keys absent in parent.
// Cancellation, deadline, and Err come solely from parent; extra contributes values only.
//
// Because no cancellation is merged, MergeValues never starts a goroutine
// and has nothing to release, so it returns no cancel function.
func MergeValues(parent context.Context, extra Values) context.Context {
	return &mergedValues{Context: parent, extra: extra}
}

func (c *mergedValues) Value(key any) any {
	if v := c.Context.Value(key); v != nil {
		return v
	}
	return c.extra.Value(key)
}

type mergedCancel struct {
	context.Context

	extra context.Context
}

// MergeCancel returns a context derived from parent that is also cancelled
// when extra is cancelled, whichever happens first, or when the returned cancel is called.
// Values come solely from parent; extra contributes only its cancellation and deadline.
// The returned context's deadline is the earlier of parent's and extra's,
// and its cancellation [context.Cause] is the cause of whichever context cancelled it first.
//
// MergeCancel uses [context.AfterFunc], so it starts no goroutine.
// Always call cancel to release that registration once the merged context is no longer needed,
// even if it has already been cancelled by parent or extra.
func MergeCancel(parent, extra context.Context) (ctx context.Context, cancel context.CancelFunc) {
	merged, cancelCause := context.WithCancelCause(parent)
	stop := context.AfterFunc(extra, func() {
		cancelCause(context.Cause(extra))
	})
	return &mergedCancel{Context: merged, extra: extra}, func() {
		stop()
		cancelCause(context.Canceled)
	}
}

func (c *mergedCancel) Deadline() (deadline time.Time, ok bool) {
	d1, ok1 := c.Context.Deadline()
	d2, ok2 := c.extra.Deadline()
	switch {
	case !ok2:
		return d1, ok1
	case !ok1:
		return d2, ok2
	case d2.Before(d1):
		return d2, true
	default:
		return d1, ok1
	}
}
