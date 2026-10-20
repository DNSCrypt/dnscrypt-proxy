package unpack

import "fmt"

// Error represents an unpacking error.
type Error struct{ Err string }

func (e *Error) Error() string { return "dns unpack: " + e.Err }

func Errorf(format string, a ...any) *Error { return &Error{Err: fmt.Sprintf(format, a...)} }

var (
	ErrOverflow         = &Error{Err: "overflow data"}
	ErrTruncatedMessage = &Error{Err: "overflow truncated message"}
	ErrTrailingData     = &Error{Err: "trailing record rdata"}
)
