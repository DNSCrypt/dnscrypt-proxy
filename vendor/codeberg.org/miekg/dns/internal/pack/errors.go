package pack

import "fmt"

// Error represents a packing error.
type Error struct{ Err string }

func (e *Error) Error() string { return "dns packing: " + e.Err }

func Errorf(format string, a ...any) *Error { return &Error{Err: fmt.Sprintf(format, a...)} }

var ErrBuf = &Error{Err: "buffer size too small"} // ErrBuf indicates that the buffer used is too small for the message.
