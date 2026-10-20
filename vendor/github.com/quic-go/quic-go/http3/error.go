package http3

import (
	"errors"
	"fmt"

	"github.com/quic-go/quic-go"
)

// Error is returned, possibly wrapped, by [Stream] and [RequestStream] operations,
// [ClientConn.OpenRequestStream], [Transport.RoundTrip], [Transport.RoundTripOpt], and
// [ClientConn.RoundTrip] for HTTP clients, and from request-body reads and response
// writes inside HTTP handlers for HTTP servers, when an HTTP/3 error occurs.
// See section 8 of RFC 9114.
//
// An Error returned by this package wraps a [quic.StreamError] for stream
// cancellations or a [quic.ApplicationError] for connection closure.
// Other QUIC errors are returned without conversion to Error.
type Error struct {
	Remote       bool
	ErrorCode    ErrCode
	ErrorMessage string

	err error
}

var _ error = &Error{}

func (e *Error) Error() string {
	s := e.ErrorCode.string()
	if s == "" {
		s = fmt.Sprintf("H3 error (%#x)", uint64(e.ErrorCode))
	}
	// Usually errors are remote. Only make it explicit for local errors.
	if !e.Remote {
		s += " (local)"
	}
	if e.ErrorMessage != "" {
		s += ": " + e.ErrorMessage
	}
	return s
}

// Unwrap returns the underlying error.
func (e *Error) Unwrap() error { return e.err }

func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	return ok && e.ErrorCode == t.ErrorCode && e.Remote == t.Remote
}

func maybeReplaceError(err error) error {
	if err == nil {
		return nil
	}
	if _, ok := errors.AsType[*Error](err); ok {
		return err
	}
	if e, ok := errors.AsType[*quic.StreamError](err); ok {
		return &Error{
			Remote:    e.Remote,
			ErrorCode: ErrCode(e.ErrorCode),
			err:       err,
		}
	}
	if e, ok := errors.AsType[*quic.ApplicationError](err); ok {
		return &Error{
			Remote:       e.Remote,
			ErrorCode:    ErrCode(e.ErrorCode),
			ErrorMessage: e.ErrorMessage,
			err:          err,
		}
	}
	return err
}
