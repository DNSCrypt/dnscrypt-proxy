package http2

import (
	"errors"
	"fmt"
	"strconv"
)

// ErrorCode defines the HTTP/2 error codes:
//
// Error codes are defined here http://httpwg.org/specs/rfc7540.html#ErrorCodes
//
// Errors must be uint32 because of FrameReset.
type ErrorCode uint32

const (
	NoError              ErrorCode = 0x0
	ProtocolError        ErrorCode = 0x1
	InternalError        ErrorCode = 0x2
	FlowControlError     ErrorCode = 0x3
	SettingsTimeoutError ErrorCode = 0x4
	StreamClosedError    ErrorCode = 0x5
	FrameSizeError       ErrorCode = 0x6
	RefusedStreamError   ErrorCode = 0x7
	StreamCanceled       ErrorCode = 0x8
	CompressionError     ErrorCode = 0x9
	ConnectionError      ErrorCode = 0xa
	EnhanceYourCalm      ErrorCode = 0xb
	InadequateSecurity   ErrorCode = 0xc
	HTTP11Required       ErrorCode = 0xd
)

var errStr = [...]string{
	NoError:              "NoError",
	ProtocolError:        "ProtocolError",
	InternalError:        "InternalError",
	FlowControlError:     "FlowControlError",
	SettingsTimeoutError: "SettingsTimeoutError",
	StreamClosedError:    "StreamClosedError",
	FrameSizeError:       "FrameSizeError",
	RefusedStreamError:   "RefusedStreamError",
	StreamCanceled:       "StreamCanceled",
	CompressionError:     "CompressionError",
	ConnectionError:      "ConnectionError",
	EnhanceYourCalm:      "EnhanceYourCalm",
	InadequateSecurity:   "InadequateSecurity",
	HTTP11Required:       "HTTP11Required",
}

func (e ErrorCode) String() string {
	if int(e) >= len(errStr) {
		return "Unknown"
	}

	return errStr[e]
}

// Error implements the error interface.
func (e ErrorCode) Error() string {
	if int(e) < len(errParser) {
		return errParser[e]
	}

	return strconv.Itoa(int(e))
}

// Error defines the HTTP/2 errors, composed by the code and debug data.
type Error struct {
	code      ErrorCode
	frameType FrameType
	debug     string
}

// Is implements the interface for errors.Is.
func (e Error) Is(target error) bool {
	return errors.Is(e.code, target)
}

// Code returns the error code.
func (e Error) Code() ErrorCode {
	return e.code
}

// Debug returns the debug string.
func (e Error) Debug() string {
	return e.debug
}

// NewError creates a new Error.
func NewError(e ErrorCode, debug string) Error {
	return Error{
		code:      e,
		debug:     debug,
		frameType: FrameResetStream,
	}
}

func NewGoAwayError(e ErrorCode, debug string) Error {
	return Error{
		code:      e,
		debug:     debug,
		frameType: FrameGoAway,
	}
}

func NewResetStreamError(e ErrorCode, debug string) Error {
	return Error{
		code:      e,
		debug:     debug,
		frameType: FrameResetStream,
	}
}

// Error implements the error interface.
func (e Error) Error() string {
	return fmt.Sprintf("%s: %s", e.code, e.debug)
}

var (
	errParser = []string{
		NoError:              "No errors",
		ProtocolError:        "Protocol error",
		InternalError:        "Internal error",
		FlowControlError:     "Flow control error",
		SettingsTimeoutError: "Settings timeout",
		StreamClosedError:    "Stream have been closed",
		FrameSizeError:       "FrameHeader size error",
		RefusedStreamError:   "Refused Stream",
		StreamCanceled:       "Stream canceled",
		CompressionError:     "Compression error",
		ConnectionError:      "Connection error",
		EnhanceYourCalm:      "Enhance your calm",
		InadequateSecurity:   "Inadequate security",
		HTTP11Required:       "HTTP/1.1 required",
	}

	// ErrUnknownFrameType This error codes must be used with FrameGoAway.
	ErrUnknownFrameType = NewError(
		ProtocolError, "unknown frame type")
	ErrMissingBytes = NewError(
		ProtocolError, "missing payload bytes. Need more")
	ErrPayloadExceeds = NewError(
		FrameSizeError, "FrameHeader payload exceeds the negotiated maximum size")
	ErrCompression = NewGoAwayError(
		CompressionError, "Compression error")
)
