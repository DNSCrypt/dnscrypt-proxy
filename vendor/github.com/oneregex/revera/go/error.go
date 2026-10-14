package revera

// Error reports a compilation, execution, or replacement failure.
// A Code of ErrNone means success.
// The other values mirror the <regex.h> error constants.
type Error struct {
	Code int32
	// Pos is the byte offset of the error in the pattern, or in the replacement text for a replacement error.
	// It is -1 when the error has no position.
	Pos int
}

const (
	// ErrNone is the zero code: no error.
	ErrNone int32 = 0
	// ErrNoMatch: regexec() found no match.
	ErrNoMatch int32 = 1
	// ErrBadPat: invalid regular expression.
	ErrBadPat int32 = 2
	// ErrECollate: invalid collating element reference.
	ErrECollate int32 = 3
	// ErrECType: invalid character class reference.
	ErrECType int32 = 4
	// ErrEEscape: trailing backslash.
	ErrEEscape int32 = 5
	// ErrESubReg: invalid backreference, which ERE never uses.
	ErrESubReg int32 = 6
	// ErrEBrack: bracket imbalance.
	ErrEBrack int32 = 7
	// ErrEParen: parenthesis imbalance.
	ErrEParen int32 = 8
	// ErrEBrace: brace imbalance.
	ErrEBrace int32 = 9
	// ErrBadBR: invalid interval content.
	ErrBadBR int32 = 10
	// ErrERange: invalid range endpoint.
	ErrERange int32 = 11
	// ErrESpace: insufficient memory or capacity.
	ErrESpace int32 = 12
	// ErrBadRpt: repetition without a valid operand.
	ErrBadRpt int32 = 13
	// ErrENoSub is an extension with no <regex.h> counterpart.
	// A call needed match offsets from an expression compiled with FlagNoSub.
	ErrENoSub int32 = 14
)

// noError is the success value.
func noError() Error {
	var e Error
	e.Pos = -1
	return e
}

func compileError(code int32, pos int) Error {
	var e Error
	e.Code = code
	e.Pos = pos
	return e
}

// ErrorText returns a short printable message for the code.
func ErrorText(code int32) string {
	switch code {
	case ErrNone:
		return "success"
	case ErrNoMatch:
		return "no match"
	case ErrBadPat:
		return "invalid regular expression"
	case ErrECollate:
		return "invalid collating element"
	case ErrECType:
		return "invalid character class"
	case ErrEEscape:
		return "invalid or trailing backslash"
	case ErrESubReg:
		return "invalid backreference"
	case ErrEBrack:
		return "unbalanced bracket"
	case ErrEParen:
		return "unbalanced parenthesis"
	case ErrEBrace:
		return "unbalanced brace"
	case ErrBadBR:
		return "invalid interval"
	case ErrERange:
		return "invalid range endpoint"
	case ErrESpace:
		return "capacity limit reached"
	case ErrBadRpt:
		return "repetition without an operand"
	case ErrENoSub:
		return "offsets requested from a NoSub expression"
	default:
		return "unknown error"
	}
}
