package dnslex

import (
	"bufio"
	"io"
	"strconv"
	"strings"
)

// ScanError is a scanning error, it has no presentation format, it is expected that ParseError will be
// wrapping this error, and uses Err and Lex directly.
type ScanError struct {
	Err string
	Lex Lex
}

func (e *ScanError) Error() string { return "" }

// Tokenize a RFC 1035 zone file. The tokenizer will normalize it:
// * Add ownernames if they are left blank;
// * Suppress sequences of spaces;
// * Make each RR fit on one line ([Newline] is send as last)
// * Handle braces - anywhere.
const (
	// Zone file
	EOF uint8 = iota
	String
	Blank
	Quote
	Newline
	Rrtype
	Owner
	Class
	DirOrigin   // $ORIGIN
	DirTTL      // $TTL
	DirInclude  // $INCLUDE
	DirGenerate // $GENERATE
)

type Lex struct {
	Token  string // text of the token
	Line   int    // line in the file
	Column int    // column in the file
	Torc   uint16 // type or class as parsed in the lexer, we only need to look this up in the grammar
	Err    bool   // when true, token text has lexer error
	Value  uint8  // value: String, Blank, etc.
	As     uint8  // create an RR (asRR), an EDNS0 (asCode) or DSO RR (asStateful)
}

const (
	asRR       uint8 = iota // parse the string as an RR.
	asCode                  // parse the string as an EDNS RR.
	asStateful              // TODO, but parse the string as an DSO RR.
)

// Lexer tokenizes the zone data, so that the grammar implemented in ZoneParser can parse RRs out of an RFC
// 1035 styled text file.
type Lexer struct {
	br  io.ByteReader
	tok []byte

	readErr error

	line   int
	column int

	l       Lex
	cachedL *Lex

	brace  int
	quote  bool
	space  bool
	commt  bool
	rrtype bool
	owner  bool

	nextL bool

	eol bool // end-of-line

	StringToType  map[string]uint16
	StringToCode  map[string]uint16
	StringToClass map[string]uint16
}

// New returns a pointer to a new Lexer.
func New(r io.Reader, StringToType, StringToCode, StringToClass map[string]uint16) *Lexer {
	br, ok := r.(io.ByteReader)
	if !ok {
		br = bufio.NewReaderSize(r, 1024)
	}

	return &Lexer{
		br:            br,
		tok:           make([]byte, 512),
		line:          1,
		owner:         true,
		StringToType:  StringToType,
		StringToCode:  StringToCode,
		StringToClass: StringToClass,
	}
}

func (zl *Lexer) Err() error {
	if zl.readErr == io.EOF {
		return nil
	}

	return zl.readErr
}

// readByte returns the next byte from the input
func (zl *Lexer) readByte() (byte, bool) {
	if zl.readErr != nil {
		return 0, false
	}

	c, err := zl.br.ReadByte()
	if err != nil {
		zl.readErr = err
		return 0, false
	}

	// delay the newline handling until the next token is delivered,
	// fixes off-by-one errors when reporting a parse error.
	if zl.eol {
		zl.line++
		zl.column = 0
		zl.eol = false
	}

	if c == '\n' {
		zl.eol = true
	} else {
		zl.column++
	}

	return c, true
}

func (zl *Lexer) Peek() Lex {
	if zl.nextL {
		return zl.l
	}

	l, ok := zl.Next()
	if !ok {
		return l
	}

	if zl.nextL {
		// Cache l. Next returns zl.cachedL then zl.l.
		zl.cachedL = &l
	} else {
		// In this case l == zl.l, so we just tell Next to return zl.l.
		zl.nextL = true
	}

	return l
}

func (zl *Lexer) Next() (Lex, bool) {
	l := &zl.l
	switch {
	case zl.cachedL != nil:
		l, zl.cachedL = zl.cachedL, nil
		return *l, true
	case zl.nextL:
		zl.nextL = false
		return *l, true
	case l.Err:
		// Parsing errors should be sticky.
		return Lex{Value: EOF}, false
	}

	zl.tok = zl.tok[:0]
	escape := false

	l.As = asRR

	for x, ok := zl.readByte(); ok; x, ok = zl.readByte() {
		l.Line, l.Column = zl.line, zl.column

		switch x {
		case ' ', '\t':
			if escape || zl.quote {
				zl.tok = append(zl.tok, x)
				escape = false
				continue
			}

			if zl.commt {
				continue
			}

			var retL Lex
			if len(zl.tok) > 0 {
				if zl.owner {
					// If we have a string and it's the first, make it an owner
					l.Value = Owner
					l.Token = string(zl.tok)

					// escape $... start with a \ not a $, so this will work
					switch l.Token {
					case "$TTL":
						l.Value = DirTTL
					case "$ORIGIN":
						l.Value = DirOrigin
					case "$INCLUDE":
						l.Value = DirInclude
					case "$GENERATE":
						l.Value = DirGenerate
					}

					retL = *l
				} else {
					l.Value = String
					l.Token = string(zl.tok)

					if !zl.rrtype {
						zl.typeOrCodeOrClass(l)
					}
					retL = *l
				}
			}

			zl.owner = false

			if !zl.space {
				zl.space = true

				l.Value = Blank
				l.Token = " "

				if retL.Value == EOF { // empty
					return *l, true
				}

				zl.nextL = true
			}

			if retL.Value != EOF { // not empty
				return retL, true
			}
		case ';':
			if escape || zl.quote {
				// Inside quotes or escaped this is legal.
				zl.tok = append(zl.tok, x)
				escape = false
				continue
			}

			zl.commt = true

			if len(zl.tok) > 0 {
				l.Value = String
				l.Token = string(zl.tok)
				return *l, true
			}
		case '\r':
			escape = false

			if zl.quote {
				zl.tok = append(zl.tok, x)
			}

			// discard if outside of quotes
		case '\n':
			escape = false

			// Escaped newline
			if zl.quote {
				zl.tok = append(zl.tok, x)
				continue
			}

			if zl.commt {
				zl.commt = false
				zl.rrtype = false

				if zl.brace == 0 {
					zl.owner = true

					l.Value = Newline
					l.Token = "\n"
					return *l, true
				}
				continue
			}

			if zl.brace == 0 {
				// If there is previous text, we should output it here
				var retL Lex
				if len(zl.tok) != 0 {
					l.Value = String
					l.Token = string(zl.tok)

					if !zl.rrtype {
						zl.typeOrCodeOrClass(l)
					}

					retL = *l
				}

				l.Value = Newline
				l.Token = "\n"

				zl.rrtype = false
				zl.owner = true

				if retL.Value != EOF { // not empty
					zl.nextL = true
					return retL, true
				}

				return *l, true
			}
		case '\\':
			// comments do not get escaped chars, everything is copied
			if zl.commt {
				continue
			}

			// something already escaped must be in string
			if escape {
				zl.tok = append(zl.tok, x)
				escape = false
				continue
			}

			// something escaped outside of string gets added to string
			zl.tok = append(zl.tok, x)
			escape = true
		case '"':
			if zl.commt {
				continue
			}

			if escape {
				zl.tok = append(zl.tok, x)
				escape = false
				continue
			}

			zl.space = false

			// send previous gathered text and the quote
			var retL Lex
			if len(zl.tok) != 0 {
				l.Value = String
				l.Token = string(zl.tok)

				retL = *l
			}

			// send quote itself as separate token
			l.Value = Quote
			l.Token = "\""

			zl.quote = !zl.quote

			if retL.Value == String {
				zl.nextL = true
				return retL, true
			}

			return *l, true
		case '(', ')':
			if zl.commt {
				continue
			}

			if escape || zl.quote {
				// Inside quotes or escaped this is legal.
				zl.tok = append(zl.tok, x)
				escape = false
				continue
			}

			switch x {
			case ')':
				zl.brace--

				if zl.brace < 0 {
					l.Token = "extra closing brace"
					l.Err = true
					return *l, true
				}
			case '(':
				zl.brace++
			}
		default:
			escape = false
			if !zl.commt {
				zl.tok = append(zl.tok, x)
				zl.space = false
			}
		}
	}

	if zl.readErr != nil && zl.readErr != io.EOF {
		// Don't return any tokens after a read error occurs.
		return Lex{Value: EOF}, false
	}

	if len(zl.tok) > 0 {
		// Send remainder of str
		l.Value = String
		l.Token = string(zl.tok)
		return *l, true
	}

	if zl.brace != 0 {
		l.Token = "unbalanced brace"
		l.Err = true
		return *l, true
	}

	return Lex{Value: EOF}, false
}

// Extract the class number from CLASSxx
func classToInt(token string) (uint16, bool) {
	class, err := strconv.ParseUint(token[5:], 10, 16)
	return uint16(class), err == nil
}

// Extract the rr number from TYPExxx. There is no length check, it is assumed the caller has checked the
// prefix is at least "TYPE" (4)
func TypeToInt(token string) (uint16, bool) {
	typ, err := strconv.ParseUint(token[4:], 10, 16)
	return uint16(typ), err == nil
}

// Remainer eats the rest of the "line".
func Remainder(c *Lexer) *ScanError {
	l, _ := c.Next()
	switch l.Value {
	case Blank:
		l, _ = c.Next()
		if l.Value != Newline && l.Value != EOF {
			return &ScanError{Err: "garbage after rdata", Lex: l}
		}
	case Newline:
	case EOF:
	default:
		return &ScanError{Err: "garbage after rdata", Lex: l}
	}
	return nil
}

// Tokens is used to gather up the remaining tokens and hand them to a custom Scan method for external RRs.
func Tokens(c *Lexer) []string {
	tokens := []string{}
	l, _ := c.Next()
	for {
		switch l.Value {
		case Blank:
		case Newline, EOF:
			return tokens
		default:
			tokens = append(tokens, l.Token)
		}
		l, _ = c.Next()
	}
}

func upperLookup(s string, m map[string]uint16) (uint16, bool) {
	if t, ok := m[s]; ok {
		return t, true
	}
	t, ok := m[strings.ToUpper(s)]
	return t, ok
}

func (zl *Lexer) typeOrCodeOrClass(l *Lex) {
	if t, ok := upperLookup(l.Token, zl.StringToType); ok {
		l.Value = Rrtype
		l.Torc = t
		zl.rrtype = true
		return
	}

	if t, ok := zl.StringToCode[l.Token]; ok {
		l.As = asCode
		l.Value = Rrtype
		l.Torc = t
		zl.rrtype = true
		return
	}

	if strings.HasPrefix(l.Token, "TYPE") {
		t, ok := TypeToInt(l.Token)
		if !ok {
			l.Token = "unknown RR type"
			l.Err = true
			return
		}
		l.Value = Rrtype
		l.Torc = t
		zl.rrtype = true
		return
	}

	// Check for class
	if t, ok := zl.StringToClass[l.Token]; ok {
		l.Value = Class
		l.Torc = t
		return
	}

	if strings.HasPrefix(l.Token, "CLASS") {
		t, ok := classToInt(l.Token)
		if !ok {
			l.Token = "unknown class"
			l.Err = true
			return
		}
		l.Value = Class
		l.Torc = t
	}
}
