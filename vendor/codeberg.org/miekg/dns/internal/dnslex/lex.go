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
	Error
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
	As     uint8  // create an RR (asRR), an EDNS0 (asCode) or DSO RR (asStateful)
	Value  uint8  // value: String, Blank, etc.
	Line   uint32 // line in the file
	Column uint16 // column in the file
	Torc   uint16 // type or class as parsed in the lexer, we only need to look this up in the grammar
}

const (
	asRR       uint8 = iota // parse the string as an RR.
	asCode                  // parse the string as an EDNS RR.
	asStateful              // TODO, but parse the string as an DSO RR.
)

// Lexer tokenizes the zone data, so that the grammar implemented in ZoneParser can parse RRs out of an RFC
// 1035 styled text file.
type Lexer struct {
	line   uint32 // yes this overflows for insane zone files...
	column uint16
	brace  uint8
	keys   uint8 // bit0: kQuote, bit1: kSpace, bit2: kCommt, bit3: kRRtype, bit4: kOwner, bit5: kNextL, bit6: kEol
	tok    []byte

	br      io.ByteReader
	readErr error

	// Current or peek token.
	l       Lex
	cachedL *Lex // used when finding a token, but delaying it's return.

	stringToType  map[string]uint16
	stringToCode  map[string]uint16
	stringToClass map[string]uint16
}

// Key bit definitions.
const (
	kQuote uint8 = 1 << iota
	kSpace
	kCommt
	kRRtype
	kOwner
	kNextL
	kEOL
)

func (zl *Lexer) SetKey(key uint8)   { zl.keys |= key }
func (zl *Lexer) ClearKey(key uint8) { zl.keys &^= key }
func (zl *Lexer) Key(key uint8) bool { return zl.keys&key != 0 }

// New returns a pointer to a new Lexer.
func New(r io.Reader, StringToType, StringToCode, StringToClass map[string]uint16) *Lexer {
	br, ok := r.(io.ByteReader)
	if !ok {
		br = bufio.NewReaderSize(r, 1024)
	}

	zl := &Lexer{
		br:            br,
		tok:           make([]byte, 512),
		line:          1,
		stringToType:  StringToType,
		stringToCode:  StringToCode,
		stringToClass: StringToClass,
	}
	zl.SetKey(kOwner)
	return zl
}

func (zl *Lexer) Err() error {
	if zl.readErr == io.EOF {
		return nil
	}

	return zl.readErr
}

// readByte returns the next byte from the input.
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
	if zl.Key(kEOL) {
		zl.line++
		zl.column = 0
		zl.ClearKey(kEOL)
	}

	if c == '\n' {
		zl.SetKey(kEOL)
		return c, true
	}

	zl.column++
	return c, true
}

func (zl *Lexer) Peek() Lex {
	if zl.Key(kNextL) {
		return zl.l
	}

	l, ok := zl.Next()
	if !ok {
		return l
	}

	if zl.Key(kNextL) {
		// Cache l. Next returns zl.cachedL then zl.l.
		zl.cachedL = &l
		return l
	}

	// In this case l == zl.l, so we just tell Next to return zl.l.
	zl.SetKey(kNextL)
	return l
}

func (zl *Lexer) Next() (Lex, bool) {
	l := &zl.l
	switch {
	case zl.cachedL != nil:
		l, zl.cachedL = zl.cachedL, nil
		return *l, true
	case zl.Key(kNextL):
		zl.ClearKey(kNextL)
		return *l, true
	case l.Value == Error:
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
			if escape || zl.Key(kQuote) {
				zl.tok = append(zl.tok, x)
				escape = false
				continue
			}

			if zl.Key(kCommt) {
				continue
			}

			var retL Lex
			if len(zl.tok) > 0 {
				if zl.Key(kOwner) {

					l.Token = string(zl.tok)
					l.Value = directive(l.Token)

					retL = *l
				} else {
					l.Value = String
					l.Token = string(zl.tok)

					if !zl.Key(kRRtype) {
						zl.typeOrCodeOrClass(l)
					}
					retL = *l
				}
			}

			zl.ClearKey(kOwner)

			if !zl.Key(kSpace) {
				zl.SetKey(kSpace)

				l.Value = Blank
				l.Token = " "

				if retL.Value == EOF { // empty
					return *l, true
				}

				zl.SetKey(kNextL)
			}

			if retL.Value != EOF { // not empty
				return retL, true
			}
		case ';':
			if escape || zl.Key(kQuote) {
				// Inside quotes or escaped this is legal.
				zl.tok = append(zl.tok, x)
				escape = false
				continue
			}

			zl.SetKey(kCommt)

			if len(zl.tok) > 0 {
				l.Value = String
				l.Token = string(zl.tok)
				return *l, true
			}
		case '\r':
			escape = false

			if zl.Key(kQuote) {
				zl.tok = append(zl.tok, x)
			}

			// discard if outside of quotes
		case '\n':
			escape = false

			// Escaped newline
			if zl.Key(kQuote) {
				zl.tok = append(zl.tok, x)
				continue
			}

			if zl.Key(kCommt) {
				zl.ClearKey(kCommt)
				zl.ClearKey(kRRtype)

				if zl.brace == 0 {
					zl.SetKey(kOwner)

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

					if !zl.Key(kRRtype) {
						zl.typeOrCodeOrClass(l)
					}

					retL = *l
				}

				l.Value = Newline
				l.Token = "\n"

				zl.ClearKey(kRRtype)
				zl.SetKey(kOwner)

				if retL.Value != EOF { // not empty
					zl.SetKey(kNextL)
					return retL, true
				}

				return *l, true
			}
		case '\\':
			// comments do not get escaped chars, everything is copied
			if zl.Key(kCommt) {
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
			if zl.Key(kCommt) {
				continue
			}

			if escape {
				zl.tok = append(zl.tok, x)
				escape = false
				continue
			}

			zl.ClearKey(kSpace)

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

			if zl.Key(kQuote) {
				zl.ClearKey(kQuote)
			} else {
				zl.SetKey(kQuote)
			}

			if retL.Value == String {
				zl.SetKey(kNextL)
				return retL, true
			}

			return *l, true
		case '(', ')':
			if zl.Key(kCommt) {
				continue
			}

			if escape || zl.Key(kQuote) {
				// Inside quotes or escaped this is legal.
				zl.tok = append(zl.tok, x)
				escape = false
				continue
			}

			switch x {
			case ')':
				if zl.brace == 0 {
					l.Token = "extra closing brace"
					l.Value = Error
					return *l, true
				}
				zl.brace--

			case '(':
				zl.brace++
				if zl.brace > 10 {
					l.Token = "excessive opening braces"
					l.Value = Error
					return *l, true
				}
			}
		default:
			escape = false
			if !zl.Key(kCommt) {
				zl.tok = append(zl.tok, x)
				zl.ClearKey(kSpace)
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
		l.Value = Error
		return *l, true
	}

	return Lex{Value: EOF}, false
}

// Extract the class number from CLASSxx
func classToInt(token string) (uint16, bool) {
	class, err := strconv.Atoi(token[5:])
	return uint16(class), err == nil && class >= 0
}

// Extract the rr number from TYPExxx. There is no length check, it is assumed the caller has checked the
// prefix is at least "TYPE" (4)
func TypeToInt(token string) (uint16, bool) {
	typ, err := strconv.Atoi(token[4:])
	return uint16(typ), err == nil && typ >= 0
}

// Discard discards the rest of the "line".
func Discard(c *Lexer) *ScanError {
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
	for {
		l, _ := c.Next()
		switch l.Value {
		case Blank:
		case Newline, EOF:
			return tokens
		default:
			tokens = append(tokens, l.Token)
		}
	}
}

// upperLookup will defer strings.ToUpper in the map lookup, until after the lookup has occurred and nothing
// was found.
func upperLookup(s string, m map[string]uint16) (uint16, bool) {
	if t, ok := m[s]; ok {
		return t, true
	}
	t, ok := m[strings.ToUpper(s)]
	return t, ok
}

// typeOrCodeOrClass returns the type, or code, or TYPExxxx, or class, or CLASSxxxx, from the current token in
// l. The check happens in that order.
func (zl *Lexer) typeOrCodeOrClass(l *Lex) {
	if t, ok := upperLookup(l.Token, zl.stringToType); ok {
		l.Value = Rrtype
		l.Torc = t
		zl.SetKey(kRRtype)
		return
	}

	if t, ok := zl.stringToClass[l.Token]; ok {
		l.Value = Class
		l.Torc = t
		return
	}

	if strings.HasPrefix(l.Token, "TYPE") {
		t, ok := TypeToInt(l.Token)
		if !ok {
			l.Token = "unknown RR type"
			l.Value = Error
			return
		}
		l.Value = Rrtype
		l.Torc = t
		zl.SetKey(kRRtype)
		return
	}

	if strings.HasPrefix(l.Token, "CLASS") {
		t, ok := classToInt(l.Token)
		if !ok {
			l.Token = "unknown class"
			l.Value = Error
			return
		}
		l.Value = Class
		l.Torc = t
	}

	if t, ok := zl.stringToCode[l.Token]; ok {
		l.As = asCode
		l.Value = Rrtype
		l.Torc = t
		zl.SetKey(kRRtype)
		return
	}
}

func directive(s string) uint8 {
	if s[0] != '$' {
		return Owner
	}
	dir, ok := dirMap[s]
	if ok {
		return dir
	}
	return Owner
}

var dirMap = map[string]uint8{
	"$TTL":      DirTTL,
	"$ORIGIN":   DirOrigin,
	"$INCLUDE":  DirInclude,
	"$GENERATE": DirGenerate,
}
