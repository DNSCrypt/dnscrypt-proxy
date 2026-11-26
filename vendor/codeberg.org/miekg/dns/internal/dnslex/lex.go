package dnslex

import (
	"bytes"
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
	Value  uint8  // value: String, Blank, etc.
	Line   int    // line in the file
	Column int    // column in the file
	Torc   uint16 // type or class as parsed in the lexer, we only need to look this up in the grammar
}

// Lexer tokenizes the zone data, so that the grammar implemented in ZoneParser can parse RRs out of an RFC
// 1035 styled text file.
type Lexer struct {
	line   int
	column int
	brace  uint8
	keys   uint8 // bit0: kQuote, bit1: kSpace, bit2: kCommt, bit3: kRRtype, bit4: kOwner, bit5: kNextL, bit6: kEol
	tok    []byte

	r       io.Reader
	buf     []byte // chunk read from r, buf[pos:end] is not consumed yet
	pos     int
	end     int
	bufErr  error // error r returned together with buf, it becomes readErr once buf is consumed
	readErr error

	// Current or peek token.
	l       Lex
	cachedL Lex  // used when finding a token, but delaying it's return.
	cached  bool // cachedL is active.

	stringToType  map[string]uint16
	stringToClass map[string]uint16

	owner  string      // the previous owner name
	tokens *[64]string // the strings of TTL, class and type tokens we returned, see [Lexer.token], nil for short inputs.
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

// SetType sets the lexer state for input that is only rdata text, i.e. no owner name, TTL,
// class or type precedes it. Callers feeding such input must call this right after [New].
// The RR type is marked as already seen, so that rdata tokens that look like a type or class
// (e.g. "A NS" in an NSEC or CSYNC type bitmap) are returned as plain strings rather than
// [Rrtype] or [Class].
func (zl *Lexer) SetType() {
	zl.SetKey(kRRtype)
}

// New returns a pointer to a new Lexer.
func New(r io.Reader, StringToType, StringToClass map[string]uint16) *Lexer {
	size := 4096
	if l, ok := r.(interface{ Len() int }); ok { // short input, i.e. a single RR from a string, check if we have Len - which a string has for instance.
		size = min(max(l.Len(), 1), size)
	}
	zl := &Lexer{
		r:             r,
		buf:           make([]byte, size),
		tok:           make([]byte, 512),
		line:          1,
		stringToType:  StringToType,
		stringToClass: StringToClass,
	}
	zl.SetKey(kOwner)
	if size == 4096 { // not worth it for a single RR
		zl.tokens = new([64]string)
	}
	return zl
}

// token returns zl.tok as a string, for the tokens between the owner name and the rdata: the TTL, class and
// type. A zone only has a few distinct ones, so we keep the strings we made, at an index derived from their
// contents, and return such a string again when the token is equal to it, instead of allocating a new one.
func (zl *Lexer) token() string {
	n := len(zl.tok)
	if zl.tokens == nil || n == 0 {
		return string(zl.tok)
	}
	// A cheap index: the length, and the first, middle and last byte.
	// This is your typical multiply with primes to get a unique number.
	i := uint(n)*131 + uint(zl.tok[0])*31 + uint(zl.tok[n/2])*7 + uint(zl.tok[n-1])
	s := &zl.tokens[i%uint(len(zl.tokens))]
	if *s != string(zl.tok) { // this comparison does not allocate
		*s = string(zl.tok)
	}
	return *s
}

// Exact makes the lexer consume no more of an [io.ByteReader] than the tokens it returns, by reading a single
// byte at a time. Without it the lexer reads ahead. It must be called before the first token is read.
func (zl *Lexer) Exact() {
	if _, ok := zl.r.(io.ByteReader); ok {
		zl.buf = zl.buf[:1]
	}
}

func (zl *Lexer) Err() error {
	if zl.readErr == io.EOF {
		return nil
	}

	return zl.readErr
}

// plain are the bytes that have no special meaning for the lexer, they are just added to the token.
var plain = func() (t [256]bool) {
	for i := range t {
		t[i] = true
	}
	for _, c := range []byte(" \t;\r\n\\\"()") {
		t[c] = false
	}
	return t
}()

// skipComment skips what is left of a comment in the current chunk, up to the newline that ends it. It
// returns the column we are then at.
func (zl *Lexer) skipComment() int {
	n := bytes.IndexByte(zl.buf[zl.pos:zl.end], '\n')
	if n < 0 {
		n = zl.end - zl.pos
	}
	zl.pos += n
	zl.column += n
	return zl.column
}

// readByte returns the next byte from the input.
func (zl *Lexer) readByte() (byte, bool) {
	if zl.readErr != nil {
		return 0, false
	}

	for zl.pos == zl.end { // read the next chunk
		if zl.bufErr != nil {
			zl.readErr = zl.bufErr
			return 0, false
		}
		zl.pos = 0
		zl.end, zl.bufErr = zl.r.Read(zl.buf)
	}
	c := zl.buf[zl.pos]
	zl.pos++

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

// Blank consumes the next token and returns false if the token was not a blacnk
func (zl *Lexer) Blank() bool { l, _ := zl.Next(); return l.Value == Blank }

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
		zl.cachedL, zl.cached = l, true
		return l
	}

	// In this case l == zl.l, so we just tell Next to return zl.l.
	zl.SetKey(kNextL)
	return l
}

func (zl *Lexer) Next() (Lex, bool) {
	l := &zl.l
	switch {
	case zl.cached:
		zl.cached = false
		return zl.cachedL, true
	case zl.Key(kNextL):
		zl.ClearKey(kNextL)
		return *l, true
	case l.Value == Error:
		// Parsing errors should be sticky.
		return Lex{Value: EOF}, false
	}

	zl.tok = zl.tok[:0]
	escape := false

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
					// Consecutive RRs often have the same owner name, use the string we already have.
					if zl.owner != string(zl.tok) { // this comparison does not allocate
						zl.owner = string(zl.tok)
					}
					l.Token = zl.owner
					l.Value = directive(l.Token)

					retL = *l
				} else {
					l.Value = String
					if zl.Key(kRRtype) {
						l.Token = string(zl.tok)
					} else {
						l.Token = zl.token()
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
			l.Column = zl.skipComment()
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
				// Take the ordinary bytes that follow in one go, instead of one per loop.
				b := zl.buf[zl.pos:zl.end]
				n := 0
				for n < len(b) && plain[b[n]] {
					n++
				}
				zl.tok = append(zl.tok, b[:n]...)
				zl.pos += n
				zl.column += n
				l.Column = zl.column
			} else {
				l.Column = zl.skipComment()
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

// Ignore ignores the rest of the line, i.e. Nexts until a [Newline] is seen.
func Ignore(c *Lexer) {
	for l, ok := c.Next(); l.Value != Newline && ok; l, ok = c.Next() {
	}
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
