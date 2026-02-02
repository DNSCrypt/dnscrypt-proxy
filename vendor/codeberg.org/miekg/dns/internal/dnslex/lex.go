package dnslex

import (
	"bufio"
	"io"
	"math"
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

const maxTok = 512 // Token buffer start size, and growth size amount.

// Tokenize a RFC 1035 zone file. The tokenizer will normalize it:
// * Add ownernames if they are left blank;
// * Suppress sequences of spaces;
// * Make each RR fit on one line (_NEWLINE is send as last)
// * Handle comments: ;
// * Handle braces - anywhere.
const (
	// Zone file
	EOF = iota
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
	br io.ByteReader

	readErr error

	line   int
	column int

	comBuf  string
	comment string

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

	var (
		str = make([]byte, maxTok) // Hold string text
		com = make([]byte, maxTok) // Hold comment text

		stri int // Offset in str (0 means empty)
		comi int // Offset in com (0 means empty)

		escape bool
	)

	if zl.comBuf != "" {
		comi = copy(com[:], zl.comBuf)
		zl.comBuf = ""
	}

	zl.comment = ""
	l.As = asRR

	for x, ok := zl.readByte(); ok; x, ok = zl.readByte() {
		l.Line, l.Column = zl.line, zl.column

		if stri >= len(str) {
			// if buffer length is insufficient, increase it.
			str = append(str[:], make([]byte, maxTok)...)
		}
		if comi >= len(com) {
			// if buffer length is insufficient, increase it.
			com = append(com[:], make([]byte, maxTok)...)
		}

		switch x {
		case ' ', '\t':
			if escape || zl.quote {
				// Inside quotes or escaped this is legal.
				str[stri] = x
				stri++

				escape = false
				break
			}

			if zl.commt {
				com[comi] = x
				comi++
				break
			}

			var retL Lex
			if stri == 0 {
				// Space directly in the beginning, handled in the grammar
			} else if zl.owner {
				// If we have a string and it's the first, make it an owner
				l.Value = Owner
				l.Token = string(str[:stri])

				// escape $... start with a \ not a $, so this will work
				switch strings.ToUpper(l.Token) {
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
				l.Token = string(str[:stri])

				if !zl.rrtype {
					tokenUpper := strings.ToUpper(l.Token)
					if t, ok := zl.StringToType[tokenUpper]; ok {
						l.Value = Rrtype
						l.Torc = t

						zl.rrtype = true
					} else if t, ok := zl.StringToCode[tokenUpper]; ok {
						zl.rrtype = true
						l.As = asCode
						l.Value = Rrtype
						l.Torc = t
					} else if strings.HasPrefix(tokenUpper, "TYPE") {
						t, ok := typeToInt(l.Token)
						if !ok {
							l.Token = "unknown RR type"
							l.Err = true
							return *l, true
						}

						l.Value = Rrtype
						l.Torc = t

						zl.rrtype = true
					}

					if t, ok := zl.StringToClass[tokenUpper]; ok {
						l.Value = Class
						l.Torc = t
					} else if strings.HasPrefix(tokenUpper, "CLASS") {
						t, ok := classToInt(l.Token)
						if !ok {
							l.Token = "unknown class"
							l.Err = true
							return *l, true
						}

						l.Value = Class
						l.Torc = t
					}
				}

				retL = *l
			}

			zl.owner = false

			if !zl.space {
				zl.space = true

				l.Value = Blank
				l.Token = " "

				if retL == (Lex{}) {
					return *l, true
				}

				zl.nextL = true
			}

			if retL != (Lex{}) {
				return retL, true
			}
		case ';':
			if escape || zl.quote {
				// Inside quotes or escaped this is legal.
				str[stri] = x
				stri++

				escape = false
				break
			}

			zl.commt = true
			zl.comBuf = ""

			if comi > 1 {
				// A newline was previously seen inside a comment that
				// was inside braces and we delayed adding it until now.
				com[comi] = ' ' // convert newline to space
				comi++
				if comi >= len(com) {
					l.Token = "comment length insufficient for parsing"
					l.Err = true
					return *l, true
				}
			}

			com[comi] = ';'
			comi++

			if stri > 0 {
				zl.comBuf = string(com[:comi])

				l.Value = String
				l.Token = string(str[:stri])
				return *l, true
			}
		case '\r':
			escape = false

			if zl.quote {
				str[stri] = x
				stri++
			}

			// discard if outside of quotes
		case '\n':
			escape = false

			// Escaped newline
			if zl.quote {
				str[stri] = x
				stri++
				break
			}

			if zl.commt {
				// Reset a comment
				zl.commt = false
				zl.rrtype = false

				// If not in a brace this ends the comment AND the RR
				if zl.brace == 0 {
					zl.owner = true

					l.Value = Newline
					l.Token = "\n"
					zl.comment = string(com[:comi])
					return *l, true
				}

				zl.comBuf = string(com[:comi])
				break
			}

			if zl.brace == 0 {
				// If there is previous text, we should output it here
				var retL Lex
				if stri != 0 {
					l.Value = String
					l.Token = string(str[:stri])

					if !zl.rrtype {
						tokenUpper := strings.ToUpper(l.Token)
						if t, ok := zl.StringToType[tokenUpper]; ok {
							zl.rrtype = true
							l.Value = Rrtype
							l.Torc = t
						} else if t, ok := zl.StringToCode[tokenUpper]; ok {
							zl.rrtype = true
							l.As = asCode
							l.Value = Rrtype
							l.Torc = t
						}
					}

					retL = *l
				}

				l.Value = Newline
				l.Token = "\n"

				zl.comment = zl.comBuf
				zl.comBuf = ""
				zl.rrtype = false
				zl.owner = true

				if retL != (Lex{}) {
					zl.nextL = true
					return retL, true
				}

				return *l, true
			}
		case '\\':
			// comments do not get escaped chars, everything is copied
			if zl.commt {
				com[comi] = x
				comi++
				break
			}

			// something already escaped must be in string
			if escape {
				str[stri] = x
				stri++

				escape = false
				break
			}

			// something escaped outside of string gets added to string
			str[stri] = x
			stri++

			escape = true
		case '"':
			if zl.commt {
				com[comi] = x
				comi++
				break
			}

			if escape {
				str[stri] = x
				stri++

				escape = false
				break
			}

			zl.space = false

			// send previous gathered text and the quote
			var retL Lex
			if stri != 0 {
				l.Value = String
				l.Token = string(str[:stri])

				retL = *l
			}

			// send quote itself as separate token
			l.Value = Quote
			l.Token = "\""

			zl.quote = !zl.quote

			if retL != (Lex{}) {
				zl.nextL = true
				return retL, true
			}

			return *l, true
		case '(', ')':
			if zl.commt {
				com[comi] = x
				comi++
				break
			}

			if escape || zl.quote {
				// Inside quotes or escaped this is legal.
				str[stri] = x
				stri++

				escape = false
				break
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

			if zl.commt {
				com[comi] = x
				comi++
				break
			}

			str[stri] = x
			stri++

			zl.space = false
		}
	}

	if zl.readErr != nil && zl.readErr != io.EOF {
		// Don't return any tokens after a read error occurs.
		return Lex{Value: EOF}, false
	}

	var retL Lex
	if stri > 0 {
		// Send remainder of str
		l.Value = String
		l.Token = string(str[:stri])
		retL = *l

		if comi <= 0 {
			return retL, true
		}
	}

	if comi > 0 {
		// Send remainder of com
		l.Value = Newline
		l.Token = "\n"
		zl.comment = string(com[:comi])

		if retL != (Lex{}) {
			zl.nextL = true
			return retL, true
		}

		return *l, true
	}

	if zl.brace != 0 {
		l.Token = "unbalanced brace"
		l.Err = true
		return *l, true
	}

	return Lex{Value: EOF}, false
}

func (zl *Lexer) Comment() string {
	if zl.l.Err {
		return ""
	}

	return zl.comment
}

// Extract the class number from CLASSxx
func classToInt(token string) (uint16, bool) {
	offset := 5
	if len(token) < offset+1 {
		return 0, false
	}
	class, err := strconv.ParseUint(token[offset:], 10, 16)
	if err != nil {
		return 0, false
	}
	return uint16(class), true
}

// Extract the rr number from TYPExxx
func typeToInt(token string) (uint16, bool) {
	offset := 4
	if len(token) < offset+1 {
		return 0, false
	}
	typ, err := strconv.ParseUint(token[offset:], 10, 16)
	if err != nil {
		return 0, false
	}
	return uint16(typ), true
}

// stringToTTL parses things like 2w, 2m, etc, and returns the time in seconds.
func stringToTTL(token string) (uint32, bool) {
	var s, i uint
	for _, c := range token {
		switch c {
		case 's', 'S':
			s += i
			i = 0
		case 'm', 'M':
			s += i * 60
			i = 0
		case 'h', 'H':
			s += i * 60 * 60
			i = 0
		case 'd', 'D':
			s += i * 60 * 60 * 24
			i = 0
		case 'w', 'W':
			s += i * 60 * 60 * 24 * 7
			i = 0
		case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
			i *= 10
			i += uint(c) - '0'
		default:
			return 0, false
		}
	}
	if s+i > math.MaxUint32 {
		return 0, false
	}
	return uint32(s + i), true
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
