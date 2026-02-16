package dns

import (
	"fmt"
	"io"
	"io/fs"
	"iter"
	"math"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	"codeberg.org/miekg/dns/internal/dnslex"
	"codeberg.org/miekg/dns/internal/dnsstring"
	"codeberg.org/miekg/dns/rdata"
)

// The maximum depth of $INCLUDE directives supported by the ZoneParser API.
const maxIncludeDepth = 7

// Tokenize a RFC 1035 zone file. The tokenizer will normalize it:
// * Add ownernames if they are left blank;
// * Suppress sequences of spaces;
// * Make each RR fit on one line (_NEWLINE is send as last)
// * Handle comments: ;
// * Handle braces - anywhere.
const (
	// Privatekey file
	zValue uint8 = iota
	zKey

	zExpectOwnerDir    uint8 = iota // Ownername
	zExpectAny                      // Expect rrtype, ttl or class
	zExpectAnyNoClass               // Expect rrtype or ttl
	zExpectAnyNoTTL                 // Expect rrtype or class
	zExpectRrtype                   // Expect whitespace and rrtype
	zExpectRdata                    // The first element of the rdata
	zExpectDirTTL                   // Directive $TTL
	zExpectDirOrigin                // Directive $ORIGIN
	zExpectDirInclude               // Directive $INCLUDE
	zExpectDirGenerate              // Directive $GENERATE
)

// ParseError is a parsing error. It contains the parse error and the location in the io.Reader
// where the error occurred.
type ParseError struct {
	file       string
	err        string
	wrappedErr error
	lex        dnslex.Lex
}

func (e *ParseError) Error() (s string) {
	if e.file != "" {
		s = e.file + ": "
	}
	if e.err == "" && e.wrappedErr != nil {
		e.err = e.wrappedErr.Error()
	}
	s += "dns: " + e.err + ": " + strconv.QuoteToASCII(e.lex.Token) + " at line: " +
		strconv.Itoa(e.lex.Line) + ":" + strconv.Itoa(e.lex.Column)
	return
}

func (e *ParseError) Unwrap() error { return e.wrappedErr }

const (
	asRR       uint8 = iota // parse the string as an RR.
	asCode                  // parse the string as an EDNS RR.
	asStateful              // TODO, but parse the string as an DSO RR.
)

// ttlState describes the state necessary to fill in an omitted RR TTL.
type ttlState struct {
	ttl           uint32 // ttl is the current default TTL
	isByDirective bool   // isByDirective indicates whether ttl was set by a $TTL directive
}

// New reads the RR contained in the string s. Only the first RR is returned.
// If s contains no records, New will return nil with no error.
// The origin for resolving relative domain names defaults to the DNS root (.).
//
// The class defaults to IN and TTL defaults to 3600. The full zone file syntax
// like $TTL, $ORIGIN, etc. is supported.
//
// Note that building an RR directly from it Go structure is far more efficient, i.e.
//
//	mx := &dns.MX{Hdr: dns.Header{Name: "miek.nl.", Class: dns.ClassINET, TTL: 3600}, MX: rdata.MX{Preference: 10, Mx: "mx.miek.nl."}}
//
// instead of:
//
//	mx := New("miek.nl. 0 IN MX 10 mx.miek.nl.")
//
// In this library EDNS0 option codes have a presentation format, which you see when you print them. This
// presentation format is also parsed back to EDNS0. In other words you can get an ENDS0 option code just from
// a string.
//
// Or with [codeberg.org/miekg/dns/dnstest.New], if you are sure no error will occur.
//
//	mx := dnstest.New("miek.nl.  IN MX 10 mx.miek.nl.")
func New(s string) (RR, error) {
	return read(dnsstring.NewReader(s), "")
}

// Read behaves like [New] but reads from an io.Reader. Note the reader must include an ending newline,
// otherwise the parsing will fail.
func Read(r io.Reader) (RR, error) { return read(r, "") }

func read(r io.Reader, file string) (RR, error) {
	zp := NewZoneParser(r, ".", file)
	zp.SetDefaultTTL(defaultTTL)
	rr, _ := zp.Next()
	return rr, zp.Err()
}

// NewData parses s, but only for the rdata, i.e. when the full RR is "miek.nl. IN 3600 MX 10 mx.miek.nl.",
// NewData must get "10 mx.miek.nl." and optionally an origin. Leading spaces are not allowed.
func NewData(rrtype uint16, s string, origin ...string) (RDATA, error) {
	return readData(strings.NewReader(s), rrtype, origin...)
}

// ReadData behaves like [NewData] but reads from an io.Reader.
func ReadData(r io.Reader, rrtype uint16, origin ...string) (RDATA, error) {
	return readData(r, rrtype, origin...)
}

func readData(r io.Reader, rrtype uint16, origin ...string) (RDATA, error) {
	o := "."
	if len(origin) > 0 {
		o = origin[0]
	}
	return parseData(r, rrtype, o)
}

// ZoneParser is a parser for an RFC 1035 style zone file.
//
// Each parsed RR in the zone is returned sequentially from [ZoneParser.Next].
// Also see [ZoneParser.RRs] which is an iterator.
//
// The directives $INCLUDE, $ORIGIN, $TTL and $GENERATE are all supported.
// Note that $GENERATE's range support up to a maximum of 65535 steps.
//
// Basic usage pattern when reading from a string (z) containing the zone data:
//
//	zp := NewZoneParser(strings.NewReader(z), "", "")
//
//	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
//		// Do something with rr
//	}
//
//	if err := zp.Err(); err != nil {
//		// log.Println(err)
//	}
//
// Callers should not assume all returned data in a RR is
// syntactically correct, e.g. illegal base64 in RRSIGs will be returned as-is.
type ZoneParser struct {
	h Header // rr header as we parse
	t uint16 // type as we parse, not stored in the header
	r io.Reader
	c *dnslex.Lexer

	// IncludeAllowFunc tells if and how includes are allowed.
	IncludeAllowFunc

	// IncludeFS provides an [fs.FS] to use when looking for the target of $INCLUDE directives.
	// If nil, [os.Open] will be used.
	//
	// When it is an on-disk FS, the ability of $INCLUDE to reach files from
	// outside its root directory depends upon the FS implementation.  For
	// instance, [os.DirFS] will refuse to open paths like "../../etc/passwd",
	// however it will still follow links which may point anywhere on the system.
	//
	// FS paths are slash-separated on all systems, even Windows.  $INCLUDE paths
	// containing other characters such as backslash and colon may be accepted as
	// valid, but those characters will never be interpreted by an FS
	// implementation as path element separators.  See [fs.ValidPath] for more
	// details.
	IncludeFS fs.FS

	origin string
	file   string
	path   string // full path of file

	parseErr *ParseError
	defttl   *ttlState

	// sub is used to parse $INCLUDE files and $GENERATE directives.
	// Next, by calling subNext, forwards the resulting RRs from this
	// sub parser to the calling code.
	sub *ZoneParser

	includeDepth       uint8
	generateDisallowed bool
}

// NewZoneParser returns an RFC 1035 style zone file parser that reads from r.
//
// The string file is used in error reporting and to resolve relative
// $INCLUDE directives. The string origin is used as the initial
// origin, as if the file would start with an $ORIGIN directive.
// IncludeAllowFunc is set to DefaultIncludeAllowFunc.
func NewZoneParser(r io.Reader, origin, file string) *ZoneParser {
	var pe *ParseError
	if origin != "" {
		origin = dnsutilFqdn(origin)
		if ok := dnsutilIsName(origin); !ok {
			pe = &ParseError{file: file, err: "bad initial origin name"}
		}
	}

	return &ZoneParser{
		c:                dnslex.New(r, StringToType, StringToCode, StringToClass),
		IncludeAllowFunc: DefaultIncludeAllowFunc,
		parseErr:         pe,
		origin:           origin,
		file:             file,
		path:             func() string { p, _ := filepath.Abs(file); return p }(),
	}
}

// SetDefaultTTL sets the parsers default TTL to ttl.
func (zp *ZoneParser) SetDefaultTTL(ttl uint32) {
	zp.defttl = &ttlState{ttl, false}
}

// Err returns the first non-EOF error that was encountered by the ZoneParser.
func (zp *ZoneParser) Err() error {
	if zp.parseErr != nil {
		return zp.parseErr
	}

	if zp.sub != nil {
		if err := zp.sub.Err(); err != nil {
			return err
		}
	}

	return zp.c.Err()
}

func (zp *ZoneParser) setParseError(err string, l dnslex.Lex) (RR, bool) {
	zp.parseErr = &ParseError{file: zp.file, err: err, lex: l}
	return nil, false
}

func (zp *ZoneParser) subNext() (RR, bool) {
	if rr, ok := zp.sub.Next(); ok {
		return rr, true
	}

	if zp.sub.r != nil {
		if c, ok := zp.sub.r.(io.Closer); ok {
			c.Close()
		}
		zp.sub.r = nil
	}

	if zp.sub.Err() != nil {
		// We have errors to surface.
		return nil, false
	}

	zp.sub = nil
	return zp.Next()
}

// Next advances the parser to the next RR in the zone file and
// returns the (RR, true). It will return (nil, false) when the
// parsing stops, either by reaching the end of the input or an
// error. After Next returns (nil, false), the Err method will return
// any error that occurred during parsing.
func (zp *ZoneParser) Next() (RR, bool) {
	if zp.parseErr != nil {
		return nil, false
	}
	if zp.sub != nil {
		return zp.subNext()
	}

	setTTL := func(l dnslex.Lex) (uint32, bool) {
		ttl, ok := stringToTTL(l.Token)
		if !ok {
			return 0, false
		}
		if zp.defttl == nil || !zp.defttl.isByDirective {
			zp.defttl = &ttlState{ttl, false}
		}
		return ttl, true
	}

	// 6 possible beginnings of a line (_ is a space):
	//
	//   0. dnslex.Rrtype                                                -> all omitted until the rrtype
	//   1. dnslex.Owner _ dnslex.Rrtype                                 -> class/ttl omitted
	//   2. dnslex.Owner _ dnslex.String _ dnslex.Rrtype                 -> class omitted
	//   3. dnslex.Owner _ dnslex.Class  _ dnslex.Rrtype                 -> ttl omitted
	//   4. dnslex.Owner _ dnslex.String _ dnslex.Class  _ dnslex.Rrtype -> ttl/class
	//   5. dnslex.Owner _ dnslex.Class  _ dnslex.String _ dnslex.Rrtype -> class/ttl (reversed)
	//
	// After detecting these, we know the zRrtype so we can jump to functions handling the rdata for each of these types.

	st := zExpectOwnerDir // initial state

Next:
	for l, ok := zp.c.Next(); ok; l, ok = zp.c.Next() {
		// zlexer spotted an error already
		if l.Value == dnslex.Error {
			return zp.setParseError(l.Token, l)
		}

		switch st {
		case zExpectOwnerDir:
			// We can also expect a directive, like $TTL or $ORIGIN
			if zp.defttl != nil {
				zp.h.TTL = zp.defttl.ttl
			}

			zp.h.Class = ClassINET

			switch l.Value {
			case dnslex.Newline:

				st = zExpectOwnerDir
			case dnslex.Owner:
				name := dnsutilAbsolute(l.Token, zp.origin)
				if name == "" {
					return zp.setParseError("bad owner name", l)
				}

				zp.h.Name = name

				if l, ok = zp.c.Next(); !ok {
					break Next
				}
				if l.Value != dnslex.Blank {
					return zp.setParseError("no blank after owner", l)
				}

				st = zExpectAny
			case dnslex.DirTTL:
				if l, ok = zp.c.Next(); !ok {
					break Next
				}
				if l.Value != dnslex.Blank {
					return zp.setParseError("no blank after $TTL-directive", l)
				}

				st = zExpectDirTTL
			case dnslex.DirOrigin:
				if l, ok = zp.c.Next(); !ok {
					break Next
				}
				if l.Value != dnslex.Blank {
					return zp.setParseError("no blank after $ORIGIN-directive", l)
				}

				st = zExpectDirOrigin
			case dnslex.DirInclude:
				if l, ok = zp.c.Next(); !ok {
					break Next
				}
				if l.Value != dnslex.Blank {
					return zp.setParseError("no blank after $INCLUDE-directive", l)
				}

				st = zExpectDirInclude
			case dnslex.DirGenerate:
				if l, ok = zp.c.Next(); !ok {
					break Next
				}
				if l.Value != dnslex.Blank {
					return zp.setParseError("no blank after $GENERATE-directive", l)
				}

				st = zExpectDirGenerate
			case dnslex.Rrtype:
				zp.t = l.Torc

				st = zExpectRdata
			case dnslex.Class:
				zp.h.Class = l.Torc

				if l, ok = zp.c.Next(); !ok {
					break Next
				}
				if l.Value != dnslex.Blank {
					return zp.setParseError("no blank after class", l)
				}

				st = zExpectAnyNoClass
			case dnslex.Blank:
				// Discard, can happen when there is nothing on the
				// line except the RR type
			case dnslex.String:
				if zp.h.TTL, ok = setTTL(l); !ok {
					return zp.setParseError("not a TTL", l)
				}
				if l, ok = zp.c.Next(); !ok {
					break Next
				}
				if l.Value != dnslex.Blank {
					return zp.setParseError("no blank after TTL", l)
				}

				st = zExpectAnyNoTTL
			default:
				return zp.setParseError("syntax error at beginning", l)
			}
		case zExpectRrtype:
			if l.Value != dnslex.Blank {
				return zp.setParseError("no blank before RR type", l)
			}
			if l, ok = zp.c.Next(); !ok {
				break Next
			}
			if l.Value != dnslex.Rrtype {
				return zp.setParseError("unknown RR type", l)
			}
			zp.t = l.Torc

			st = zExpectRdata
		case zExpectRdata:
			var (
				rr             RR
				parseAsRFC3597 bool
			)
			switch l.As {
			case asRR:
				if newFn, ok := TypeToRR[zp.t]; ok {
					rr = newFn()
					*rr.Header() = zp.h

					// We may be parsing a known RR type using the RFC3597 format.
					// If so, we handle that here in a generic way.
					//
					// This is also true for PrivateRR types which will have the
					// RFC3597 parsing done for them and the Unpack method called
					// to populate the RR instead of simply deferring to Parse.
					if zp.c.Peek().Token == "\\#" {
						parseAsRFC3597 = true
					}
				} else {
					rr = &RFC3597{zp.h, rdata.RFC3597{RRType: zp.t}}
				}
			case asCode:
				newFn, ok := CodeToRR[zp.t]
				if !ok {
					return zp.setParseError("unknown EDNS0 type", l)
				}
				rr = newFn()
				*rr.Header() = zp.h
			}

			if zp.c.Peek().Token == "" {
				// This is a dynamic update rr.
				if err := dnslex.Discard(zp.c); err != nil {
					return zp.setParseError(err.Err, err.Lex)
				}

				return rr, true
			} else if l.Value == dnslex.Newline {
				return zp.setParseError("unexpected newline", l)
			}

			parseAsRR := rr
			if parseAsRFC3597 {
				parseAsRR = &RFC3597{zp.h, rdata.RFC3597{RRType: zp.t}}
			}

			// This needs zparser which calls Parser for new types.
			if err := parse(parseAsRR, zp.c, zp.origin); err != nil {
				pe := err.(*ParseError)
				// err is a concrete *ParseError without the file field set.
				// The setParseError call below will construct a new
				// *ParseError with file set to zp.file.

				// err.lex may be nil in which case we substitute our current lex token.
				if pe.lex == (dnslex.Lex{}) {
					return zp.setParseError(pe.err, l)
				}

				return zp.setParseError(pe.err, pe.lex)
			}

			if parseAsRFC3597 {
				err := parseAsRR.(*RFC3597).fromRFC3597(rr)
				if err != nil {
					return zp.setParseError(err.Error(), l)
				}
			}

			return rr, true
		case zExpectDirInclude:
			if l.Value != dnslex.String {
				return zp.setParseError("expecting $INCLUDE value, not this...", l)
			}

			neworigin := zp.origin // There may be optionally a new origin set after the filename, if not use current one
			switch l, _ := zp.c.Next(); l.Value {
			case dnslex.Blank:
				l, _ := zp.c.Next()
				if l.Value == dnslex.String {
					name := dnsutilAbsolute(l.Token, zp.origin)
					if name == "" {
						return zp.setParseError("bad origin name", l)
					}

					neworigin = name
				}
			case dnslex.Newline, dnslex.EOF:
				// Ok
			default:
				return zp.setParseError("garbage after $INCLUDE", l)
			}

			if !zp.IncludeAllowFunc(zp.path, l.Token) {
				return zp.setParseError("$INCLUDE directive not allowed", l)
			}
			if zp.includeDepth >= maxIncludeDepth {
				return zp.setParseError("too deeply nested $INCLUDE", l)
			}

			// Start with the new file
			includePath := l.Token
			var r1 io.Reader
			var e1 error
			if zp.IncludeFS != nil {
				// fs.FS always uses / as separator, even on Windows, so use
				// path instead of filepath here:
				if !path.IsAbs(includePath) {
					includePath = path.Join(path.Dir(zp.file), includePath)
				}

				// os.DirFS, and probably others, expect all paths to be
				// relative, so clean the path and remove leading / if
				// present:
				includePath = strings.TrimLeft(path.Clean(includePath), "/")

				r1, e1 = zp.IncludeFS.Open(includePath)
			} else {
				if !filepath.IsAbs(includePath) {
					includePath = filepath.Join(filepath.Dir(zp.file), includePath)
				}
				r1, e1 = os.Open(includePath)
			}
			if e1 != nil {
				var as string
				if includePath != l.Token {
					as = fmt.Sprintf(" as `%s'", includePath)
				}
				zp.parseErr = &ParseError{
					file:       zp.file,
					wrappedErr: fmt.Errorf("failed to open `%s'%s: %w", l.Token, as, e1),
					lex:        l,
				}
				return nil, false
			}

			zp.sub = NewZoneParser(r1, neworigin, includePath)
			zp.sub.defttl, zp.sub.includeDepth, zp.sub.r = zp.defttl, zp.includeDepth+1, r1
			zp.sub.IncludeAllowFunc = zp.IncludeAllowFunc
			zp.sub.IncludeFS = zp.IncludeFS
			return zp.subNext()

		case zExpectDirTTL:
			if l.Value != dnslex.String {
				return zp.setParseError("expecting $TTL value, not this...", l)
			}

			if err := dnslex.Discard(zp.c); err != nil {
				return zp.setParseError(err.Err, err.Lex)
			}

			ttl, ok := stringToTTL(l.Token)
			if !ok {
				return zp.setParseError("expecting $TTL value, not this...", l)
			}

			zp.defttl = &ttlState{ttl, true}

			st = zExpectOwnerDir
		case zExpectDirOrigin:
			if l.Value != dnslex.String {
				return zp.setParseError("expecting $ORIGIN value, not this...", l)
			}

			if err := dnslex.Discard(zp.c); err != nil {
				return zp.setParseError(err.Err, err.Lex)
			}

			name := dnsutilAbsolute(l.Token, zp.origin)
			if name == "" {
				return zp.setParseError("bad origin name", l)
			}

			zp.origin = name

			st = zExpectOwnerDir
		case zExpectDirGenerate:
			if zp.generateDisallowed {
				return zp.setParseError("nested $GENERATE directive not allowed", l)
			}
			if l.Value != dnslex.String {
				return zp.setParseError("expecting $GENERATE value, not this...", l)
			}

			return zp.generate(l)
		case zExpectAny:
			switch l.Value {
			case dnslex.Rrtype:
				if zp.defttl == nil {
					return zp.setParseError("missing TTL with no previous value", l)
				}

				zp.t = l.Torc

				st = zExpectRdata
			case dnslex.Class:
				zp.h.Class = l.Torc

				if l, ok = zp.c.Next(); !ok {
					break Next
				}
				if l.Value != dnslex.Blank {
					return zp.setParseError("no blank after class", l)
				}

				st = zExpectAnyNoClass
			case dnslex.String:
				if zp.h.TTL, ok = setTTL(l); !ok {
					return zp.setParseError("not a TTL", l)
				}
				if l, ok = zp.c.Next(); !ok {
					break Next
				}
				if l.Value != dnslex.Blank {
					return zp.setParseError("no blank after TTL", l)
				}

				st = zExpectAnyNoTTL
			default:
				return zp.setParseError("expecting RR type, TTL or class, not this...", l)
			}
		case zExpectAnyNoTTL:
			switch l.Value {
			case dnslex.Class:
				zp.h.Class = l.Torc

				st = zExpectRrtype
			case dnslex.Rrtype:
				zp.t = l.Torc

				st = zExpectRdata
			default:
				return zp.setParseError("expecting RR type or class, not this...", l)
			}
		case zExpectAnyNoClass:
			switch l.Value {
			case dnslex.String:
				if zp.h.TTL, ok = setTTL(l); !ok {
					return zp.setParseError("not a TTL", l)
				}

				st = zExpectRrtype
			case dnslex.Rrtype:
				zp.t = l.Torc

				st = zExpectRdata
			default:
				return zp.setParseError("expecting RR type or TTL, not this...", l)
			}
		}
	}

	// If we get here, we and the h.Rrtype is still zero, we haven't parsed anything, this
	// is not an error, because an empty zone file is still a zone file.
	return nil, false
}

// RRs allows ranging over the RRs from the zone currently parsed.
func (zp *ZoneParser) RRs() iter.Seq2[RR, error] {
	return func(yield func(RR, error) bool) {
		for {
			rr, ok := zp.Next()
			if !yield(rr, zp.Err()) {
				return
			}
			if !ok {
				break
			}
		}
	}
}

// stringToTTL parses things like 2w, 2m, etc, and returns the time in seconds.
func stringToTTL(token string) (uint32, bool) {
	switch token {
	case "300":
		return 300, true
	case "1800", "30m", "30M":
		return 1800, true
	case "3600", "1h", "1H":
		return 3600, true
	case "14400":
		return 14400, true
	case "86400", "1d", "1D":
		return 86400, true
	case "604800", "1w", "1W":
		return 604800, true
	}

	var s, i uint
	for j := range token {
		switch token[j] {
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
			i += uint(token[j]) - '0'
		default:
			return 0, false
		}
	}
	if s+i > math.MaxUint32 {
		return 0, false
	}
	return uint32(s + i), true
}

// Parse LOC records' <digits>[.<digits>][mM] into a
// mantissa exponent format. Token should contain the entire
// string (i.e. no spaces allowed)
func stringToCm(token string) (e, m uint8, ok bool) {
	if token[len(token)-1] == 'M' || token[len(token)-1] == 'm' {
		token = token[0 : len(token)-1]
	}

	var (
		meters, cmeters, val int
		err                  error
	)
	mStr, cmStr, hasCM := strings.Cut(token, ".")
	if hasCM {
		// There's no point in having more than 2 digits in this part, and would rather make the implementation complicated ('123' should be treated as '12').
		// So we simply reject it.
		// We also make sure the first character is a digit to reject '+-' signs.
		cmeters, err = strconv.Atoi(cmStr)
		if err != nil || len(cmStr) > 2 || cmStr[0] < '0' || cmStr[0] > '9' {
			return
		}
		if len(cmStr) == 1 {
			// 'nn.1' must be treated as 'nn-meters and 10cm, not 1cm.
			cmeters *= 10
		}
	}
	// This slightly ugly condition will allow omitting the 'meter' part, like .01 (meaning 0.01m = 1cm).
	if !hasCM || mStr != "" {
		meters, err = strconv.Atoi(mStr)
		// RFC1876 states the max value is 90000000.00.  The latter two conditions enforce it.
		if err != nil || mStr[0] < '0' || mStr[0] > '9' || meters > 90000000 || (meters == 90000000 && cmeters != 0) {
			return
		}
	}

	if meters > 0 {
		e = 2
		val = meters
	} else {
		e = 0
		val = cmeters
	}
	for val >= 10 {
		e++
		val /= 10
	}
	return e, uint8(val), true
}

// LOC record helper function
func locCheckNorth(token string, latitude uint32) (uint32, bool) {
	if latitude > 90*1000*60*60 {
		return latitude, false
	}
	switch token {
	case "n", "N":
		return LOCEquator + latitude, true
	case "s", "S":
		return LOCEquator - latitude, true
	}
	return latitude, false
}

// LOC record helper function
func locCheckEast(token string, longitude uint32) (uint32, bool) {
	if longitude > 180*1000*60*60 {
		return longitude, false
	}
	switch token {
	case "e", "E":
		return LOCEquator + longitude, true
	case "w", "W":
		return LOCEquator - longitude, true
	}
	return longitude, false
}

// Parse a 64 bit-like ipv6 address: "0014:4fff:ff20:ee64" Used for NID and L64 record.
func stringToNodeID(l dnslex.Lex) (uint64, error) {
	if len(l.Token) < 19 {
		return 0, &ParseError{file: l.Token, err: "bad NID/L64 NodeID/Locator64", lex: l}
	}
	// There must be three colons at fixes positions, if not its a parse error
	if l.Token[4] != ':' && l.Token[9] != ':' && l.Token[14] != ':' {
		return 0, &ParseError{file: l.Token, err: "bad NID/L64 NodeID/Locator64", lex: l}
	}
	s := l.Token[0:4] + l.Token[5:9] + l.Token[10:14] + l.Token[15:19]
	u, err := strconv.ParseUint(s, 16, 64)
	if err != nil {
		return 0, &ParseError{file: l.Token, err: "bad NID/L64 NodeID/Locator64", lex: l}
	}
	return u, nil
}

// IncludeAllowFunc is a function that gets the full path of the original parsed file name and the included
// file path and returns true if the include is allowed.
type IncludeAllowFunc func(file, include string) bool

// DefaultIncludeAllowFunc returns true if the included file is on the same level or in a directory below.
var DefaultIncludeAllowFunc IncludeAllowFunc = defaultIncludeAllowFunc

func defaultIncludeAllowFunc(file, include string) bool {
	up := ".." + string(os.PathSeparator)
	rel, err := filepath.Rel(file, include)
	if err != nil {
		return false
	}
	if !strings.HasPrefix(rel, up) && rel != ".." {
		return true
	}
	return false
}

func toParseError(err *dnslex.ScanError) error {
	if err == nil {
		return nil
	}
	return &ParseError{err: err.Err, lex: err.Lex}
}
