package dns

import (
	"encoding/binary"
	"strconv"
	"strings"

	"codeberg.org/miekg/dns/internal/dnslex"
)

func (o *ZONEVERSION) parse(c *dnslex.Lexer, _ string) error {
	// this parses the output: 8 SOA-SERIAL 1000000000
	l, _ := c.Next()
	i, err := strconv.ParseUint(l.Token, 10, 8)
	if err != nil || l.Err {
		return &ParseError{err: "bad ZONEVERSION Labels", lex: l}
	}
	o.Labels = uint8(i)

	c.Next()        // zBlank
	l, _ = c.Next() // zString
	// type, can be TYPEXXX, or SOA-SERIAL - we only accept SOA-SERIAL
	if l.Token == "SOA-SERIAL" {
		o.Type = 0
		o.Version = make([]byte, 4)
	}
	c.Next()        // zBlank
	l, _ = c.Next() // zString
	i, err = strconv.ParseUint(l.Token, 10, 32)
	if err != nil || l.Err {
		return &ParseError{err: "bad ZONEVERSION Version", lex: l}
	}
	binary.BigEndian.PutUint32(o.Version, uint32(i))
	return toParseError(dnslex.Discard(c))
}

func (o *EDE) parse(c *dnslex.Lexer, _ string) error {
	// this parses the output: EDE     15 "Blocked": ""
	l, _ := c.Next()
	i, err := strconv.ParseUint(l.Token, 10, 16)
	if err != nil || l.Err {
		return &ParseError{err: "bad EDE InfoCode", lex: l}
	}
	o.InfoCode = uint16(i)

	c.Next()        // zBlank
	l, _ = c.Next() // zString, "
	// we skip the string because that's the infocode's text
	c.Next()        // zString
	l, _ = c.Next() // zString, "
	if l.Token != `"` {
		return &ParseError{err: "bad EDE InfoCode", lex: l}
	}
	l, _ = c.Next() // zString, :
	if l.Token != ":" {
		return &ParseError{err: "bad EDE ExtraText", lex: l}
	}
	c.Next()        // zBlank
	l, _ = c.Next() // zString
	if l.Token != `"` {
		return &ParseError{err: "bad EDE ExtraText", lex: l}
	}
	l, _ = c.Next()     // zString
	if l.Token == `"` { // no extra text
		return toParseError(dnslex.Discard(c))
	}
	o.ExtraText = l.Token

	l, _ = c.Next() // Zstring, quote
	if l.Token != `"` {
		return &ParseError{err: "bad EDE ExtraText", lex: l}
	}
	return toParseError(dnslex.Discard(c))
}

func (o *NSID) parse(c *dnslex.Lexer, _ string) error {
	// this parses the output: NSID 	5573652074686520666f726365: "Use the force"
	l, _ := c.Next()
	if !strings.HasSuffix(l.Token, ":") {
		return &ParseError{err: "bad NSID Nsid"}
	}
	if (len(l.Token)-1)%2 != 0 || len(l.Token) < 2 {
		return &ParseError{err: "bad NSID Nsid"}
	}
	o.Nsid = l.Token[:len(l.Token)-2]

	c.Next()        // zBlank
	l, _ = c.Next() // zString
	if l.Token != `"` {
		return &ParseError{err: "bad NSID Nsid", lex: l}
	}
	c.Next()
	l, _ = c.Next() // Zstring, quote
	if l.Token != `"` {
		return &ParseError{err: "bad NSID Nsid", lex: l}
	}
	return toParseError(dnslex.Discard(c))
}
