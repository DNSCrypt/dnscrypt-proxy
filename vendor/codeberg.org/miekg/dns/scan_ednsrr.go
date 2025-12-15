package dns

import (
	"encoding/binary"
	"strconv"
	"strings"
)

func (o *ZONEVERSION) parse(c *zlexer, _ string) *ParseError {
	// this parses the output: 8 SOA-SERIAL 1000000000
	l, _ := c.Next()
	i, err := strconv.ParseUint(l.token, 10, 8)
	if err != nil || l.err {
		return &ParseError{err: "bad ZONEVERSION Labels", lex: l}
	}
	o.Labels = uint8(i)

	c.Next()        // zBlank
	l, _ = c.Next() // zString
	// type, can be TYPEXXX, or SOA-SERIAL - we only accept SOA-SERIAL
	if l.token == "SOA-SERIAL" {
		o.Type = 0
		o.Version = make([]byte, 4)
	}
	c.Next()        // zBlank
	l, _ = c.Next() // zString
	i, err = strconv.ParseUint(l.token, 10, 32)
	if err != nil || l.err {
		return &ParseError{err: "bad ZONEVERSION Version", lex: l}
	}
	binary.BigEndian.PutUint32(o.Version, uint32(i))
	return slurpRemainder(c)
}

func (o *EDE) parse(c *zlexer, _ string) *ParseError {
	// this parses the output: EDE     15 "Blocked": ""
	l, _ := c.Next()
	i, err := strconv.ParseUint(l.token, 10, 16)
	if err != nil || l.err {
		return &ParseError{err: "bad EDE InfoCode", lex: l}
	}
	o.InfoCode = uint16(i)

	c.Next()        // zBlank
	l, _ = c.Next() // zString, "
	// we skip the string because that's the infocode's text
	c.Next()        // zString
	l, _ = c.Next() // zString, "
	if l.token != `"` {
		return &ParseError{err: "bad EDE InfoCode", lex: l}
	}
	l, _ = c.Next() // zString, :
	if l.token != ":" {
		return &ParseError{err: "bad EDE ExtraText", lex: l}
	}
	c.Next()        // zBlank
	l, _ = c.Next() // zString
	if l.token != `"` {
		return &ParseError{err: "bad EDE ExtraText", lex: l}
	}
	l, _ = c.Next()     // zString
	if l.token == `"` { // no extra text
		return slurpRemainder(c)
	}
	o.ExtraText = l.token

	l, _ = c.Next() // Zstring, quote
	if l.token != `"` {
		return &ParseError{err: "bad EDE ExtraText", lex: l}
	}
	return slurpRemainder(c)
}

func (o *NSID) parse(c *zlexer, _ string) *ParseError {
	// this parses the output: NSID 	5573652074686520666f726365: "Use the force"
	l, _ := c.Next()
	if !strings.HasSuffix(l.token, ":") {
		return &ParseError{err: "bad NSID Nsid"}
	}
	if (len(l.token)-1)%2 != 0 || len(l.token) < 2 {
		return &ParseError{err: "bad NSID Nsid"}
	}
	o.Nsid = l.token[:len(l.token)-2]

	c.Next()        // zBlank
	l, _ = c.Next() // zString
	if l.token != `"` {
		return &ParseError{err: "bad NSID Nsid", lex: l}
	}
	c.Next()
	l, _ = c.Next() // Zstring, quote
	if l.token != `"` {
		return &ParseError{err: "bad NSID Nsid", lex: l}
	}
	return slurpRemainder(c)
}
