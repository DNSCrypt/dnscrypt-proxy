package dns

import (
	"encoding/base64"
	"net/netip"
	"strconv"
	"strings"

	"codeberg.org/miekg/dns/deleg"
	"codeberg.org/miekg/dns/internal/dnslex"
	"codeberg.org/miekg/dns/internal/dnsstring"
	"codeberg.org/miekg/dns/rdata"
	"codeberg.org/miekg/dns/svcb"
)

func parseA(rd *rdata.A, c *dnslex.Lexer, o string) error {
	var err error
	l, _ := c.Next()
	rd.Addr, err = netip.ParseAddr(l.Token)
	if l.Value == dnslex.Error || err != nil || !rd.Addr.Is4() {
		return &ParseError{err: "bad A Addr", lex: l}
	}
	return toParseError(dnslex.Discard(c))
}

func parseAAAA(rd *rdata.AAAA, c *dnslex.Lexer, o string) error {
	var err error
	l, _ := c.Next()
	rd.Addr, err = netip.ParseAddr(l.Token)
	if l.Value == dnslex.Error || err != nil || !rd.Addr.Is6() {
		return &ParseError{err: "bad AAAA Addr", lex: l}
	}
	return toParseError(dnslex.Discard(c))
}

func parseNS(rd *rdata.NS, c *dnslex.Lexer, o string) error {
	l, _ := c.Next()
	rd.Ns = dnsutilAbsolute(l.Token, o)
	if l.Value == dnslex.Error || rd.Ns == "" {
		return &ParseError{err: "bad NS Ns", lex: l}
	}
	return toParseError(dnslex.Discard(c))
}

func parsePTR(rd *rdata.PTR, c *dnslex.Lexer, o string) error {
	l, _ := c.Next()
	rd.Ptr = dnsutilAbsolute(l.Token, o)
	if l.Value == dnslex.Error || rd.Ptr == "" {
		return &ParseError{err: "bad PTR Ptr", lex: l}
	}
	return toParseError(dnslex.Discard(c))
}

func parseNSAPPTR(rd *rdata.NSAPPTR, c *dnslex.Lexer, o string) error {
	l, _ := c.Next()
	rd.Ptr = dnsutilAbsolute(l.Token, o)
	if l.Value == dnslex.Error || rd.Ptr == "" {
		return &ParseError{err: "bad NSAP-PTR Ptr", lex: l}
	}
	return toParseError(dnslex.Discard(c))
}

func parseRP(rd *rdata.RP, c *dnslex.Lexer, o string) error {
	l, _ := c.Next()
	rd.Mbox = dnsutilAbsolute(l.Token, o)
	if l.Value == dnslex.Error || rd.Mbox == "" {
		return &ParseError{err: "bad RP Mbox", lex: l}
	}

	c.Next() // dnslex.Blank
	l, _ = c.Next()
	rd.Txt = l.Token

	rd.Txt = dnsutilAbsolute(l.Token, o)
	if l.Value == dnslex.Error || rd.Txt == "" {
		return &ParseError{err: "bad RP Txt", lex: l}
	}
	return toParseError(dnslex.Discard(c))
}

func parseMR(rd *rdata.MR, c *dnslex.Lexer, o string) error {
	l, _ := c.Next()
	rd.Mr = dnsutilAbsolute(l.Token, o)
	if l.Value == dnslex.Error || rd.Mr == "" {
		return &ParseError{err: "bad MR Mr", lex: l}
	}
	return toParseError(dnslex.Discard(c))
}

func parseMB(rd *rdata.MB, c *dnslex.Lexer, o string) error {
	l, _ := c.Next()
	rd.Mb = dnsutilAbsolute(l.Token, o)
	if l.Value == dnslex.Error || rd.Mb == "" {
		return &ParseError{err: "bad MB Mb", lex: l}
	}
	return toParseError(dnslex.Discard(c))
}

func parseMG(rd *rdata.MG, c *dnslex.Lexer, o string) error {
	l, _ := c.Next()
	rd.Mg = dnsutilAbsolute(l.Token, o)
	if l.Value == dnslex.Error || rd.Mg == "" {
		return &ParseError{err: "bad MG Mg", lex: l}
	}
	return toParseError(dnslex.Discard(c))
}

func parseHINFO(rd *rdata.HINFO, c *dnslex.Lexer, o string) error {
	chunks, err := remainderSlice(c, "bad HINFO Fields")
	if err != nil {
		return err
	}

	if ln := len(chunks); ln == 0 {
		return nil
	} else if ln == 1 {
		// Can we split it?
		if out := strings.Fields(chunks[0]); len(out) > 1 {
			chunks = out
		} else {
			chunks = append(chunks, "")
		}
	}

	rd.Cpu = chunks[0]
	rd.Os = strings.Join(chunks[1:], " ")
	return nil
}

// according to RFC 1183 the parsing is identical to HINFO, so just use that code.
func parseISDN(rd *rdata.ISDN, c *dnslex.Lexer, o string) error {
	chunks, err := remainderSlice(c, "bad ISDN Fields")
	if err != nil {
		return err
	}

	if ln := len(chunks); ln == 0 {
		return nil
	} else if ln == 1 {
		// Can we split it?
		if out := strings.Fields(chunks[0]); len(out) > 1 {
			chunks = out
		} else {
			chunks = append(chunks, "")
		}
	}

	rd.Address = chunks[0]
	rd.SubAddress = strings.Join(chunks[1:], " ")
	return nil
}

func parseMINFO(rd *rdata.MINFO, c *dnslex.Lexer, o string) error {
	l, _ := c.Next()
	rd.Rmail = dnsutilAbsolute(l.Token, o)
	if l.Value == dnslex.Error || rd.Rmail == "" {
		return &ParseError{err: "bad MINFO Rmail", lex: l}
	}

	c.Next() // dnslex.Blank
	l, _ = c.Next()
	rd.Email = l.Token

	rd.Email = dnsutilAbsolute(l.Token, o)
	if l.Value == dnslex.Error || rd.Email == "" {
		return &ParseError{err: "bad MINFO Email", lex: l}
	}
	return toParseError(dnslex.Discard(c))
}

func parseMF(rd *rdata.MF, c *dnslex.Lexer, o string) error {
	l, _ := c.Next()
	rd.Mf = dnsutilAbsolute(l.Token, o)
	if l.Value == dnslex.Error || rd.Mf == "" {
		return &ParseError{err: "bad MF Mf", lex: l}
	}
	return toParseError(dnslex.Discard(c))
}

func parseMD(rd *rdata.MD, c *dnslex.Lexer, o string) error {
	l, _ := c.Next()
	rd.Md = dnsutilAbsolute(l.Token, o)
	if l.Value == dnslex.Error || rd.Md == "" {
		return &ParseError{err: "bad MD Md", lex: l}
	}
	return toParseError(dnslex.Discard(c))
}

func parseMX(rd *rdata.MX, c *dnslex.Lexer, o string) error {
	var err error
	l, _ := c.Next()
	rd.Preference, err = dnsstring.AtoiUint16(l.Token)
	if err != nil || l.Value == dnslex.Error {
		return &ParseError{err: "bad MX Pref", lex: l}
	}

	c.Next()        // dnslex.Blank
	l, _ = c.Next() // dnslex.String
	rd.Mx = dnsutilAbsolute(l.Token, o)
	if l.Value == dnslex.Error || rd.Mx == "" {
		return &ParseError{err: "bad MX Mx", lex: l}
	}
	return toParseError(dnslex.Discard(c))
}

func parseRT(rd *rdata.RT, c *dnslex.Lexer, o string) error {
	var err error
	l, _ := c.Next()
	rd.Preference, err = dnsstring.AtoiUint16(l.Token)
	if err != nil {
		return &ParseError{err: "bad RT Preference", lex: l}
	}

	c.Next()        // dnslex.Blank
	l, _ = c.Next() // dnslex.String
	rd.Host = l.Token

	rd.Host = dnsutilAbsolute(l.Token, o)
	if l.Value == dnslex.Error || rd.Host == "" {
		return &ParseError{err: "bad RT Host", lex: l}
	}
	return toParseError(dnslex.Discard(c))
}

func parseAFSDB(rd *rdata.AFSDB, c *dnslex.Lexer, o string) error {
	var err error
	l, _ := c.Next()
	rd.Subtype, err = dnsstring.AtoiUint16(l.Token)
	if err != nil || l.Value == dnslex.Error {
		return &ParseError{err: "bad AFSDB Subtype", lex: l}
	}

	c.Next()        // dnslex.Blank
	l, _ = c.Next() // dnslex.String
	rd.Hostname = l.Token

	rd.Hostname = dnsutilAbsolute(l.Token, o)
	if l.Value == dnslex.Error || rd.Hostname == "" {
		return &ParseError{err: "bad AFSDB Hostname", lex: l}
	}
	return toParseError(dnslex.Discard(c))
}

func parseX25(rd *rdata.X25, c *dnslex.Lexer, o string) error {
	l, _ := c.Next()
	if l.Value == dnslex.Error {
		return &ParseError{err: "bad X25 PSDNAddress", lex: l}
	}
	rd.PSDNAddress = l.Token
	return toParseError(dnslex.Discard(c))
}

func parseKX(rd *rdata.KX, c *dnslex.Lexer, o string) error {
	var err error
	l, _ := c.Next()
	rd.Preference, err = dnsstring.AtoiUint16(l.Token)
	if err != nil || l.Value == dnslex.Error {
		return &ParseError{err: "bad KX Pref", lex: l}
	}

	c.Next()        // dnslex.Blank
	l, _ = c.Next() // dnslex.String
	rd.Exchanger = dnsutilAbsolute(l.Token, o)
	if l.Value == dnslex.Error || rd.Exchanger == "" {
		return &ParseError{err: "bad KX Exchanger", lex: l}
	}
	return toParseError(dnslex.Discard(c))
}

func parseCNAME(rd *rdata.CNAME, c *dnslex.Lexer, o string) error {
	l, _ := c.Next()
	rd.Target = dnsutilAbsolute(l.Token, o)
	if l.Value == dnslex.Error || rd.Target == "" {
		return &ParseError{err: "bad CNAME Target", lex: l}
	}
	return toParseError(dnslex.Discard(c))
}

func parseDNAME(rd *rdata.DNAME, c *dnslex.Lexer, o string) error {
	l, _ := c.Next()
	rd.Target = dnsutilAbsolute(l.Token, o)
	if l.Value == dnslex.Error || rd.Target == "" {
		return &ParseError{err: "bad DNAME Target", lex: l}
	}
	return toParseError(dnslex.Discard(c))
}

func parseSOA(rd *rdata.SOA, c *dnslex.Lexer, o string) error {
	l, _ := c.Next()
	rd.Ns = dnsutilAbsolute(l.Token, o)
	if l.Value == dnslex.Error || rd.Ns == "" {
		return &ParseError{err: "bad SOA Ns", lex: l}
	}

	c.Next() // dnslex.Blank
	l, _ = c.Next()
	rd.Mbox = l.Token

	rd.Mbox = dnsutilAbsolute(l.Token, o)
	if l.Value == dnslex.Error || rd.Mbox == "" {
		return &ParseError{err: "bad SOA Mbox", lex: l}
	}

	c.Next() // dnslex.Blank

	for i := range 5 {

		l, _ = c.Next()
		if l.Value == dnslex.Error {
			return &ParseError{err: "bad SOA field", lex: l}
		}

		v, err := dnsstring.AtoiUint32(l.Token)
		if err != nil {
			var ok bool
			if i == 0 { // Serial must be a number
				return &ParseError{err: "bad SOA Serial", lex: l}
			}
			// We allow other fields to be unitful duration strings
			v, ok = stringToTTL(l.Token)
			if !ok {
				return &ParseError{err: "bad SOA field", lex: l}
			}
		}

		switch i {
		case 0:
			rd.Serial = v
			c.Next() // dnslex.Blank
		case 1:
			rd.Refresh = v
			c.Next() // dnslex.Blank
		case 2:
			rd.Retry = v
			c.Next() // dnslex.Blank
		case 3:
			rd.Expire = v
			c.Next() // dnslex.Blank
		case 4:
			rd.Minttl = v
		}
	}
	return toParseError(dnslex.Discard(c))
}

func parseSRV(rd *rdata.SRV, c *dnslex.Lexer, o string) error {
	var err error
	l, _ := c.Next()
	rd.Priority, err = dnsstring.AtoiUint16(l.Token)
	if err != nil || l.Value == dnslex.Error {
		return &ParseError{err: "bad SRV Priority", lex: l}
	}

	c.Next()        // dnslex.Blank
	l, _ = c.Next() // dnslex.String
	rd.Weight, err = dnsstring.AtoiUint16(l.Token)
	if err != nil || l.Value == dnslex.Error {
		return &ParseError{err: "bad SRV Weight", lex: l}
	}

	c.Next()        // dnslex.Blank
	l, _ = c.Next() // dnslex.String
	rd.Port, err = dnsstring.AtoiUint16(l.Token)
	if err != nil || l.Value == dnslex.Error {
		return &ParseError{err: "bad SRV Port", lex: l}
	}

	c.Next()        // dnslex.Blank
	l, _ = c.Next() // dnslex.String
	rd.Target = dnsutilAbsolute(l.Token, o)
	if l.Value == dnslex.Error || rd.Target == "" {
		return &ParseError{err: "bad SRV Target", lex: l}
	}
	return toParseError(dnslex.Discard(c))
}

func parseNAPTR(rd *rdata.NAPTR, c *dnslex.Lexer, o string) error {
	var err error
	l, _ := c.Next()
	rd.Order, err = dnsstring.AtoiUint16(l.Token)
	if err != nil || l.Value == dnslex.Error {
		return &ParseError{err: "bad NAPTR Order", lex: l}
	}

	c.Next()        // dnslex.Blank
	l, _ = c.Next() // dnslex.String
	rd.Preference, err = dnsstring.AtoiUint16(l.Token)
	if err != nil || l.Value == dnslex.Error {
		return &ParseError{err: "bad NAPTR Preference", lex: l}
	}

	// Flags
	c.Next()        // dnslex.Blank
	l, _ = c.Next() // dnslex.Quote
	if l.Value != dnslex.Quote {
		return &ParseError{err: "bad NAPTR Flags", lex: l}
	}
	l, _ = c.Next() // Either String or Quote
	switch l.Value {
	case dnslex.String:
		rd.Flags = l.Token
		l, _ = c.Next() // dnslex.Quote
		if l.Value != dnslex.Quote {
			return &ParseError{err: "bad NAPTR Flags", lex: l}
		}
	case dnslex.Quote:
		rd.Flags = ""
	default:
		return &ParseError{err: "bad NAPTR Flags", lex: l}
	}

	// Service
	c.Next()        // dnslex.Blank
	l, _ = c.Next() // dnslex.Quote
	if l.Value != dnslex.Quote {
		return &ParseError{err: "bad NAPTR Service", lex: l}
	}
	l, _ = c.Next() // Either String or Quote
	switch l.Value {
	case dnslex.String:
		rd.Service = l.Token
		l, _ = c.Next() // dnslex.Quote
		if l.Value != dnslex.Quote {
			return &ParseError{err: "bad NAPTR Service", lex: l}
		}
	case dnslex.Quote:
		rd.Service = ""
	default:
		return &ParseError{err: "bad NAPTR Service", lex: l}
	}

	// Regexp
	c.Next()        // dnslex.Blank
	l, _ = c.Next() // dnslex.Quote
	if l.Value != dnslex.Quote {
		return &ParseError{err: "bad NAPTR Regexp", lex: l}
	}
	l, _ = c.Next() // Either String or Quote
	switch l.Value {
	case dnslex.String:
		rd.Regexp = l.Token
		l, _ = c.Next() // _dnslex.Quote
		if l.Value != dnslex.Quote {
			return &ParseError{err: "bad NAPTR Regexp", lex: l}
		}
	case dnslex.Quote:
		rd.Regexp = ""
	default:
		return &ParseError{err: "bad NAPTR Regexp", lex: l}
	}

	// After quote no space??
	c.Next()        // dnslex.Blank
	l, _ = c.Next() // dnslex.String
	rd.Replacement = dnsutilAbsolute(l.Token, o)
	if l.Value == dnslex.Error || rd.Replacement == "" {
		return &ParseError{err: "bad NAPTR Replacement", lex: l}
	}
	return toParseError(dnslex.Discard(c))
}

func parseTALINK(rd *rdata.TALINK, c *dnslex.Lexer, o string) error {
	l, _ := c.Next()
	rd.PreviousName = dnsutilAbsolute(l.Token, o)
	if l.Value == dnslex.Error || rd.PreviousName == "" {
		return &ParseError{err: "bad TALINK PreviousName", lex: l}
	}

	c.Next() // dnslex.Blank
	l, _ = c.Next()
	rd.NextName = l.Token

	rd.NextName = dnsutilAbsolute(l.Token, o)
	if l.Value == dnslex.Error || rd.NextName == "" {
		return &ParseError{err: "bad TALINK NextName", lex: l}
	}
	return toParseError(dnslex.Discard(c))
}

func parseLOC(rd *rdata.LOC, c *dnslex.Lexer, o string) error {
	var err error
	// Non zero defaults for LOC record, see RFC 1876, Section 3.
	rd.Size = 0x12     // 1e2 cm (1m)
	rd.HorizPre = 0x16 // 1e6 cm (10000m)
	rd.VertPre = 0x13  // 1e3 cm (10m)
	ok := false

	// North
	l, _ := c.Next()
	rd.Latitude, err = dnsstring.AtoiUint32(l.Token)
	if err != nil || l.Value == dnslex.Error || rd.Latitude > 90 {
		return &ParseError{err: "bad LOC Latitude", lex: l}
	}
	rd.Latitude = rd.Latitude * 1000 * 60 * 60

	c.Next() // dnslex.Blank
	// Either number, 'N' or 'S'
	l, _ = c.Next()
	if rd.Latitude, ok = locCheckNorth(l.Token, rd.Latitude); ok {
		goto East
	}
	if i, err := dnsstring.AtoiUint32(l.Token); err != nil || l.Value == dnslex.Error || i > 59 {
		return &ParseError{err: "bad LOC Latitude minutes", lex: l}
	} else {
		rd.Latitude += 1000 * 60 * uint32(i)
	}

	c.Next() // dnslex.Blank
	l, _ = c.Next()
	if i, err := strconv.ParseFloat(l.Token, 64); err != nil || l.Value == dnslex.Error || i < 0 || i >= 60 {
		return &ParseError{err: "bad LOC Latitude seconds", lex: l}
	} else {
		rd.Latitude += uint32(1000 * i)
	}
	c.Next() // dnslex.Blank
	// Either number, 'N' or 'S'
	l, _ = c.Next()
	if rd.Latitude, ok = locCheckNorth(l.Token, rd.Latitude); ok {
		goto East
	}
	// If still alive, flag an error
	return &ParseError{err: "bad LOC Latitude North/South", lex: l}

East:
	// East
	c.Next() // dnslex.Blank
	l, _ = c.Next()
	if i, err := dnsstring.AtoiUint32(l.Token); err != nil || l.Value == dnslex.Error || i > 180 {
		return &ParseError{err: "bad LOC Longitude", lex: l}
	} else {
		rd.Longitude = 1000 * 60 * 60 * uint32(i)
	}
	c.Next() // dnslex.Blank
	// Either number, 'E' or 'W'
	l, _ = c.Next()
	if rd.Longitude, ok = locCheckEast(l.Token, rd.Longitude); ok {
		goto Altitude
	}
	if i, err := dnsstring.AtoiUint32(l.Token); err != nil || l.Value == dnslex.Error || i > 59 {
		return &ParseError{err: "bad LOC Longitude minutes", lex: l}
	} else {
		rd.Longitude += 1000 * 60 * uint32(i)
	}
	c.Next() // dnslex.Blank
	l, _ = c.Next()
	if i, err := strconv.ParseFloat(l.Token, 64); err != nil || l.Value == dnslex.Error || i < 0 || i >= 60 {
		return &ParseError{err: "bad LOC Longitude seconds", lex: l}
	} else {
		rd.Longitude += uint32(1000 * i)
	}
	c.Next() // dnslex.Blank
	// Either number, 'E' or 'W'
	l, _ = c.Next()
	if rd.Longitude, ok = locCheckEast(l.Token, rd.Longitude); ok {
		goto Altitude
	}
	// If still alive, flag an error
	return &ParseError{err: "bad LOC Longitude East/West", lex: l}

Altitude:
	c.Next() // dnslex.Blank
	l, _ = c.Next()
	if l.Token == "" || l.Value == dnslex.Error {
		return &ParseError{err: "bad LOC Altitude", lex: l}
	}
	if l.Token[len(l.Token)-1] == 'M' || l.Token[len(l.Token)-1] == 'm' {
		l.Token = l.Token[0 : len(l.Token)-1]
	}
	if i, err := strconv.ParseFloat(l.Token, 64); err != nil {
		return &ParseError{err: "bad LOC Altitude", lex: l}
	} else {
		rd.Altitude = uint32(i*100.0 + 10000000.0 + 0.5)
	}

	// And now optionally the other values
	l, _ = c.Next()
	count := 0
	for l.Value != dnslex.Newline && l.Value != dnslex.EOF {
		switch l.Value {
		case dnslex.String:
			switch count {
			case 0: // Size
				exp, m, ok := stringToCm(l.Token)
				if !ok {
					return &ParseError{err: "bad LOC Size", lex: l}
				}
				rd.Size = exp&0x0F | m<<4&0xF0
			case 1: // HorizPre
				exp, m, ok := stringToCm(l.Token)
				if !ok {
					return &ParseError{err: "bad LOC HorizPre", lex: l}
				}
				rd.HorizPre = exp&0x0F | m<<4&0xF0
			case 2: // VertPre
				exp, m, ok := stringToCm(l.Token)
				if !ok {
					return &ParseError{err: "bad LOC VertPre", lex: l}
				}
				rd.VertPre = exp&0x0F | m<<4&0xF0
			}
			count++
		case dnslex.Blank:
			// Ok
		default:
			return &ParseError{err: "bad LOC Size, HorizPre or VertPre", lex: l}
		}
		l, _ = c.Next()
	}
	return nil
}

func parseHIP(rd *rdata.HIP, c *dnslex.Lexer, o string) error {
	var err error
	// HitLength is not represented
	l, _ := c.Next()
	rd.PublicKeyAlgorithm, err = dnsstring.AtoiUint8(l.Token)
	if err != nil || l.Value == dnslex.Error {
		return &ParseError{err: "bad HIP PublicKeyAlgorithm", lex: l}
	}

	c.Next()        // dnslex.Blank
	l, _ = c.Next() // dnslex.String
	if l.Token == "" || l.Value == dnslex.Error {
		return &ParseError{err: "bad HIP Hit", lex: l}
	}
	rd.Hit = l.Token // This can not contain spaces, see RFC 5205 Section 6.
	rd.HitLength = uint8(len(rd.Hit)) / 2

	c.Next()        // dnslex.Blank
	l, _ = c.Next() // dnslex.String
	if l.Token == "" || l.Value == dnslex.Error {
		return &ParseError{err: "bad HIP PublicKey", lex: l}
	}
	rd.PublicKey = l.Token // This cannot contain spaces
	rd.PublicKeyLength = uint16(base64.StdEncoding.DecodedLen(len(rd.PublicKey)))

	// RendezvousServers (if any)
	l, _ = c.Next()
	var xs []string
	for l.Value != dnslex.Newline && l.Value != dnslex.EOF {
		switch l.Value {
		case dnslex.String:
			name := dnsutilAbsolute(l.Token, o)
			if l.Value == dnslex.Error || name == "" {
				return &ParseError{err: "bad HIP RendezvousServers", lex: l}
			}
			xs = append(xs, name)
		case dnslex.Blank:
			// Ok
		default:
			return &ParseError{err: "bad HIP RendezvousServers", lex: l}
		}
		l, _ = c.Next()
	}

	rd.RendezvousServers = xs
	return nil
}

func parseCERT(rd *rdata.CERT, c *dnslex.Lexer, o string) error {
	var err error
	l, _ := c.Next()
	if v, ok := StringToCertType[l.Token]; ok {
		rd.Type = v
	} else if i, err := strconv.ParseUint(l.Token, 10, 16); err != nil {
		return &ParseError{err: "bad CERT Type", lex: l}
	} else {
		rd.Type = uint16(i)
	}

	c.Next()        // dnslex.Blank
	l, _ = c.Next() // dnslex.String
	rd.KeyTag, err = dnsstring.AtoiUint16(l.Token)
	if err != nil || l.Value == dnslex.Error {
		return &ParseError{err: "bad CERT KeyTag", lex: l}
	}

	c.Next()        // dnslex.Blank
	l, _ = c.Next() // dnslex.String
	var ok bool
	rd.Algorithm, ok = upperLookup(l.Token, StringToAlgorithm)
	if !ok {
		if rd.Algorithm, err = dnsstring.AtoiUint8(l.Token); err != nil {
			return &ParseError{err: "bad CERT Algorithm", lex: l}
		}
	}
	rd.Certificate, err = remainder(c, "bad CERT Certificate")
	return err
}

func parseOPENPGPKEY(rd *rdata.OPENPGPKEY, c *dnslex.Lexer, o string) error {
	var err error
	rd.PublicKey, err = remainder(c, "bad OPENPGPKEY PublicKey")
	return err
}

func parseCSYNC(rd *rdata.CSYNC, c *dnslex.Lexer, o string) error {
	var err error
	l, _ := c.Next()
	rd.Serial, err = dnsstring.AtoiUint32(l.Token)
	if err != nil {
		return &ParseError{err: "bad CSYNC Serial", lex: l}
	}

	c.Next() // dnslex.Blank
	l, _ = c.Next()
	rd.Flags, err = dnsstring.AtoiUint16(l.Token)
	if err != nil {
		return &ParseError{err: "bad CSYNC Flags", lex: l}
	}

	rd.TypeBitMap = make([]uint16, 3)
	var (
		k  uint16
		ok bool
	)
	l, _ = c.Next()
	for l.Value != dnslex.Newline && l.Value != dnslex.EOF {
		switch l.Value {
		case dnslex.Blank:
			// Ok
		case dnslex.String:
			k, ok = StringToType[l.Token]
			if !ok {
				if !strings.HasPrefix(l.Token, "TYPE") {
					return &ParseError{err: "bad CSYNC TypeBitMap", lex: l}
				}
				if k, ok = dnslex.TypeToInt(l.Token); !ok {
					return &ParseError{err: "bad CSYNC TypeBitMap", lex: l}
				}
			}
			rd.TypeBitMap = append(rd.TypeBitMap, k)
		default:
			return &ParseError{err: "bad CSYNC TypeBitMap", lex: l}
		}
		l, _ = c.Next()
	}
	return nil
}

func parseZONEMD(rd *rdata.ZONEMD, c *dnslex.Lexer, o string) error {
	var err error
	l, _ := c.Next()
	rd.Serial, err = dnsstring.AtoiUint32(l.Token)
	if err != nil || l.Value == dnslex.Error {
		return &ParseError{err: "bad ZONEMD Serial", lex: l}
	}

	c.Next() // dnslex.Blank
	l, _ = c.Next()
	rd.Scheme, err = dnsstring.AtoiUint8(l.Token)
	if err != nil || l.Value == dnslex.Error {
		return &ParseError{err: "bad ZONEMD Scheme", lex: l}
	}

	c.Next() // dnslex.Blank
	l, _ = c.Next()
	rd.Hash, err = dnsstring.AtoiUint8(l.Token)
	if err != nil || l.Value == dnslex.Error {
		return &ParseError{err: "bad ZONEMD Hash Algorithm", lex: l}
	}

	rd.Digest, err = remainder(c, "bad ZONEMD Digest")
	return err
}

func parseRRSIG(rd *rdata.RRSIG, c *dnslex.Lexer, o string) error {
	var err error
	var ok bool
	l, _ := c.Next()
	rd.TypeCovered, ok = StringToType[l.Token]
	if !ok {
		if !strings.HasPrefix(l.Token, "TYPE") {
			return &ParseError{err: "bad RRSIG Typecovered", lex: l}
		}
		if rd.TypeCovered, ok = dnslex.TypeToInt(l.Token); !ok {
			return &ParseError{err: "bad RRSIG Typecovered", lex: l}
		}
	}

	c.Next() // dnslex.Blank
	l, _ = c.Next()
	if l.Value == dnslex.Error {
		return &ParseError{err: "bad RRSIG Algorithm", lex: l}
	}
	rd.Algorithm, err = dnsstring.AtoiUint8(l.Token)
	if err != nil {
		if rd.Algorithm, ok = upperLookup(l.Token, StringToAlgorithm); !ok {
			return &ParseError{err: "bad RRSIG Algorithm", lex: l}
		}
	}

	c.Next() // dnslex.Blank
	l, _ = c.Next()
	rd.Labels, err = dnsstring.AtoiUint8(l.Token)
	if err != nil || l.Value == dnslex.Error {
		return &ParseError{err: "bad RRSIG Labels", lex: l}
	}

	c.Next() // dnslex.Blank
	l, _ = c.Next()
	rd.OrigTTL, err = dnsstring.AtoiUint32(l.Token)
	if err != nil || l.Value == dnslex.Error {
		return &ParseError{err: "bad RRSIG OrigTTL", lex: l}
	}

	c.Next() // dnslex.Blank
	l, _ = c.Next()
	rd.Expiration, err = dnsutilStringToTime(l.Token)
	if err != nil {
		rd.Expiration, err = dnsstring.AtoiUint32(l.Token) // Try to see if all numeric and use it as epoch.
		if err != nil {
			return &ParseError{err: "bad RRSIG Expiration", lex: l}
		}
	}

	c.Next() // dnslex.Blank
	l, _ = c.Next()
	rd.Inception, err = dnsutilStringToTime(l.Token)
	if err != nil {
		rd.Inception, err = dnsstring.AtoiUint32(l.Token)
		if err != nil {
			return &ParseError{err: "bad RRSIG Inception", lex: l}
		}
	}

	c.Next() // dnslex.Blank
	l, _ = c.Next()
	rd.KeyTag, err = dnsstring.AtoiUint16(l.Token)
	if err != nil {
		return &ParseError{err: "bad RRSIG KeyTag", lex: l}
	}

	c.Next() // dnslex.Blank
	l, _ = c.Next()
	rd.SignerName = dnsutilAbsolute(l.Token, o)
	if l.Value == dnslex.Error || rd.SignerName == "" {
		return &ParseError{err: "bad RRSIG SignerName", lex: l}
	}

	rd.Signature, err = remainder(c, "bad RRSIG Signature")
	return err
}

func parseNSEC(rd *rdata.NSEC, c *dnslex.Lexer, o string) error {
	l, _ := c.Next()
	rd.NextDomain = dnsutilAbsolute(l.Token, o)
	if l.Value == dnslex.Error || rd.NextDomain == "" {
		return &ParseError{err: "bad NSEC NextDomain", lex: l}
	}

	rd.TypeBitMap = make([]uint16, 0, 2)
	var (
		k  uint16
		ok bool
	)
	l, _ = c.Next()
	for l.Value != dnslex.Newline && l.Value != dnslex.EOF {
		switch l.Value {
		case dnslex.Blank:
			// Ok
		case dnslex.String:
			k, ok = StringToType[l.Token]
			if !ok {
				if !strings.HasPrefix(l.Token, "TYPE") {
					return &ParseError{err: "bad NSEC TypeBitMap", lex: l}
				}
				if k, ok = dnslex.TypeToInt(l.Token); !ok {
					return &ParseError{err: "bad NSEC TypeBitMap", lex: l}
				}
			}
			rd.TypeBitMap = append(rd.TypeBitMap, k)
		default:
			return &ParseError{err: "bad NSEC TypeBitMap", lex: l}
		}
		l, _ = c.Next()
	}
	return nil
}

func parseNSEC3(rd *rdata.NSEC3, c *dnslex.Lexer, o string) error {
	var err error
	l, _ := c.Next()
	rd.Hash, err = dnsstring.AtoiUint8(l.Token)
	if err != nil || l.Value == dnslex.Error {
		return &ParseError{err: "bad NSEC3 Hash", lex: l}
	}

	c.Next() // dnslex.Blank
	l, _ = c.Next()
	rd.Flags, err = dnsstring.AtoiUint8(l.Token)
	if err != nil || l.Value == dnslex.Error {
		return &ParseError{err: "bad NSEC3 Flags", lex: l}
	}

	c.Next() // dnslex.Blank
	l, _ = c.Next()
	rd.Iterations, err = dnsstring.AtoiUint16(l.Token)
	if err != nil || l.Value == dnslex.Error {
		return &ParseError{err: "bad NSEC3 Iterations", lex: l}
	}

	c.Next()
	l, _ = c.Next()
	if l.Token == "" || l.Value == dnslex.Error {
		return &ParseError{err: "bad NSEC3 Salt", lex: l}
	}
	if l.Token != "-" {
		rd.SaltLength = uint8(len(l.Token)) / 2
		rd.Salt = l.Token
	}

	c.Next()
	l, _ = c.Next()
	rd.NextDomain = l.Token // do not append origin, this is a hashed name
	if l.Value == dnslex.Error || rd.NextDomain == "" {
		return &ParseError{err: "bad NSEC3 NextDomain", lex: l}
	}
	rd.HashLength = 20 // Fix for NSEC3 (sha1 160 bits)

	rd.TypeBitMap = make([]uint16, 0, 3)
	var (
		k  uint16
		ok bool
	)
	l, _ = c.Next()
	for l.Value != dnslex.Newline && l.Value != dnslex.EOF {
		switch l.Value {
		case dnslex.Blank:
			// Ok
		case dnslex.String:
			k, ok = StringToType[l.Token]
			if !ok {
				if !strings.HasPrefix(l.Token, "TYPE") {
					return &ParseError{err: "bad NSEC3 TypeBitMap", lex: l}
				}
				if k, ok = dnslex.TypeToInt(l.Token); !ok {
					return &ParseError{err: "bad NSEC3 TypeBitMap", lex: l}
				}
			}
			rd.TypeBitMap = append(rd.TypeBitMap, k)
		default:
			return &ParseError{err: "bad NSEC3 TypeBitMap", lex: l}
		}
		l, _ = c.Next()
	}
	return nil
}

func parseNSEC3PARAM(rd *rdata.NSEC3PARAM, c *dnslex.Lexer, o string) error {
	var err error
	l, _ := c.Next()
	rd.Hash, err = dnsstring.AtoiUint8(l.Token)
	if err != nil || l.Value == dnslex.Error {
		return &ParseError{err: "bad NSEC3PARAM Hash", lex: l}
	}

	c.Next() // dnslex.Blank
	l, _ = c.Next()
	rd.Flags, err = dnsstring.AtoiUint8(l.Token)
	if err != nil || l.Value == dnslex.Error {
		return &ParseError{err: "bad NSEC3PARAM Flags", lex: l}
	}

	c.Next() // dnslex.Blank
	l, _ = c.Next()
	rd.Iterations, err = dnsstring.AtoiUint16(l.Token)
	if err != nil || l.Value == dnslex.Error {
		return &ParseError{err: "bad NSEC3PARAM Iterations", lex: l}
	}

	c.Next()
	l, _ = c.Next()
	if l.Token != "-" {
		rd.SaltLength = uint8(len(l.Token) / 2)
		rd.Salt = l.Token
	}
	return toParseError(dnslex.Discard(c))
}

func parseEUI48(rd *rdata.EUI48, c *dnslex.Lexer, o string) error {
	l, _ := c.Next()
	if len(l.Token) != 17 || l.Value == dnslex.Error {
		return &ParseError{err: "bad EUI48 Address", lex: l}
	}
	addr := make([]byte, 12)
	dash := 0
	for i := 0; i < 10; i += 2 {
		addr[i] = l.Token[i+dash]
		addr[i+1] = l.Token[i+1+dash]
		dash++
		if l.Token[i+1+dash] != '-' {
			return &ParseError{err: "bad EUI48 Address", lex: l}
		}
	}
	addr[10] = l.Token[15]
	addr[11] = l.Token[16]

	i, err := strconv.ParseUint(string(addr), 16, 48)
	if err != nil {
		return &ParseError{err: "bad EUI48 Address", lex: l}
	}
	rd.Address = i
	return toParseError(dnslex.Discard(c))
}

func parseEUI64(rd *rdata.EUI64, c *dnslex.Lexer, o string) error {
	l, _ := c.Next()
	if len(l.Token) != 23 || l.Value == dnslex.Error {
		return &ParseError{err: "bad EUI64 Address", lex: l}
	}
	addr := make([]byte, 16)
	dash := 0
	for i := 0; i < 14; i += 2 {
		addr[i] = l.Token[i+dash]
		addr[i+1] = l.Token[i+1+dash]
		dash++
		if l.Token[i+1+dash] != '-' {
			return &ParseError{err: "bad EUI64 Address", lex: l}
		}
	}
	addr[14] = l.Token[21]
	addr[15] = l.Token[22]

	i, err := strconv.ParseUint(string(addr), 16, 64)
	if err != nil {
		return &ParseError{err: "bad EUI68 Address", lex: l}
	}
	rd.Address = i
	return toParseError(dnslex.Discard(c))
}

func parseSSHFP(rd *rdata.SSHFP, c *dnslex.Lexer, o string) error {
	var err error
	l, _ := c.Next()
	rd.Algorithm, err = dnsstring.AtoiUint8(l.Token)
	if err != nil || l.Value == dnslex.Error {
		return &ParseError{err: "bad SSHFP Algorithm", lex: l}
	}

	c.Next() // dnslex.Blank
	l, _ = c.Next()
	rd.Type, err = dnsstring.AtoiUint8(l.Token)
	if err != nil || l.Value == dnslex.Error {
		return &ParseError{err: "bad SSHFP Type", lex: l}
	}

	c.Next() // dnslex.Blank
	rd.FingerPrint, err = remainder(c, "bad SSHFP Fingerprint")
	return err
}

func parseDNSKEY(rd *rdata.DNSKEY, c *dnslex.Lexer, o string) error {
	var err error
	l, _ := c.Next()
	rd.Flags, err = dnsstring.AtoiUint16(l.Token)
	if err != nil || l.Value == dnslex.Error {
		return &ParseError{err: "bad DNSKEY Flags", lex: l}
	}

	c.Next()        // dnslex.Blank
	l, _ = c.Next() // dnslex.String
	rd.Protocol, err = dnsstring.AtoiUint8(l.Token)
	if err != nil || l.Value == dnslex.Error {
		return &ParseError{err: "bad DNSKEY Protocol", lex: l}
	}

	c.Next()        // dnslex.Blank
	l, _ = c.Next() // dnslex.String
	rd.Algorithm, err = dnsstring.AtoiUint8(l.Token)
	if err != nil || l.Value == dnslex.Error {
		return &ParseError{err: "bad DNSKEY Algorithm", lex: l}
	}

	rd.PublicKey, err = remainder(c, "bad DNSKEY PublicKey")
	return err
}

func parseRKEY(rd *rdata.RKEY, c *dnslex.Lexer, o string) error {
	var err error
	l, _ := c.Next()
	rd.Flags, err = dnsstring.AtoiUint16(l.Token)
	if err != nil || l.Value == dnslex.Error {
		return &ParseError{err: "bad RKEY Flags", lex: l}
	}

	c.Next()        // dnslex.Blank
	l, _ = c.Next() // dnslex.String
	rd.Protocol, err = dnsstring.AtoiUint8(l.Token)
	if err != nil || l.Value == dnslex.Error {
		return &ParseError{err: "bad RKEY Protocol", lex: l}
	}

	c.Next()        // dnslex.Blank
	l, _ = c.Next() // dnslex.String
	rd.Algorithm, err = dnsstring.AtoiUint8(l.Token)
	if err != nil || l.Value == dnslex.Error {
		return &ParseError{err: "bad RKEY Algorithm", lex: l}
	}

	rd.PublicKey, err = remainder(c, "bad RKEY PublicKey")
	return err
}

func parseEID(rd *rdata.EID, c *dnslex.Lexer, o string) error {
	var err error
	rd.Endpoint, err = remainder(c, "bad EID Endpoint")
	return err
}

func parseNIMLOC(rd *rdata.NIMLOC, c *dnslex.Lexer, o string) error {
	var err error
	rd.Locator, err = remainder(c, "bad NIMLOC Locator")
	return err
}

func parseGPOS(rd *rdata.GPOS, c *dnslex.Lexer, o string) error {
	var err error
	l, _ := c.Next()
	if _, err = strconv.ParseFloat(l.Token, 64); err != nil || l.Value == dnslex.Error {
		return &ParseError{err: "bad GPOS Longitude", lex: l}
	}
	rd.Longitude = l.Token

	c.Next() // dnslex.Blank
	l, _ = c.Next()
	if _, err = strconv.ParseFloat(l.Token, 64); err != nil || l.Value == dnslex.Error {
		return &ParseError{err: "bad GPOS Latitude", lex: l}
	}
	rd.Latitude = l.Token

	c.Next() // dnslex.Blank
	l, _ = c.Next()
	if _, err = strconv.ParseFloat(l.Token, 64); err != nil || l.Value == dnslex.Error {
		return &ParseError{err: "bad GPOS Altitude", lex: l}
	}
	rd.Altitude = l.Token
	return toParseError(dnslex.Discard(c))
}

func parseDS(rd *rdata.DS, c *dnslex.Lexer, o string) error {
	var err error
	l, _ := c.Next()
	rd.KeyTag, err = dnsstring.AtoiUint16(l.Token)
	if err != nil || l.Value == dnslex.Error {
		return &ParseError{err: "bad DS KeyTag", lex: l}
	}

	c.Next() // dnslex.Blank
	l, _ = c.Next()
	rd.Algorithm, err = dnsstring.AtoiUint8(l.Token)
	if err != nil {
		var ok bool
		rd.Algorithm, ok = upperLookup(l.Token, StringToAlgorithm)
		if !ok || l.Value == dnslex.Error {
			return &ParseError{err: "bad DS Algorithm", lex: l}
		}
	}

	c.Next() // dnslex.Blank
	l, _ = c.Next()
	rd.DigestType, err = dnsstring.AtoiUint8(l.Token)
	if err != nil || l.Value == dnslex.Error {
		return &ParseError{err: "bad DS DigestType", lex: l}
	}
	rd.Digest, err = remainder(c, "bad DS Digest")
	return err
}

func parseTA(rd *rdata.TA, c *dnslex.Lexer, o string) error {
	var err error
	l, _ := c.Next()
	rd.KeyTag, err = dnsstring.AtoiUint16(l.Token)
	if err != nil || l.Value == dnslex.Error {
		return &ParseError{err: "bad TA KeyTag", lex: l}
	}

	c.Next() // dnslex.Blank
	l, _ = c.Next()
	rd.Algorithm, err = dnsstring.AtoiUint8(l.Token)
	if err != nil {
		var ok bool
		rd.Algorithm, ok = upperLookup(l.Token, StringToAlgorithm)
		if !ok || l.Value == dnslex.Error {
			return &ParseError{err: "bad TA Algorithm", lex: l}
		}
	}

	c.Next() // dnslex.Blank
	l, _ = c.Next()
	rd.DigestType, err = dnsstring.AtoiUint8(l.Token)
	if err != nil || l.Value == dnslex.Error {
		return &ParseError{err: "bad TA DigestType", lex: l}
	}

	rd.Digest, err = remainder(c, "bad TA Digest")
	return err
}

func parseTLSA(rd *rdata.TLSA, c *dnslex.Lexer, o string) error {
	var err error
	l, _ := c.Next()
	rd.Usage, err = dnsstring.AtoiUint8(l.Token)
	if err != nil || l.Value == dnslex.Error {
		return &ParseError{err: "bad TLSA Usage", lex: l}
	}

	c.Next() // dnslex.Blank
	l, _ = c.Next()
	rd.Selector, err = dnsstring.AtoiUint8(l.Token)
	if err != nil || l.Value == dnslex.Error {
		return &ParseError{err: "bad TLSA Selector", lex: l}
	}

	c.Next() // dnslex.Blank
	l, _ = c.Next()
	rd.MatchingType, err = dnsstring.AtoiUint8(l.Token)
	if err != nil || l.Value == dnslex.Error {
		return &ParseError{err: "bad TLSA MatchingType", lex: l}
	}

	rd.Certificate, err = remainder(c, "bad TLSA Certificate")
	return err
}

func parseSMIMEA(rd *rdata.SMIMEA, c *dnslex.Lexer, o string) error {
	var err error
	l, _ := c.Next()
	rd.Usage, err = dnsstring.AtoiUint8(l.Token)
	if err != nil || l.Value == dnslex.Error {
		return &ParseError{err: "bad SMIMEA Usage", lex: l}
	}

	c.Next() // dnslex.Blank
	l, _ = c.Next()
	rd.Selector, err = dnsstring.AtoiUint8(l.Token)
	if err != nil || l.Value == dnslex.Error {
		return &ParseError{err: "bad SMIMEA Selector", lex: l}
	}

	c.Next() // dnslex.Blank
	l, _ = c.Next()
	rd.MatchingType, err = dnsstring.AtoiUint8(l.Token)
	if err != nil || l.Value == dnslex.Error {
		return &ParseError{err: "bad SMIMEA MatchingType", lex: l}
	}

	rd.Certificate, err = remainder(c, "bad SMIMEA Certificate")
	return err
}

func parseRFC3597(rd *rdata.RFC3597, c *dnslex.Lexer, o string) error {
	l, _ := c.Next()
	if l.Token != "\\#" {
		return &ParseError{err: "bad RFC3597 Rdata", lex: l}
	}

	c.Next() // dnslex.Blank
	l, _ = c.Next()
	rdlength, err := strconv.ParseUint(l.Token, 10, 16)
	if err != nil || l.Value == dnslex.Error {
		return &ParseError{err: "bad RFC3597 Rdata ", lex: l}
	}

	rd.Data, err = remainder(c, "bad RFC3597 Rdata")
	if int(rdlength)*2 != len(rd.Data) {
		return &ParseError{err: "bad RFC3597 Rdata", lex: l}
	}
	return err
}

func parseTXT(rd *rdata.TXT, c *dnslex.Lexer, o string) error {
	var err error
	// no dnslex.Blank reading here, because all this rdata is TXT
	rd.Txt, err = remainderSlice(c, "bad TXT Txt")
	return err
}

// identical to setTXT
func parseNINFO(rd *rdata.NINFO, c *dnslex.Lexer, o string) error {
	var err error
	rd.ZSData, err = remainderSlice(c, "bad NINFO ZSData")
	return err
}

func parseIPN(rd *rdata.IPN, c *dnslex.Lexer, o string) error {
	l, _ := c.Next()
	i, err := strconv.ParseUint(l.Token, 10, 64)
	if err != nil || l.Value == dnslex.Error {
		return &ParseError{err: "bad IPN Node", lex: l}
	}
	rd.Node = uint64(i)
	return toParseError(dnslex.Discard(c))
}

func parseURI(rd *rdata.URI, c *dnslex.Lexer, o string) error {
	var err error
	l, _ := c.Next()
	rd.Priority, err = dnsstring.AtoiUint16(l.Token)
	if err != nil || l.Value == dnslex.Error {
		return &ParseError{err: "bad URI Priority", lex: l}
	}

	c.Next() // dnslex.Blank
	l, _ = c.Next()
	rd.Weight, err = dnsstring.AtoiUint16(l.Token)
	if err != nil || l.Value == dnslex.Error {
		return &ParseError{err: "bad URI Weight", lex: l}
	}

	c.Next() // dnslex.Blank
	s, err := remainderSlice(c, "bad URI Target")
	if err != nil {
		return err
	}
	if len(s) != 1 {
		return &ParseError{err: "bad URI Target", lex: l}
	}
	rd.Target = s[0]
	return nil
}

func parseDHCID(rd *rdata.DHCID, c *dnslex.Lexer, o string) error {
	var err error
	// awesome record to parse!
	rd.Digest, err = remainder(c, "bad DHCID Digest")
	return err
}

func parseNID(rd *rdata.NID, c *dnslex.Lexer, o string) error {
	var err error
	l, _ := c.Next()
	rd.Preference, err = dnsstring.AtoiUint16(l.Token)
	if err != nil || l.Value == dnslex.Error {
		return &ParseError{err: "bad NID Preference", lex: l}
	}

	c.Next()        // dnslex.Blank
	l, _ = c.Next() // dnslex.String
	rd.NodeID, err = stringToNodeID(l)
	if err != nil || l.Value == dnslex.Error {
		return err
	}
	return toParseError(dnslex.Discard(c))
}

func parseL32(rd *rdata.L32, c *dnslex.Lexer, o string) error {
	var err error
	l, _ := c.Next()
	rd.Preference, err = dnsstring.AtoiUint16(l.Token)
	if err != nil || l.Value == dnslex.Error {
		return &ParseError{err: "bad L32 Preference", lex: l}
	}

	c.Next()        // dnslex.Blank
	l, _ = c.Next() // dnslex.String
	rd.Locator32, err = netip.ParseAddr(l.Token)
	if l.Value == dnslex.Error || err != nil || !rd.Locator32.Is4() {
		return &ParseError{err: "bad L32 Locator", lex: l}
	}
	return toParseError(dnslex.Discard(c))
}

func parseLP(rd *rdata.LP, c *dnslex.Lexer, o string) error {
	var err error
	l, _ := c.Next()
	rd.Preference, err = dnsstring.AtoiUint16(l.Token)
	if err != nil || l.Value == dnslex.Error {
		return &ParseError{err: "bad LP Preference", lex: l}
	}

	c.Next()        // dnslex.Blank
	l, _ = c.Next() // dnslex.String
	rd.Fqdn = dnsutilAbsolute(l.Token, o)
	if l.Value == dnslex.Error || rd.Fqdn == "" {
		return &ParseError{err: "bad LP Fqdn", lex: l}
	}
	return toParseError(dnslex.Discard(c))
}

func parseL64(rd *rdata.L64, c *dnslex.Lexer, o string) error {
	var err error
	l, _ := c.Next()
	rd.Preference, err = dnsstring.AtoiUint16(l.Token)
	if err != nil || l.Value == dnslex.Error {
		return &ParseError{err: "bad L64 Preference", lex: l}
	}

	c.Next()        // dnslex.Blank
	l, _ = c.Next() // dnslex.String
	rd.Locator64, err = stringToNodeID(l)
	if err != nil || l.Value == dnslex.Error {
		return err
	}
	return toParseError(dnslex.Discard(c))
}

func parseUID(rd *rdata.UID, c *dnslex.Lexer, o string) error {
	var err error
	l, _ := c.Next()
	rd.Uid, err = dnsstring.AtoiUint32(l.Token)
	if err != nil || l.Value == dnslex.Error {
		return &ParseError{err: "bad UID Uid", lex: l}
	}
	return toParseError(dnslex.Discard(c))
}

func parseGID(rd *rdata.GID, c *dnslex.Lexer, o string) error {
	var err error
	l, _ := c.Next()
	rd.Gid, err = dnsstring.AtoiUint32(l.Token)
	if err != nil || l.Value == dnslex.Error {
		return &ParseError{err: "bad GID Gid", lex: l}
	}
	return toParseError(dnslex.Discard(c))
}

func parseUINFO(rd *rdata.UINFO, c *dnslex.Lexer, o string) error {
	s, err := remainderSlice(c, "bad UINFO Uinfo")
	if err != nil {
		return err
	}
	if len(s) != 1 {
		return nil // TODO(miek): ?
	}
	rd.Uinfo = s[0] // silently discard anything after the first character-string
	return nil
}

func parsePX(rd *rdata.PX, c *dnslex.Lexer, o string) error {
	var err error
	l, _ := c.Next()
	rd.Preference, err = dnsstring.AtoiUint16(l.Token)
	if err != nil || l.Value == dnslex.Error {
		return &ParseError{err: "bad PX Preference", lex: l}
	}

	c.Next()        // dnslex.Blank
	l, _ = c.Next() // dnslex.String
	rd.Map822 = dnsutilAbsolute(l.Token, o)
	if l.Value == dnslex.Error || rd.Map822 == "" {
		return &ParseError{err: "bad PX Map822", lex: l}
	}

	c.Next()        // dnslex.Blank
	l, _ = c.Next() // dnslex.String
	rd.Mapx400 = dnsutilAbsolute(l.Token, o)
	if l.Value == dnslex.Error || rd.Mapx400 == "" {
		return &ParseError{err: "bad PX Mapx400", lex: l}
	}
	return toParseError(dnslex.Discard(c))
}

func parseCAA(rd *rdata.CAA, c *dnslex.Lexer, o string) error {
	var err error
	l, _ := c.Next()
	rd.Flag, err = dnsstring.AtoiUint8(l.Token)
	if err != nil || l.Value == dnslex.Error {
		return &ParseError{err: "bad CAA Flag", lex: l}
	}

	c.Next()        // dnslex.Blank
	l, _ = c.Next() // dnslex.String
	if l.Value != dnslex.String {
		return &ParseError{err: "bad CAA Tag", lex: l}
	}
	rd.Tag = l.Token

	c.Next() // dnslex.Blank
	s, err := remainderSlice(c, "bad CAA Value")
	if err != nil {
		return err
	}
	if len(s) != 1 {
		return &ParseError{err: "bad CAA Value", lex: l}
	}
	rd.Value = s[0]
	return nil
}

func parseTKEY(rd *rdata.TKEY, c *dnslex.Lexer, o string) error {
	var err error
	l, _ := c.Next()

	// Algorithm
	if l.Value != dnslex.String {
		return &ParseError{err: "bad TKEY Algorithm", lex: l}
	}
	rd.Algorithm = l.Token
	c.Next() // dnslex.Blank

	// Get the key length and key values
	l, _ = c.Next()
	rd.KeySize, err = dnsstring.AtoiUint16(l.Token)
	if err != nil || l.Value == dnslex.Error {
		return &ParseError{err: "bad TKEY KeySize", lex: l}
	}

	c.Next() // dnslex.Blank
	l, _ = c.Next()
	if l.Value != dnslex.String {
		return &ParseError{err: "bad TKEY Key", lex: l}
	}
	rd.Key = l.Token
	c.Next() // dnslex.Blank

	// Get the otherdata length and string data
	l, _ = c.Next()
	rd.OtherLen, err = dnsstring.AtoiUint16(l.Token)
	if err != nil || l.Value == dnslex.Error {
		return &ParseError{err: "bad TKEY OtherLen", lex: l}
	}

	c.Next() // dnslex.Blank
	l, _ = c.Next()
	if l.Value != dnslex.String {
		return &ParseError{err: "bad TKEY OtherData", lex: l}
	}
	rd.OtherData = l.Token
	return nil
}

func parseSVCB(rd *rdata.SVCB, c *dnslex.Lexer, o string) error {
	var err error
	l, _ := c.Next()
	rd.Priority, err = dnsstring.AtoiUint16(l.Token)
	if err != nil || l.Value == dnslex.Error {
		return &ParseError{file: l.Token, err: "bad SVCB Priority", lex: l}
	}

	c.Next()        // dnslex.Blank
	l, _ = c.Next() // dnslex.String
	rd.Target = l.Token

	rd.Target = dnsutilAbsolute(l.Token, o)
	if l.Value == dnslex.Error || rd.Target == "" {
		return &ParseError{file: l.Token, err: "bad SVCB Target", lex: l}
	}

	// Values (if any)
	l, _ = c.Next()
	var xs []svcb.Pair
	// Helps require whitespace between pairs.
	// Prevents key1000="a"key1001=...
	canHaveNextKey := true
	for l.Value != dnslex.Newline && l.Value != dnslex.EOF {
		switch l.Value {
		case dnslex.String:
			if !canHaveNextKey {
				// The key we can now read was probably meant to be
				// a part of the last value.
				return &ParseError{file: l.Token, err: "bad SVCB value quotation", lex: l}
			}

			// In key=value pairs, value does not have to be quoted unless value
			// contains whitespace. And keys don't need to have values.
			// Similarly, keys with an equality signs after them don't need values.
			// l.Token includes at least up to the first equality sign.
			idx := strings.IndexByte(l.Token, '=')
			var key, value string
			if idx < 0 {
				// Key with no value and no equality sign
				key = l.Token
			} else if idx == 0 {
				return &ParseError{file: l.Token, err: "bad SVCB Key", lex: l}
			} else {
				key, value = l.Token[:idx], l.Token[idx+1:]

				if value == "" {
					// We have a key and an equality sign. Maybe we have nothing
					// after "=" or we have a double quote.
					l, _ = c.Next()
					if l.Value == dnslex.Quote {
						// Only needed when value ends with double quotes.
						// Any value starting with dnslex.Quote ends with it.
						canHaveNextKey = false

						l, _ = c.Next()
						switch l.Value {
						case dnslex.String:
							// We have a value in double quotes.
							value = l.Token
							l, _ = c.Next()
							if l.Value != dnslex.Quote {
								return &ParseError{file: l.Token, err: "SVCB unterminated value", lex: l}
							}
						case dnslex.Quote:
							// There's nothing in double quotes.
						default:
							return &ParseError{file: l.Token, err: "bad SVCB Pair", lex: l}
						}
					}
				}
			}
			pairFn := svcb.KeyToPair(svcb.StringToKey(key))
			if pairFn == nil {
				return &ParseError{file: l.Token, err: "bad SVCB Key", lex: l}
			}
			pair := pairFn()
			if err := svcb.Parse(pair, value, o); err != nil {
				return &ParseError{file: l.Token, wrappedErr: err, lex: l}
			}
			xs = append(xs, pair)
		case dnslex.Quote:
			return &ParseError{file: l.Token, err: "SVCB Key can't contain double quotes", lex: l}
		case dnslex.Blank:
			canHaveNextKey = true
		default:
			return &ParseError{file: l.Token, err: "bad SVCB Pairs", lex: l}
		}
		l, _ = c.Next()
	}

	// "In AliasMode, records SHOULD NOT include any SvcParams, and recipients MUST
	// ignore any SvcParams that are present."
	// However, we don't check rd.Priority == 0 && len(xs) > 0 here
	// It is the responsibility of the user of the library to check this.
	// This is to encourage the fixing of the source of this error.

	rd.Value = xs
	return nil
}

func parseDELEG(rd *rdata.DELEG, c *dnslex.Lexer, o string) error {
	// TODO(miek): unify with SVCB
	// Values (if any)
	l, _ := c.Next()
	var xs []deleg.Info
	// Helps require whitespace between infos.
	// Prevents key1000="a"key1001=...
	canHaveNextKey := true
	for l.Value != dnslex.Newline && l.Value != dnslex.EOF {
		switch l.Value {
		case dnslex.String:
			if !canHaveNextKey {
				// The key we can now read was probably meant to be
				// a part of the last value.
				return &ParseError{file: l.Token, err: "bad DELEG value quotation", lex: l}
			}

			// In key=value infos, value does not have to be quoted unless value
			// contains whitespace. And keys don't need to have values.
			// Similarly, keys with an equality signs after them don't need values.
			// l.Token includes at least up to the first equality sign.
			idx := strings.IndexByte(l.Token, '=')
			var key, value string
			if idx < 0 {
				// Key with no value and no equality sign
				key = l.Token
			} else if idx == 0 {
				return &ParseError{file: l.Token, err: "bad DELEG Key", lex: l}
			} else {
				key, value = l.Token[:idx], l.Token[idx+1:]

				if value == "" {
					// We have a key and an equality sign. Maybe we have nothing
					// after "=" or we have a double quote.
					l, _ = c.Next()
					if l.Value == dnslex.Quote {
						// Only needed when value ends with double quotes.
						// Any value starting with dnslex.Quote ends with it.
						canHaveNextKey = false

						l, _ = c.Next()
						switch l.Value {
						case dnslex.String:
							// We have a value in double quotes.
							value = l.Token
							l, _ = c.Next()
							if l.Value != dnslex.Quote {
								return &ParseError{file: l.Token, err: "DELEG unterminated value", lex: l}
							}
						case dnslex.Quote:
							// There's nothing in double quotes.
						default:
							return &ParseError{file: l.Token, err: "bad DELEG Info", lex: l}
						}
					}
				}
			}
			infoFn := deleg.KeyToInfo(deleg.StringToKey(key))
			if infoFn == nil {
				return &ParseError{file: l.Token, err: "bad DELEG Key", lex: l}
			}
			info := infoFn()
			if err := deleg.Parse(info, value, o); err != nil {
				return &ParseError{file: l.Token, wrappedErr: err, lex: l}
			}
			xs = append(xs, info)
		case dnslex.Quote:
			return &ParseError{file: l.Token, err: "DELEG Key can't contain double quotes", lex: l}
		case dnslex.Blank:
			canHaveNextKey = true
		default:
			return &ParseError{file: l.Token, err: "bad DELEG Infos", lex: l}
		}
		l, _ = c.Next()
	}
	rd.Value = xs
	return nil
}

func parseDSYNC(rd *rdata.DSYNC, c *dnslex.Lexer, o string) error {
	var err error
	l, _ := c.Next()
	rd.Type = StringToType[l.Token]

	c.Next()        // dnslex.Blank
	l, _ = c.Next() // dnslex.String
	if strings.ToUpper(l.Token) == "NOTIFY" || l.Token == "1" {
		rd.Scheme = 1
	}

	c.Next()        // dnslex.Blank
	l, _ = c.Next() // dnslex.String
	rd.Port, err = dnsstring.AtoiUint16(l.Token)
	if err != nil {
		return &ParseError{err: "bad DSYNC Port"}
	}

	c.Next()        // dnslex.Blank
	l, _ = c.Next() // dnslex.String
	rd.Target = dnsutilAbsolute(l.Token, o)
	if l.Value == dnslex.Error || rd.Target == "" {
		return &ParseError{err: "bad DSYNC Target", lex: l}
	}
	return toParseError(dnslex.Discard(c))
}

// upperLookup will defer strings.ToUpper in the map lookup, until after the lookup has occurred and nothing
// was found.
func upperLookup(s string, m map[string]uint8) (uint8, bool) {
	// Duplicated in dnsex/lex.go
	if t, ok := m[s]; ok {
		return t, true
	}
	t, ok := m[strings.ToUpper(s)]
	return t, ok
}
