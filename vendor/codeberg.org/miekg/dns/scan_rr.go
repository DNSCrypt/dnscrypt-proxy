package dns

import (
	"codeberg.org/miekg/dns/internal/ddd"
	"codeberg.org/miekg/dns/internal/dnslex"
)

func (rr *A) parse(c *dnslex.Lexer, o string) error    { return parseA(&rr.A, c, o) }
func (rr *AAAA) parse(c *dnslex.Lexer, o string) error { return parseAAAA(&rr.AAAA, c, o) }
func (rr *NS) parse(c *dnslex.Lexer, o string) error   { return parseNS(&rr.NS, c, o) }
func (rr *PTR) parse(c *dnslex.Lexer, o string) error  { return parsePTR(&rr.PTR, c, o) }
func (rr *NSAPPTR) parse(c *dnslex.Lexer, o string) error {
	return parseNSAPPTR(&rr.NSAPPTR, c, o)
}
func (rr *RP) parse(c *dnslex.Lexer, o string) error     { return parseRP(&rr.RP, c, o) }
func (rr *MR) parse(c *dnslex.Lexer, o string) error     { return parseMR(&rr.MR, c, o) }
func (rr *MB) parse(c *dnslex.Lexer, o string) error     { return parseMB(&rr.MB, c, o) }
func (rr *MG) parse(c *dnslex.Lexer, o string) error     { return parseMG(&rr.MG, c, o) }
func (rr *HINFO) parse(c *dnslex.Lexer, o string) error  { return parseHINFO(&rr.HINFO, c, o) }
func (rr *ISDN) parse(c *dnslex.Lexer, o string) error   { return parseISDN(&rr.ISDN, c, o) }
func (rr *MINFO) parse(c *dnslex.Lexer, o string) error  { return parseMINFO(&rr.MINFO, c, o) }
func (rr *MF) parse(c *dnslex.Lexer, o string) error     { return parseMF(&rr.MF, c, o) }
func (rr *MD) parse(c *dnslex.Lexer, o string) error     { return parseMD(&rr.MD, c, o) }
func (rr *MX) parse(c *dnslex.Lexer, o string) error     { return parseMX(&rr.MX, c, o) }
func (rr *RT) parse(c *dnslex.Lexer, o string) error     { return parseRT(&rr.RT, c, o) }
func (rr *AFSDB) parse(c *dnslex.Lexer, o string) error  { return parseAFSDB(&rr.AFSDB, c, o) }
func (rr *X25) parse(c *dnslex.Lexer, o string) error    { return parseX25(&rr.X25, c, o) }
func (rr *KX) parse(c *dnslex.Lexer, o string) error     { return parseKX(&rr.KX, c, o) }
func (rr *CNAME) parse(c *dnslex.Lexer, o string) error  { return parseCNAME(&rr.CNAME, c, o) }
func (rr *DNAME) parse(c *dnslex.Lexer, o string) error  { return parseDNAME(&rr.DNAME, c, o) }
func (rr *SOA) parse(c *dnslex.Lexer, o string) error    { return parseSOA(&rr.SOA, c, o) }
func (rr *SRV) parse(c *dnslex.Lexer, o string) error    { return parseSRV(&rr.SRV, c, o) }
func (rr *NAPTR) parse(c *dnslex.Lexer, o string) error  { return parseNAPTR(&rr.NAPTR, c, o) }
func (rr *TALINK) parse(c *dnslex.Lexer, o string) error { return parseTALINK(&rr.TALINK, c, o) }
func (rr *LOC) parse(c *dnslex.Lexer, o string) error    { return parseLOC(&rr.LOC, c, o) }
func (rr *CERT) parse(c *dnslex.Lexer, o string) error   { return parseCERT(&rr.CERT, c, o) }
func (rr *OPENPGPKEY) parse(c *dnslex.Lexer, o string) error {
	return parseOPENPGPKEY(&rr.OPENPGPKEY, c, o)
}
func (rr *HIP) parse(c *dnslex.Lexer, o string) error    { return parseHIP(&rr.HIP, c, o) }
func (rr *CSYNC) parse(c *dnslex.Lexer, o string) error  { return parseCSYNC(&rr.CSYNC, c, o) }
func (rr *ZONEMD) parse(c *dnslex.Lexer, o string) error { return parseZONEMD(&rr.ZONEMD, c, o) }
func (rr *SIG) parse(c *dnslex.Lexer, o string) error    { return parseRRSIG(&rr.RRSIG.RRSIG, c, o) }
func (rr *RRSIG) parse(c *dnslex.Lexer, o string) error  { return parseRRSIG(&rr.RRSIG, c, o) }
func (rr *NXT) parse(c *dnslex.Lexer, o string) error    { return parseNSEC(&rr.NSEC.NSEC, c, o) }
func (rr *NSEC) parse(c *dnslex.Lexer, o string) error   { return parseNSEC(&rr.NSEC, c, o) }
func (rr *NSEC3) parse(c *dnslex.Lexer, o string) error  { return parseNSEC3(&rr.NSEC3, c, o) }
func (rr *NSEC3PARAM) parse(c *dnslex.Lexer, o string) error {
	return parseNSEC3PARAM(&rr.NSEC3PARAM, c, o)
}
func (rr *EUI48) parse(c *dnslex.Lexer, o string) error  { return parseEUI48(&rr.EUI48, c, o) }
func (rr *EUI64) parse(c *dnslex.Lexer, o string) error  { return parseEUI64(&rr.EUI64, c, o) }
func (rr *SSHFP) parse(c *dnslex.Lexer, o string) error  { return parseSSHFP(&rr.SSHFP, c, o) }
func (rr *DNSKEY) parse(c *dnslex.Lexer, o string) error { return parseDNSKEY(&rr.DNSKEY, c, o) }
func (rr *KEY) parse(c *dnslex.Lexer, o string) error {
	return parseDNSKEY(&rr.DNSKEY.DNSKEY, c, o)
}
func (rr *CDNSKEY) parse(c *dnslex.Lexer, o string) error {
	return parseDNSKEY(&rr.DNSKEY.DNSKEY, c, o)
}
func (rr *DS) parse(c *dnslex.Lexer, o string) error     { return parseDS(&rr.DS, c, o) }
func (rr *DLV) parse(c *dnslex.Lexer, o string) error    { return parseDS(&rr.DS.DS, c, o) }
func (rr *CDS) parse(c *dnslex.Lexer, o string) error    { return parseDS(&rr.DS.DS, c, o) }
func (rr *RKEY) parse(c *dnslex.Lexer, o string) error   { return parseRKEY(&rr.RKEY, c, o) }
func (rr *EID) parse(c *dnslex.Lexer, o string) error    { return parseEID(&rr.EID, c, o) }
func (rr *NIMLOC) parse(c *dnslex.Lexer, o string) error { return parseNIMLOC(&rr.NIMLOC, c, o) }
func (rr *GPOS) parse(c *dnslex.Lexer, o string) error   { return parseGPOS(&rr.GPOS, c, o) }
func (rr *TA) parse(c *dnslex.Lexer, o string) error     { return parseTA(&rr.TA, c, o) }
func (rr *TLSA) parse(c *dnslex.Lexer, o string) error   { return parseTLSA(&rr.TLSA, c, o) }
func (rr *SMIMEA) parse(c *dnslex.Lexer, o string) error { return parseSMIMEA(&rr.SMIMEA, c, o) }
func (rr *RFC3597) parse(c *dnslex.Lexer, o string) error {
	return parseRFC3597(&rr.RFC3597, c, o)
}
func (rr *SPF) parse(c *dnslex.Lexer, o string) error     { return parseTXT(&rr.TXT.TXT, c, o) }
func (rr *AVC) parse(c *dnslex.Lexer, o string) error     { return parseTXT(&rr.TXT.TXT, c, o) }
func (rr *TXT) parse(c *dnslex.Lexer, o string) error     { return parseTXT(&rr.TXT, c, o) }
func (rr *NINFO) parse(c *dnslex.Lexer, o string) error   { return parseNINFO(&rr.NINFO, c, o) }
func (rr *RESINFO) parse(c *dnslex.Lexer, o string) error { return parseTXT(&rr.TXT.TXT, c, o) }
func (rr *WALLET) parse(c *dnslex.Lexer, o string) error  { return parseTXT(&rr.TXT.TXT, c, o) }
func (rr *CLA) parse(c *dnslex.Lexer, o string) error     { return parseTXT(&rr.TXT.TXT, c, o) }
func (rr *IPN) parse(c *dnslex.Lexer, o string) error     { return parseIPN(&rr.IPN, c, o) }
func (rr *URI) parse(c *dnslex.Lexer, o string) error     { return parseURI(&rr.URI, c, o) }
func (rr *DHCID) parse(c *dnslex.Lexer, o string) error   { return parseDHCID(&rr.DHCID, c, o) }
func (rr *NID) parse(c *dnslex.Lexer, o string) error     { return parseNID(&rr.NID, c, o) }
func (rr *L32) parse(c *dnslex.Lexer, o string) error     { return parseL32(&rr.L32, c, o) }
func (rr *LP) parse(c *dnslex.Lexer, o string) error      { return parseLP(&rr.LP, c, o) }
func (rr *L64) parse(c *dnslex.Lexer, o string) error     { return parseL64(&rr.L64, c, o) }
func (rr *UID) parse(c *dnslex.Lexer, o string) error     { return parseUID(&rr.UID, c, o) }
func (rr *GID) parse(c *dnslex.Lexer, o string) error     { return parseGID(&rr.GID, c, o) }
func (rr *UINFO) parse(c *dnslex.Lexer, o string) error   { return parseUINFO(&rr.UINFO, c, o) }
func (rr *PX) parse(c *dnslex.Lexer, o string) error      { return parsePX(&rr.PX, c, o) }
func (rr *CAA) parse(c *dnslex.Lexer, o string) error     { return parseCAA(&rr.CAA, c, o) }
func (rr *TKEY) parse(c *dnslex.Lexer, o string) error    { return parseTKEY(&rr.TKEY, c, o) }
func (rr *SVCB) parse(c *dnslex.Lexer, o string) error    { return parseSVCB(&rr.SVCB, c, o) }
func (rr *HTTPS) parse(c *dnslex.Lexer, o string) error {
	return parseSVCB(&rr.SVCB.SVCB, c, o)
}
func (rr *DELEG) parse(c *dnslex.Lexer, o string) error { return parseDELEG(&rr.DELEG, c, o) }
func (rr *DELEGPARAM) parse(c *dnslex.Lexer, o string) error {
	return parseDELEG(&rr.DELEG.DELEG, c, o)
}
func (rr *DSYNC) parse(c *dnslex.Lexer, o string) error { return parseDSYNC(&rr.DSYNC, c, o) }

// escapedStringOffset finds the offset within a string (which may contain escape
// sequences) that corresponds to a certain byte offset. If the input offset is
// out of bounds, -1 is returned (which is *not* considered an error).
func escapedStringOffset(s string, desiredByteOffset int) (int, bool) {
	if desiredByteOffset == 0 {
		return 0, true
	}

	currentByteOffset, i := 0, 0

	for i < len(s) {
		currentByteOffset += 1

		// Skip escape sequences
		if s[i] != '\\' {
			// Single plain byte, not an escape sequence.
			i++
		} else if ddd.Is(s[i+1:]) {
			// Skip backslash and DDD.
			i += 4
		} else if len(s[i+1:]) < 1 {
			// No character following the backslash; that's an error.
			return 0, false
		} else {
			// Skip backslash and following byte.
			i += 2
		}

		if currentByteOffset >= desiredByteOffset {
			return i, true
		}
	}

	return -1, true
}

// remainder returns a remainder of the rdata with embedded spaces, return the parsed string (sans the spaces)
// or an error
func remainder(c *dnslex.Lexer, errstr string) (string, error) {
	s := "" // usually one or two strings, just contact without strings.Builder
	for {
		l, _ := c.Next()
		switch l.Value {
		case dnslex.Newline:
			return s, nil
		case dnslex.EOF:
			return s, nil
		case dnslex.String:
			s += l.Token
		case dnslex.Blank:
		default:
			return "", &ParseError{err: errstr, lex: l}
		}
	}
}

// remainderSlice returns a remainder of the rdata with embedded spaces, split on unquoted whitespace
// and return the parsed string slice or an error
func remainderSlice(c *dnslex.Lexer, errstr string) ([]string, error) {
	l, _ := c.Next()
	if l.Value == dnslex.Error {
		return nil, &ParseError{err: errstr, lex: l}
	}

	// build the slice
	s := make([]string, 0, 2)
	quote := false
	empty := false
	for l.Value != dnslex.Newline && l.Value != dnslex.EOF {
		if l.Value == dnslex.Error {
			return nil, &ParseError{err: errstr, lex: l}
		}
		switch l.Value {
		case dnslex.String:
			empty = false
			// split up tokens that are larger than 255 into 255-chunks
			p := 0
			for {
				i, ok := escapedStringOffset(l.Token[p:], 255)
				if !ok {
					return nil, &ParseError{err: errstr, lex: l}
				}
				if i != -1 && p+i != len(l.Token) {
					s = append(s, l.Token[p:p+i])
					p += i
				} else {
					s = append(s, l.Token[p:])
					break
				}
			}
		case dnslex.Blank:
			if quote {
				// dnslex.Blank can only be seen in between txt parts.
				return nil, &ParseError{err: errstr, lex: l}
			}
		case dnslex.Quote:
			if empty && quote {
				s = append(s, "")
			}
			quote = !quote
			empty = true
		default:
			return nil, &ParseError{err: errstr, lex: l}
		}
		l, _ = c.Next()
	}

	if quote {
		return nil, &ParseError{err: errstr, lex: l}
	}

	return s, nil
}
