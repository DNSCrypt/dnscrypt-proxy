package dns

import (
	"codeberg.org/miekg/dns/internal/ddd"
	"codeberg.org/miekg/dns/internal/dnslex"
)

func (rr *A) parse(c *dnslex.Lexer, o string) *ParseError    { return parseA(&rr.A, c, o) }
func (rr *AAAA) parse(c *dnslex.Lexer, o string) *ParseError { return parseAAAA(&rr.AAAA, c, o) }
func (rr *NS) parse(c *dnslex.Lexer, o string) *ParseError   { return parseNS(&rr.NS, c, o) }
func (rr *PTR) parse(c *dnslex.Lexer, o string) *ParseError  { return parsePTR(&rr.PTR, c, o) }
func (rr *NSAPPTR) parse(c *dnslex.Lexer, o string) *ParseError {
	return parseNSAPPTR(&rr.NSAPPTR, c, o)
}
func (rr *RP) parse(c *dnslex.Lexer, o string) *ParseError     { return parseRP(&rr.RP, c, o) }
func (rr *MR) parse(c *dnslex.Lexer, o string) *ParseError     { return parseMR(&rr.MR, c, o) }
func (rr *MB) parse(c *dnslex.Lexer, o string) *ParseError     { return parseMB(&rr.MB, c, o) }
func (rr *MG) parse(c *dnslex.Lexer, o string) *ParseError     { return parseMG(&rr.MG, c, o) }
func (rr *HINFO) parse(c *dnslex.Lexer, o string) *ParseError  { return parseHINFO(&rr.HINFO, c, o) }
func (rr *ISDN) parse(c *dnslex.Lexer, o string) *ParseError   { return parseISDN(&rr.ISDN, c, o) }
func (rr *MINFO) parse(c *dnslex.Lexer, o string) *ParseError  { return parseMINFO(&rr.MINFO, c, o) }
func (rr *MF) parse(c *dnslex.Lexer, o string) *ParseError     { return parseMF(&rr.MF, c, o) }
func (rr *MD) parse(c *dnslex.Lexer, o string) *ParseError     { return parseMD(&rr.MD, c, o) }
func (rr *MX) parse(c *dnslex.Lexer, o string) *ParseError     { return parseMX(&rr.MX, c, o) }
func (rr *RT) parse(c *dnslex.Lexer, o string) *ParseError     { return parseRT(&rr.RT, c, o) }
func (rr *AFSDB) parse(c *dnslex.Lexer, o string) *ParseError  { return parseAFSDB(&rr.AFSDB, c, o) }
func (rr *X25) parse(c *dnslex.Lexer, o string) *ParseError    { return parseX25(&rr.X25, c, o) }
func (rr *KX) parse(c *dnslex.Lexer, o string) *ParseError     { return parseKX(&rr.KX, c, o) }
func (rr *CNAME) parse(c *dnslex.Lexer, o string) *ParseError  { return parseCNAME(&rr.CNAME, c, o) }
func (rr *DNAME) parse(c *dnslex.Lexer, o string) *ParseError  { return parseDNAME(&rr.DNAME, c, o) }
func (rr *SOA) parse(c *dnslex.Lexer, o string) *ParseError    { return parseSOA(&rr.SOA, c, o) }
func (rr *SRV) parse(c *dnslex.Lexer, o string) *ParseError    { return parseSRV(&rr.SRV, c, o) }
func (rr *NAPTR) parse(c *dnslex.Lexer, o string) *ParseError  { return parseNAPTR(&rr.NAPTR, c, o) }
func (rr *TALINK) parse(c *dnslex.Lexer, o string) *ParseError { return parseTALINK(&rr.TALINK, c, o) }
func (rr *LOC) parse(c *dnslex.Lexer, o string) *ParseError    { return parseLOC(&rr.LOC, c, o) }
func (rr *CERT) parse(c *dnslex.Lexer, o string) *ParseError   { return parseCERT(&rr.CERT, c, o) }
func (rr *OPENPGPKEY) parse(c *dnslex.Lexer, o string) *ParseError {
	return parseOPENPGPKEY(&rr.OPENPGPKEY, c, o)
}
func (rr *HIP) parse(c *dnslex.Lexer, o string) *ParseError    { return parseHIP(&rr.HIP, c, o) }
func (rr *CSYNC) parse(c *dnslex.Lexer, o string) *ParseError  { return parseCSYNC(&rr.CSYNC, c, o) }
func (rr *ZONEMD) parse(c *dnslex.Lexer, o string) *ParseError { return parseZONEMD(&rr.ZONEMD, c, o) }
func (rr *SIG) parse(c *dnslex.Lexer, o string) *ParseError    { return parseRRSIG(&rr.RRSIG.RRSIG, c, o) }
func (rr *RRSIG) parse(c *dnslex.Lexer, o string) *ParseError  { return parseRRSIG(&rr.RRSIG, c, o) }
func (rr *NXT) parse(c *dnslex.Lexer, o string) *ParseError    { return parseNSEC(&rr.NSEC.NSEC, c, o) }
func (rr *NSEC) parse(c *dnslex.Lexer, o string) *ParseError   { return parseNSEC(&rr.NSEC, c, o) }
func (rr *NSEC3) parse(c *dnslex.Lexer, o string) *ParseError  { return parseNSEC3(&rr.NSEC3, c, o) }
func (rr *NSEC3PARAM) parse(c *dnslex.Lexer, o string) *ParseError {
	return parseNSEC3PARAM(&rr.NSEC3PARAM, c, o)
}
func (rr *EUI48) parse(c *dnslex.Lexer, o string) *ParseError  { return parseEUI48(&rr.EUI48, c, o) }
func (rr *EUI64) parse(c *dnslex.Lexer, o string) *ParseError  { return parseEUI64(&rr.EUI64, c, o) }
func (rr *SSHFP) parse(c *dnslex.Lexer, o string) *ParseError  { return parseSSHFP(&rr.SSHFP, c, o) }
func (rr *DNSKEY) parse(c *dnslex.Lexer, o string) *ParseError { return parseDNSKEY(&rr.DNSKEY, c, o) }
func (rr *KEY) parse(c *dnslex.Lexer, o string) *ParseError {
	return parseDNSKEY(&rr.DNSKEY.DNSKEY, c, o)
}
func (rr *CDNSKEY) parse(c *dnslex.Lexer, o string) *ParseError {
	return parseDNSKEY(&rr.DNSKEY.DNSKEY, c, o)
}
func (rr *DS) parse(c *dnslex.Lexer, o string) *ParseError     { return parseDS(&rr.DS, c, o) }
func (rr *DLV) parse(c *dnslex.Lexer, o string) *ParseError    { return parseDS(&rr.DS.DS, c, o) }
func (rr *CDS) parse(c *dnslex.Lexer, o string) *ParseError    { return parseDS(&rr.DS.DS, c, o) }
func (rr *RKEY) parse(c *dnslex.Lexer, o string) *ParseError   { return parseRKEY(&rr.RKEY, c, o) }
func (rr *EID) parse(c *dnslex.Lexer, o string) *ParseError    { return parseEID(&rr.EID, c, o) }
func (rr *NIMLOC) parse(c *dnslex.Lexer, o string) *ParseError { return parseNIMLOC(&rr.NIMLOC, c, o) }
func (rr *GPOS) parse(c *dnslex.Lexer, o string) *ParseError   { return parseGPOS(&rr.GPOS, c, o) }
func (rr *TA) parse(c *dnslex.Lexer, o string) *ParseError     { return parseTA(&rr.TA, c, o) }
func (rr *TLSA) parse(c *dnslex.Lexer, o string) *ParseError   { return parseTLSA(&rr.TLSA, c, o) }
func (rr *SMIMEA) parse(c *dnslex.Lexer, o string) *ParseError { return parseSMIMEA(&rr.SMIMEA, c, o) }
func (rr *RFC3597) parse(c *dnslex.Lexer, o string) *ParseError {
	return parseRFC3597(&rr.RFC3597, c, o)
}
func (rr *SPF) parse(c *dnslex.Lexer, o string) *ParseError     { return parseTXT(&rr.TXT.TXT, c, o) }
func (rr *AVC) parse(c *dnslex.Lexer, o string) *ParseError     { return parseTXT(&rr.TXT.TXT, c, o) }
func (rr *TXT) parse(c *dnslex.Lexer, o string) *ParseError     { return parseTXT(&rr.TXT, c, o) }
func (rr *NINFO) parse(c *dnslex.Lexer, o string) *ParseError   { return parseNINFO(&rr.NINFO, c, o) }
func (rr *RESINFO) parse(c *dnslex.Lexer, o string) *ParseError { return parseTXT(&rr.TXT.TXT, c, o) }
func (rr *WALLET) parse(c *dnslex.Lexer, o string) *ParseError  { return parseTXT(&rr.TXT.TXT, c, o) }
func (rr *CLA) parse(c *dnslex.Lexer, o string) *ParseError     { return parseTXT(&rr.TXT.TXT, c, o) }
func (rr *IPN) parse(c *dnslex.Lexer, o string) *ParseError     { return parseIPN(&rr.IPN, c, o) }
func (rr *URI) parse(c *dnslex.Lexer, o string) *ParseError     { return parseURI(&rr.URI, c, o) }
func (rr *DHCID) parse(c *dnslex.Lexer, o string) *ParseError   { return parseDHCID(&rr.DHCID, c, o) }
func (rr *NID) parse(c *dnslex.Lexer, o string) *ParseError     { return parseNID(&rr.NID, c, o) }
func (rr *L32) parse(c *dnslex.Lexer, o string) *ParseError     { return parseL32(&rr.L32, c, o) }
func (rr *LP) parse(c *dnslex.Lexer, o string) *ParseError      { return parseLP(&rr.LP, c, o) }
func (rr *L64) parse(c *dnslex.Lexer, o string) *ParseError     { return parseL64(&rr.L64, c, o) }
func (rr *UID) parse(c *dnslex.Lexer, o string) *ParseError     { return parseUID(&rr.UID, c, o) }
func (rr *GID) parse(c *dnslex.Lexer, o string) *ParseError     { return parseGID(&rr.GID, c, o) }
func (rr *UINFO) parse(c *dnslex.Lexer, o string) *ParseError   { return parseUINFO(&rr.UINFO, c, o) }
func (rr *PX) parse(c *dnslex.Lexer, o string) *ParseError      { return parsePX(&rr.PX, c, o) }
func (rr *CAA) parse(c *dnslex.Lexer, o string) *ParseError     { return parseCAA(&rr.CAA, c, o) }
func (rr *TKEY) parse(c *dnslex.Lexer, o string) *ParseError    { return parseTKEY(&rr.TKEY, c, o) }
func (rr *SVCB) parse(c *dnslex.Lexer, o string) *ParseError    { return parseSVCB(&rr.SVCB, c, o) }
func (rr *HTTPS) parse(c *dnslex.Lexer, o string) *ParseError {
	return parseSVCB(&rr.SVCB.SVCB, c, o)
}
func (rr *DELEG) parse(c *dnslex.Lexer, o string) *ParseError { return parseDELEG(&rr.DELEG, c, o) }
func (rr *DELEGI) parse(c *dnslex.Lexer, o string) *ParseError {
	return parseDELEG(&rr.DELEG.DELEG, c, o)
}
func (rr *DSYNC) parse(c *dnslex.Lexer, o string) *ParseError { return parseDSYNC(&rr.DSYNC, c, o) }

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

// A remainder of the rdata with embedded spaces, return the parsed string (sans the spaces)
// or an error
func endingToString(c *dnslex.Lexer, errstr string) (string, *ParseError) {
	sb := builderPool.Get()

	for {
		l, _ := c.Next()
		if l.Value == dnslex.Newline || l.Value == dnslex.EOF {
			s := sb.String()
			builderPool.Put(sb)
			return s, nil
		}
		if l.Err {
			builderPool.Put(sb)
			return "", &ParseError{err: errstr, lex: l}
		}

		switch l.Value {
		case dnslex.String:
			sb.WriteString(l.Token)
		case dnslex.Blank:
			continue
		default:
			builderPool.Put(sb)
			return "", &ParseError{err: errstr, lex: l}
		}
	}
}

// A remainder of the rdata with embedded spaces, split on unquoted whitespace
// and return the parsed string slice or an error
func endingToTxtSlice(c *dnslex.Lexer, errstr string) ([]string, *ParseError) {
	l, _ := c.Next()
	if l.Err {
		return nil, &ParseError{err: errstr, lex: l}
	}

	// Build the slice
	s := make([]string, 0)
	quote := false
	empty := false
	for l.Value != dnslex.Newline && l.Value != dnslex.EOF {
		if l.Err {
			return nil, &ParseError{err: errstr, lex: l}
		}
		switch l.Value {
		case dnslex.String:
			empty = false
			// split up tokens that are larger than 255 into 255-chunks
			sx := []string{}
			p := 0
			for {
				i, ok := escapedStringOffset(l.Token[p:], 255)
				if !ok {
					return nil, &ParseError{err: errstr, lex: l}
				}
				if i != -1 && p+i != len(l.Token) {
					sx = append(sx, l.Token[p:p+i])
				} else {
					sx = append(sx, l.Token[p:])
					break

				}
				p += i
			}
			s = append(s, sx...)
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
