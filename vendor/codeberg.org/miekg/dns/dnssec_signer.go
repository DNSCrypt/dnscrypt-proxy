package dns

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"math/big"
	"sort"

	"codeberg.org/miekg/dns/internal/pack"
)

// canonicalize will put the RR in Canonical form, see RFC 4034: 6.2.  Canonical RR Form. (2) - domain name to lowercase
// This changes the RR itself.
func canonicalize(rr RR) {
	// RFC 4034: 6.2.  Canonical RR Form. (2) - domain name to lowercase
	rr.Header().Name = dnsutilCanonical(rr.Header().Name)
	// 6.2. Canonical RR Form. (3) - domain rdata to lowercase.
	//   NS, MD, MF, CNAME, SOA, MB, MG, MR, PTR,
	//   HINFO, MINFO, MX, RP, AFSDB, RT, SIG, PX, NXT, NAPTR, KX,
	//   SRV, DNAME, A6
	//
	// RFC 6840 - Clarifications and Implementation Notes for DNS Security (DNSSEC):
	//	Section 6.2 of [RFC4034] also erroneously lists HINFO as a record
	//	that needs conversion to lowercase, and twice at that.  Since HINFO
	//	records contain no domain names, they are not subject to case
	//	conversion.
	switch x := rr.(type) {
	case *NS:
		x.Ns = dnsutilCanonical(x.Ns)
	case *MD:
		x.Md = dnsutilCanonical(x.Md)
	case *MF:
		x.Mf = dnsutilCanonical(x.Mf)
	case *CNAME:
		x.Target = dnsutilCanonical(x.Target)
	case *SOA:
		x.Ns = dnsutilCanonical(x.Ns)
		x.Mbox = dnsutilCanonical(x.Mbox)
	case *MB:
		x.Mb = dnsutilCanonical(x.Mb)
	case *MG:
		x.Mg = dnsutilCanonical(x.Mg)
	case *MR:
		x.Mr = dnsutilCanonical(x.Mr)
	case *PTR:
		x.Ptr = dnsutilCanonical(x.Ptr)
	case *MINFO:
		x.Rmail = dnsutilCanonical(x.Rmail)
		x.Email = dnsutilCanonical(x.Email)
	case *MX:
		x.Mx = dnsutilCanonical(x.Mx)
	case *RP:
		x.Mbox = dnsutilCanonical(x.Mbox)
		x.Txt = dnsutilCanonical(x.Txt)
	case *AFSDB:
		x.Hostname = dnsutilCanonical(x.Hostname)
	case *RT:
		x.Host = dnsutilCanonical(x.Host)
	case *PX:
		x.Map822 = dnsutilCanonical(x.Map822)
		x.Mapx400 = dnsutilCanonical(x.Mapx400)
	case *NAPTR:
		x.Replacement = dnsutilCanonical(x.Replacement)
	case *KX:
		x.Exchanger = dnsutilCanonical(x.Exchanger)
	case *SRV:
		x.Target = dnsutilCanonical(x.Target)
	case *DNAME:
		x.Target = dnsutilCanonical(x.Target)
	}
}

// The RRSIG needs to be converted to wireformat with some of the rdata (the signature) missing.
type rrsigWireFmt struct {
	TypeCovered uint16
	Algorithm   uint8
	Labels      uint8
	OrigTTL     uint32
	Expiration  uint32
	Inception   uint32
	KeyTag      uint16
	SignerName  string `dns:"domain-name"`
	/* No Signature */
}

// Used for converting DNSKEY's rdata to wirefmt.
type dnskeyWireFmt struct {
	Flags     uint16
	Protocol  uint8
	Algorithm uint8
	PublicKey string `dns:"base64"`
	/* Nothing is left out */
}

func (sw *rrsigWireFmt) pack(buf []byte) (int, error) {
	// copied from zmsg.go RRSIG packing
	off, err := pack.Uint16(sw.TypeCovered, buf, 0)
	if err != nil {
		return off, err
	}
	off, err = pack.Uint8(sw.Algorithm, buf, off)
	if err != nil {
		return off, err
	}
	off, err = pack.Uint8(sw.Labels, buf, off)
	if err != nil {
		return off, err
	}
	off, err = pack.Uint32(sw.OrigTTL, buf, off)
	if err != nil {
		return off, err
	}
	off, err = pack.Uint32(sw.Expiration, buf, off)
	if err != nil {
		return off, err
	}
	off, err = pack.Uint32(sw.Inception, buf, off)
	if err != nil {
		return off, err
	}
	off, err = pack.Uint16(sw.KeyTag, buf, off)
	if err != nil {
		return off, err
	}
	return pack.Name(sw.SignerName, buf, off, nil, false)
}

func (dw *dnskeyWireFmt) pack(buf []byte) (int, error) {
	// copied from zmsg.go DNSKEY packing
	off, err := pack.Uint16(dw.Flags, buf, 0)
	if err != nil {
		return off, err
	}
	off, err = pack.Uint8(dw.Protocol, buf, off)
	if err != nil {
		return off, err
	}
	off, err = pack.Uint8(dw.Algorithm, buf, off)
	if err != nil {
		return off, err
	}
	return pack.StringBase64(dw.PublicKey, buf, off)
}

// Helper function for packing and unpacking
func intToBytes(i *big.Int, length int) []byte {
	buf := i.Bytes()
	if len(buf) < length {
		b := make([]byte, length)
		copy(b[length-len(buf):], buf)
		return b
	}
	return buf
}

// publicKeyRSA returns the RSA public key from a DNSKEY record.
func (k *DNSKEY) publicKeyRSA() *rsa.PublicKey {
	keybuf, err := pack.Base64([]byte(k.PublicKey))
	if err != nil {
		return nil
	}

	if len(keybuf) < 1+1+64 {
		// Exponent must be at least 1 byte and modulus at least 64
		return nil
	}

	// RFC 2537/3110, section 2. RSA Public KEY Resource Records
	// Length is in the 0th byte, unless its zero, then it
	// it in bytes 1 and 2 and its a 16 bit number
	explen := uint16(keybuf[0])
	keyoff := 1
	if explen == 0 {
		explen = uint16(keybuf[1])<<8 | uint16(keybuf[2])
		keyoff = 3
	}

	if explen > 4 || explen == 0 || keybuf[keyoff] == 0 {
		// Exponent larger than supported by the crypto package,
		// empty, or contains prohibited leading zero.
		return nil
	}

	modoff := keyoff + int(explen)
	modlen := len(keybuf) - modoff
	if modlen < 64 || modlen > 512 || keybuf[modoff] == 0 {
		// Modulus is too small, large, or contains prohibited leading zero.
		return nil
	}

	pubkey := new(rsa.PublicKey)

	var expo uint64
	// The exponent of length explen is between keyoff and modoff.
	for _, v := range keybuf[keyoff:modoff] {
		expo <<= 8
		expo |= uint64(v)
	}
	if expo > 1<<31-1 {
		// Larger exponent than supported by the crypto package.
		return nil
	}

	pubkey.E = int(expo)
	pubkey.N = new(big.Int).SetBytes(keybuf[modoff:])
	return pubkey
}

// publicKeyECDSA returns the Curve public key from the DNSKEY record.
func (k *DNSKEY) publicKeyECDSA() *ecdsa.PublicKey {
	keybuf, err := pack.Base64([]byte(k.PublicKey))
	if err != nil {
		return nil
	}
	pubkey := new(ecdsa.PublicKey)
	switch k.Algorithm {
	case ECDSAP256SHA256:
		pubkey.Curve = elliptic.P256()
		if len(keybuf) != 64 {
			// wrongly encoded key
			return nil
		}
	case ECDSAP384SHA384:
		pubkey.Curve = elliptic.P384()
		if len(keybuf) != 96 {
			// Wrongly encoded key
			return nil
		}
	}
	pubkey.X = new(big.Int).SetBytes(keybuf[:len(keybuf)/2])
	pubkey.Y = new(big.Int).SetBytes(keybuf[len(keybuf)/2:])
	return pubkey
}

func (k *DNSKEY) publicKeyED25519() ed25519.PublicKey {
	keybuf, err := pack.Base64([]byte(k.PublicKey))
	if err != nil {
		return nil
	}
	if len(keybuf) != ed25519.PublicKeySize {
		return nil
	}
	return keybuf
}

// Return the raw signature data.
func rawSignatureData(buf []byte, rrset []RR, s *RRSIG, options SignOption) int {
	off := 0
	for _, rr := range rrset {
		rr.Header().TTL = s.OrigTTL
		labels := dnsutilLabels(rr.Header().Name)
		if skip := labels - int(s.Labels); skip > 0 {
			orig := rr.Header().Name
			// 6.2. Canonical RR Form. (4) - wildcards
			// Wildcard, trim to s.Labels from the left and substitute '*'
			for range skip {
				off, _ = dnsutilNext(rr.Header().Name, off)
			}
			rr.Header().Name = "*." + rr.Header().Name[off:]
			defer func() { rr.Header().Name = orig }()

		}
		canonicalize(rr)
	}

	sort.Sort(RRset(rrset))

	off = 0
	for _, rr := range rrset {
		_, off, _ = packRR(rr, buf, off, nil)
	}
	return off
}
