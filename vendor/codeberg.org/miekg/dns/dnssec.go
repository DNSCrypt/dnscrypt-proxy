package dns

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	_ "crypto/sha1"   // need its init function
	_ "crypto/sha256" // need its init function
	_ "crypto/sha512" // need its init function
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"hash"
	"math/big"
	"strings"
	"time"

	"codeberg.org/miekg/dns/internal/pack"
	"codeberg.org/miekg/dns/internal/unpack"
	"codeberg.org/miekg/dns/pkg/pool"
)

// DNSSEC encryption algorithm codes.
const (
	_ uint8 = iota
	RSAMD5
	DH
	DSA
	_ // Skip 4, RFC 6725, section 2.1
	RSASHA1
	DSANSEC3SHA1
	RSASHA1NSEC3SHA1
	RSASHA256
	_ // Skip 9, RFC 6725, section 2.1
	RSASHA512
	_ // Skip 11, RFC 6725, section 2.1
	ECCGOST
	ECDSAP256SHA256
	ECDSAP384SHA384
	ED25519
	ED448
	INDIRECT   uint8 = 252
	PRIVATEDNS uint8 = 253 // Private (experimental keys)
	PRIVATEOID uint8 = 254
)

// AlgorithmToString is a map of algorithm IDs to algorithm names.
var AlgorithmToString = map[uint8]string{
	RSAMD5:           "RSAMD5",
	DH:               "DH",
	DSA:              "DSA",
	RSASHA1:          "RSASHA1",
	DSANSEC3SHA1:     "DSA-NSEC3-SHA1",
	RSASHA1NSEC3SHA1: "RSASHA1-NSEC3-SHA1",
	RSASHA256:        "RSASHA256",
	RSASHA512:        "RSASHA512",
	ECCGOST:          "ECC-GOST",
	ECDSAP256SHA256:  "ECDSAP256SHA256",
	ECDSAP384SHA384:  "ECDSAP384SHA384",
	ED25519:          "ED25519",
	ED448:            "ED448",
	INDIRECT:         "INDIRECT",
	PRIVATEDNS:       "PRIVATEDNS",
	PRIVATEOID:       "PRIVATEOID",
}

// AlgorithmToHash is a map of algorithm crypto hash IDs to crypto.Hash's.
// Newer algorithm that do their own hashing (i.e. ED25519) are not present here.
var AlgorithmToHash = map[uint8]crypto.Hash{
	RSAMD5:           crypto.MD5, // Deprecated in RFC 6725
	DSA:              crypto.SHA1,
	RSASHA1:          crypto.SHA1,
	RSASHA1NSEC3SHA1: crypto.SHA1,
	RSASHA256:        crypto.SHA256,
	ECDSAP256SHA256:  crypto.SHA256,
	ECDSAP384SHA384:  crypto.SHA384,
	RSASHA512:        crypto.SHA512,
}

// DNSSEC hashing algorithm codes.
const (
	_      uint8 = iota
	SHA1         // RFC 4034
	SHA256       // RFC 4509
	GOST94       // RFC 5933
	SHA384       // Experimental
	SHA512       // Experimental
)

// HashToString is a map of hash IDs to names.
var HashToString = map[uint8]string{
	SHA1:   "SHA1",
	SHA256: "SHA256",
	GOST94: "GOST94",
	SHA384: "SHA384",
	SHA512: "SHA512",
}

// DNSKEY flag values.
const (
	FlagSEP    = 1
	FlagREVOKE = 1 << 7
	FlagZONE   = 1 << 8
	FlagDELEG  = 1 << 14
)

// KeyTag calculates the keytag (or key-id) of the DNSKEY.
func (k *DNSKEY) KeyTag() uint16 {
	if k == nil {
		return 0
	}
	var keytag int
	switch k.Algorithm {
	case RSAMD5:
		// This algorithm has been deprecated, but keep this key-tag calculation.
		// Look at the bottom two bytes of the modules, which the last item in the pubkey.
		// See https://www.rfc-editor.org/errata/eid193 .
		modulus, _ := pack.Base64([]byte(k.PublicKey))
		if len(modulus) > 1 {
			x := binary.BigEndian.Uint16(modulus[len(modulus)-3:])
			keytag = int(x)
		}
	default:
		keywire := new(dnskeyWireFmt)
		keywire.Flags = k.Flags
		keywire.Protocol = k.Protocol
		keywire.Algorithm = k.Algorithm
		keywire.PublicKey = k.PublicKey
		wire := make([]byte, DefaultMsgSize)
		n, err := keywire.pack(wire)
		if err != nil {
			return 0
		}
		wire = wire[:n]
		for i, v := range wire {
			if i&1 != 0 {
				keytag += int(v) // must be larger than uint32
			} else {
				keytag += int(v) << 8
			}
		}
		keytag += keytag >> 16 & 0xFFFF
		keytag &= 0xFFFF
	}
	return uint16(keytag)
}

// ToDS converts a DNSKEY record to a DS record.
func (k *DNSKEY) ToDS(h uint8) *DS {
	if k == nil {
		return nil
	}
	ds := new(DS)
	ds.Hdr.Name = k.Hdr.Name
	ds.Hdr.Class = k.Hdr.Class
	ds.Hdr.TTL = k.Hdr.TTL
	ds.Algorithm = k.Algorithm
	ds.DigestType = h
	ds.KeyTag = k.KeyTag()

	keywire := new(dnskeyWireFmt)
	keywire.Flags = k.Flags
	keywire.Protocol = k.Protocol
	keywire.Algorithm = k.Algorithm
	keywire.PublicKey = k.PublicKey
	wire := make([]byte, DefaultMsgSize)
	n, err := keywire.pack(wire)
	if err != nil {
		return nil
	}
	wire = wire[:n]

	owner := make([]byte, len(k.Hdr.Name)+1)
	off, err1 := pack.Name(dnsutilCanonical(k.Hdr.Name), owner, 0, nil, false)
	if err1 != nil {
		return nil
	}
	owner = owner[:off]
	// RFC4034:
	// digest = digest_algorithm( DNSKEY owner name | DNSKEY RDATA);
	// "|" denotes concatenation
	// DNSKEY RDATA = Flags | Protocol | Algorithm | Public Key.

	var hash crypto.Hash
	switch h {
	case SHA1:
		hash = crypto.SHA1
	case SHA256:
		hash = crypto.SHA256
	case SHA384:
		hash = crypto.SHA384
	case SHA512:
		hash = crypto.SHA512
	default:
		return nil
	}

	s := hash.New()
	s.Write(owner)
	s.Write(wire)
	ds.Digest = hex.EncodeToString(s.Sum(nil))
	return ds
}

// ToCDNSKEY converts a DNSKEY record to a CDNSKEY record.
func (k *DNSKEY) ToCDNSKEY() *CDNSKEY {
	c := &CDNSKEY{DNSKEY: *k}
	c.Hdr = k.Hdr
	return c
}

// ToCDS converts a DS record to a CDS record.
func (d *DS) ToCDS() *CDS {
	c := &CDS{DS: *d}
	c.Hdr = d.Hdr
	return c
}

// Sign signs an RRset. The signature needs to be filled in with the values:
// Inception, Expiration, KeyTag, SignerName and Algorithm. See [NewRRSIG], the rest is copied
// from the RRset. Sign returns a non-nill error when the signing went OK.
// There is no check if RRSet is a proper (RFC 2181) RRSet.
// Sign expect RRSIG to be initialized with [NewRRSIG]. Sign will skip RRSIG records, and return nil in that case.
func (rr *RRSIG) Sign(k crypto.Signer, rrset []RR, options *SignOption) error {
	// s.Inception and s.Expiration may be 0 (rollover etc.), the rest must be set
	if rr.KeyTag == 0 || len(rr.SignerName) == 0 || rr.Algorithm == 0 {
		return ErrKey
	}
	if options.Pooler == nil {
		options.Pooler = pool.NewNoop(DefaultMsgSize)
	}

	h0 := rrset[0].Header()
	t0 := RRToType(rrset[0])
	if t0 == TypeRRSIG {
		return nil
	}
	rr.Hdr.Name = h0.Name
	rr.Hdr.TTL = h0.TTL
	rr.Hdr.Class = h0.Class
	rr.OrigTTL = h0.TTL
	rr.TypeCovered = t0
	rr.Labels = uint8(dnsutilLabels(h0.Name))
	if strings.HasPrefix(h0.Name, "*.") {
		rr.Labels-- // wildcard, remove from label count
	}

	sigwire := new(rrsigWireFmt)
	sigwire.TypeCovered = rr.TypeCovered
	sigwire.Algorithm = rr.Algorithm
	sigwire.Labels = rr.Labels
	sigwire.OrigTTL = rr.OrigTTL
	sigwire.Expiration = rr.Expiration
	sigwire.Inception = rr.Inception
	sigwire.KeyTag = rr.KeyTag
	sigwire.SignerName = rr.SignerName

	// Create the desired binary blob
	signdata := options.Get()
	defer options.Put(signdata)

	n, _ := sigwire.pack(signdata)
	m := rawSignatureData(signdata[n:], rrset, rr, *options)
	signdata = signdata[:m+n]

	var h hash.Hash
	hash, ok := AlgorithmToHash[rr.Algorithm]
	if !ok && rr.Algorithm != ED25519 {
		return ErrAlg
	}

	switch rr.Algorithm {
	case RSAMD5, DSA, DSANSEC3SHA1:
		// See RFC 6944.
		return ErrAlg

	case ED25519:
		signature, err := sign(k, signdata, hash, rr.Algorithm)
		if err != nil {
			return err
		}

		rr.Signature = unpack.Base64(signature)
		return nil

	default:
		h = hash.New()
		h.Write(signdata)

		signature, err := sign(k, h.Sum(nil), hash, rr.Algorithm)
		if err != nil {
			return err
		}

		rr.Signature = unpack.Base64(signature)
		return nil
	}
}

func sign(k crypto.Signer, hashed []byte, hash crypto.Hash, alg uint8) ([]byte, error) {
	signature, err := k.Sign(rand.Reader, hashed, hash)
	if err != nil {
		return nil, err
	}

	switch alg {
	case RSASHA1, RSASHA1NSEC3SHA1, RSASHA256, RSASHA512, ED25519:
		return signature, nil
	case ECDSAP256SHA256, ECDSAP384SHA384:
		ecdsaSignature := &struct {
			R, S *big.Int
		}{}
		if _, err := asn1.Unmarshal(signature, ecdsaSignature); err != nil {
			return nil, err
		}

		var intlen int
		switch alg {
		case ECDSAP256SHA256:
			intlen = 32
		case ECDSAP384SHA384:
			intlen = 48
		}

		signature := intToBytes(ecdsaSignature.R, intlen)
		signature = append(signature, intToBytes(ecdsaSignature.S, intlen)...)
		return signature, nil
	default:
		return nil, ErrAlg
	}
}

// Verify validates an RRSet with the signature and key. This is only the
// cryptographic test, the signature validity period must be checked separately.
// This function copies the rdata of some RRs (to lowercase domain names) for the validation to work.
// It also checks that the Zone Key bit (RFC 4034 2.1.1) is set on the DNSKEY
// and that the Protocol field is set to 3 (RFC 4034 2.1.2). Options can not be nil.
func (rr *RRSIG) Verify(k *DNSKEY, rrset []RR, options *SignOption) error {
	if !isRRset(rrset) {
		return ErrRRset
	}
	if RRToType(rrset[0]) != rr.TypeCovered {
		return ErrRRset
	}
	if rr.KeyTag != k.KeyTag() || rr.Hdr.Class != k.Hdr.Class || rr.Algorithm != k.Algorithm {
		return ErrKey
	}
	// RFC 4034 2.1.1 If bit 7 has value 0, then the DNSKEY record holds some
	// other type of DNS public key and MUST NOT be used to verify RRSIGs that
	// cover RRsets.
	if k.Flags&FlagZONE == 0 {
		return ErrKey
	}

	if k.Protocol != 3 || !EqualName(rr.SignerName, k.Hdr.Name) {
		return ErrKey
	}

	if options.Pooler == nil {
		options.Pooler = pool.NewNoop(MinMsgSize)
	}

	rr.Hdr.Name = rrset[0].Header().Name

	// RFC 4035 5.3.2.  Reconstructing the Signed Data
	// Copy the sig, except the rrsig data
	sigwire := new(rrsigWireFmt)
	sigwire.TypeCovered = rr.TypeCovered
	sigwire.Algorithm = rr.Algorithm
	sigwire.Labels = rr.Labels
	sigwire.OrigTTL = rr.OrigTTL
	sigwire.Expiration = rr.Expiration
	sigwire.Inception = rr.Inception
	sigwire.KeyTag = rr.KeyTag
	sigwire.SignerName = rr.SignerName
	// Create the desired binary blob
	signeddata := options.Get()
	defer options.Put(signeddata)

	n, _ := sigwire.pack(signeddata)
	m := rawSignatureData(signeddata[n:], rrset, rr, *options)
	signeddata = signeddata[:m+n]

	sigbuf := rr.sigBuf()

	var h hash.Hash
	hash, ok := AlgorithmToHash[rr.Algorithm]
	if !ok && rr.Algorithm != ED25519 {
		return ErrAlg
	}

	switch rr.Algorithm {
	case RSASHA1, RSASHA1NSEC3SHA1, RSASHA256, RSASHA512:
		pubkey := k.publicKeyRSA()
		if pubkey == nil {
			return ErrKey
		}

		h = hash.New()
		h.Write(signeddata)
		return rsa.VerifyPKCS1v15(pubkey, hash, h.Sum(nil), sigbuf)

	case ECDSAP256SHA256, ECDSAP384SHA384:
		pubkey := k.publicKeyECDSA()
		if pubkey == nil {
			return ErrKey
		}

		// Split sigbuf into the r and s coordinates
		r := new(big.Int).SetBytes(sigbuf[:len(sigbuf)/2])
		s := new(big.Int).SetBytes(sigbuf[len(sigbuf)/2:])

		h = hash.New()
		h.Write(signeddata)
		if ecdsa.Verify(pubkey, h.Sum(nil), r, s) {
			return nil
		}
		return ErrSig

	case ED25519:
		pubkey := k.publicKeyED25519()
		if pubkey == nil {
			return ErrKey
		}

		if ed25519.Verify(pubkey, signeddata, sigbuf) {
			return nil
		}
		return ErrSig
	default:
		return ErrAlg
	}
}

// ValidPeriod uses RFC1982 serial arithmetic to calculate
// if a signature period is valid. If t is the zero time, the
// current time is taken other t is. Returns true if the signature
// is valid at the given time, otherwise returns false.
func (rr *RRSIG) ValidPeriod(t time.Time) bool {
	var utc int64
	if t.IsZero() {
		utc = time.Now().UTC().Unix()
	} else {
		utc = t.UTC().Unix()
	}
	modi := (int64(rr.Inception) - utc) / MaxSerialIncrement
	mode := (int64(rr.Expiration) - utc) / MaxSerialIncrement
	ti := int64(rr.Inception) + modi*MaxSerialIncrement
	te := int64(rr.Expiration) + mode*MaxSerialIncrement
	return ti <= utc && utc <= te
}

// Return the signatures base64 encoding sigdata as a byte slice.
func (rr *RRSIG) sigBuf() []byte {
	sigbuf, err := pack.Base64([]byte(rr.Signature))
	if err != nil {
		return nil
	}
	return sigbuf
}

// SignOption are options that are given to the signer and verifier.
type SignOption struct {
	pool.Pooler // If Pooler is set is will be used for all memory allocations.
}

// IsRRset is duplicated here, as isRRset to avoid a host of cyclic imports.
func isRRset(rrset []RR) bool {
	if len(rrset) == 0 {
		return false
	}
	base := rrset[0].Header()
	basetype := RRToType(rrset[0])
	for _, rr := range rrset[1:] {
		h := rr.Header()
		htype := RRToType(rr)
		if htype != basetype || h.Class != base.Class || h.Name != base.Name {
			return false
		}
	}
	return true
}
