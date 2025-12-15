package dns

import (
	"bytes"
	"crypto"
	"encoding/hex"
	"fmt"

	"codeberg.org/miekg/dns/pool"
	"codeberg.org/miekg/dns/rdata"
)

// ZONEMDption are options that are given to the signer and verifier.
type ZONEMDOption struct {
	pool.Pooler // If Pooler is set is will be used for all memory allocations.
}

// Sign "signs" an zone. When done successfully the rr's digest will be updated. ZONEMD must be a skeleton
// (placeholder) RR, where scheme and hash are filled out. See [NewZONEMD] on how to create such a record.
// The zone's RR must be in canonical order, but this isn't enforced by Sign, see [Sort]. As RFC 8976 specifies
// that for the simple scheme (the only supported scheme) some records are excluded from the digest calculation.
func (rr *ZONEMD) Sign(zone []RR, options *ZONEMDOption) error {
	if rr.Scheme != ZONEMDSchemeSimple {
		return fmt.Errorf("bad ZONEMD Scheme")
	}
	if options.Pooler == nil {
		options.Pooler = pool.NewNoop(DefaultMsgSize)
	}

	var hash crypto.Hash
	switch rr.Hash {
	case ZONEMDHashSHA384:
		hash = crypto.SHA384
	case ZONEMDHashSHA512:
		hash = crypto.SHA512
	default:
		return fmt.Errorf("bad ZONEMD Hash")
	}

	rrdata := options.Get()
	defer options.Put(rrdata)
	s := hash.New()
	for _, rr1 := range zone {
		if _, ok := rr1.(*ZONEMD); ok {
			continue
		}
		if s, ok := rr1.(*RRSIG); ok && s.TypeCovered == TypeZONEMD {
			continue
		}
		if s, ok := rr1.(*SOA); ok {
			rr.Serial = s.Serial
		}
		canonicalize(rr1)
		_, off, err := packRR(rr1, rrdata, 0, nil)
		if err != nil {
			return err
		}
		s.Write(rrdata[:off])
	}
	rr.Digest = hex.EncodeToString(s.Sum(nil))
	return nil
}

// Verify verifies the digest in rr with the one derived from zone. This simply calls [ZONEMD.Sign] and
// compares the digests, on succes nil is returned.
func (rr *ZONEMD) Verify(zone []RR, options *ZONEMDOption) error {
	rr1 := NewZONEMD(rr.Header().Name, rr.Scheme, rr.Hash)
	if err := rr1.Sign(zone, options); err != nil {
		return err
	}
	digest1, err := hex.DecodeString(rr1.Digest)
	if err != nil {
		return err
	}
	digest, err := hex.DecodeString(rr.Digest)
	if err != nil {
		return err
	}
	if bytes.Equal(digest1, digest) {
		return nil
	}
	return fmt.Errorf("bad ZONEMD Digest")
}

// NewZONEMD returns a ZONEMD record that can be used as a placeholder in a zone.
func NewZONEMD(origin string, scheme, hash uint8) *ZONEMD {
	return &ZONEMD{Header{Name: origin, Class: ClassINET}, rdata.ZONEMD{Scheme: scheme, Hash: hash}}
}
