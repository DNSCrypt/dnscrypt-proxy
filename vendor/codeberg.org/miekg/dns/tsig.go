package dns

import (
	"encoding/hex"
	"time"

	"codeberg.org/miekg/dns/internal/jump"
	"codeberg.org/miekg/dns/internal/pack"
)

// HMAC hashing codes. These are transmitted as domain names and as such need a closing dot.
const (
	HmacSHA1   = "hmac-sha1."
	HmacSHA224 = "hmac-sha224."
	HmacSHA256 = "hmac-sha256."
	HmacSHA384 = "hmac-sha384."
	HmacSHA512 = "hmac-sha512."

	HmacMD5 = "hmac-md5.sig-alg.reg.int." // Deprecated: HmacMD5 is no longer supported.
)

// TSIGSign fills out the TSIG record in m. This should be a "stub" TSIG RR (see [NewTSIG]) with the algorithm, key name
// (owner name of the RR), time fudge (defaults to 300 seconds, if zero).
// When Sign is called for the first time: options.RequestMAC should be empty and options.TimersOnly should be false.
// When this function returns options.RequestMAC will have the MAC as calculated.
func TSIGSign(m *Msg, k TSIGSigner, options *TSIGOption) error {
	if len(m.Data) == 0 {
		if err := m.Pack(); err != nil {
			return err
		}
	}

	t := hasTSIG(m)
	if t == nil {
		return ErrNoTSIG.Fmt(": %s", "sign")
	}

	last := len(m.Ns) + len(m.Answer) + len(m.Extra) // skip question as 0th, is the first after question
	off := jump.To(last, m.Data)
	if off == 0 {
		return ErrNoTSIG.Fmt(": %s", "sign")
	}

	m.Data = m.Data[:off]
	arcount := uint16(len(m.Extra))
	pack.Uint16(arcount, m.Data, msgArcount) // decrease additional section count, because we removed the TSIG

	macbuf, err := t.mac(m, *options)
	if err != nil {
		return err
	}

	mac, err := k.Sign(t, macbuf, *options)
	if err != nil {
		return err
	}

	t.OrigID = m.ID
	t.MAC = hex.EncodeToString(mac)
	t.MACSize = uint16(len(t.MAC) / 2)
	if t.TimeSigned == 0 {
		t.TimeSigned = uint64(time.Now().Unix())
	}

	tbuf := make([]byte, t.Len())
	if _, off, err = packRR(t, tbuf, 0, nil); err != nil {
		return err
	}
	tbuf = tbuf[:off]

	m.Data = append(m.Data, tbuf...)
	options.RequestMAC = t.MAC

	pack.Uint16(arcount+1, m.Data, msgArcount) // and +1 after we done for the new and improved TSIG that is added
	return nil
}

// TSIGVerify verifies the TSIG on a message. On success a nil error is returned. The TSIG record is removed
// from m.Data, but left in the unpacked message m. TODO(miek): that a good plan?
// When this function returns options.RequestMAC will have the MAC seen on the TSIG.
func TSIGVerify(m *Msg, k TSIGSigner, options *TSIGOption) error {
	if len(m.Data) == 0 {
		if err := m.Pack(); err != nil {
			return err
		}
	}

	t := hasTSIG(m)
	if t == nil {
		return ErrNoTSIG.Fmt(": %s", "verify")
	}

	// Sign unless there is a key or MAC validation error (RFC 8945 5.3.2).
	if t.Error == RcodeBadKey {
		return ErrKey
	}
	if t.Error == RcodeBadSig {
		return ErrSig
	}

	last := len(m.Answer) + len(m.Ns) + len(m.Extra)
	off := jump.To(last, m.Data)
	if off == 0 {
		return ErrNoTSIG.Fmt(": %s", "verify")
	}

	m.Data = m.Data[:off]
	arcount := uint16(len(m.Extra))
	pack.Uint16(arcount, m.Data, msgArcount) // decrease additional section count, because we removed the TSIG

	// restore msg ID, as the origID is used to calculate hash, and set in m.Data.
	pack.Uint16(t.OrigID, m.Data, 0)
	defer func() {
		pack.Uint16(m.ID, m.Data, 0)
	}()

	macbuf, err := t.mac(m, *options)
	if err != nil {
		return err
	}
	if err := k.Verify(t, macbuf, *options); err != nil {
		return err
	}

	now := uint64(time.Now().Unix())
	// Fudge factor works both ways. A message can arrive before it was signed because of clock skew.
	// We check this after verifying the signature, following draft-ietf-dnsop-rfc2845bis
	// instead of RFC2845, in order to prevent a security vulnerability as reported in CVE-2017-3142/3143.
	fudge := now - t.TimeSigned
	if now < t.TimeSigned {
		fudge = t.TimeSigned - now
	}
	if uint64(t.Fudge) < fudge {
		return ErrTime
	}
	pack.Uint16(arcount+1, m.Data, msgArcount) // restore arcount
	options.RequestMAC = t.MAC
	return nil
}

// TSIGOption are options that are given to the signer and verifier.
type TSIGOption struct {
	TimersOnly bool   // Only use the timer information to create the TSIG.
	RequestMAC string // The RequestMAC is the previous MAC to use in this TSIG calculation.
}

// TSIGigner defines an interface that allows for pluggeable signers and verifiers.
type TSIGSigner interface {
	// Sign is passed the to-be-signed binary data extracted from the DNS message in p. It should return the signature or an error.
	Sign(t *TSIG, p []byte, options TSIGOption) ([]byte, error)
	// Verify is passed the binary data with the TSIG octets and the TSIG RR. If the signature is valid it will return nil, otherwise an error.
	Verify(t *TSIG, p []byte, options TSIGOption) error
	// Key returns the key to sign or verify with.
	Key() []byte
}

func hasTSIG(m *Msg) *TSIG {
	lp := len(m.Pseudo)
	if lp == 0 {
		return nil
	}
	t, _ := m.Pseudo[lp-1].(*TSIG)
	return t
}
