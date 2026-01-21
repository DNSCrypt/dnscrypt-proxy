package dns

import (
	"crypto"

	"codeberg.org/miekg/dns/internal/jump"
	"codeberg.org/miekg/dns/internal/pack"
	"codeberg.org/miekg/dns/internal/unpack"
)

// SIG0Sign signs a dns.Msg. It fills the signature with the appropriate data.
// The SIG record should have the SignerName, KeyTag, Algorithm, Inception
// and Expiration set.
func SIG0Sign(m *Msg, k SIG0Signer, options *SIG0Option) error {
	if len(m.Data) == 0 {
		if err := m.Pack(); err != nil {
			return err
		}
	}

	s := hasSIG0(m)
	if s == nil {
		return ErrNoSIG0.Fmt(": %s", "sign")
	}

	last := len(m.Ns) + len(m.Answer) + len(m.Extra) // skip question as 0th, is the first after question
	off := jump.To(last, m.Data)
	if off == 0 {
		return ErrNoSIG0.Fmt(": %s", "sign")
	}

	m.Data = m.Data[:off]
	arcount := uint16(len(m.Extra))
	pack.Uint16(arcount, m.Data, msgArcount) // decrease additional section count, because we removed the TSIG

	signature, err := k.Sign(s, m.Data, *options)
	if err != nil {
		return err
	}

	s.Signature = unpack.Base64(signature)

	sbuf := make([]byte, s.Len())
	if _, off, err = packRR(s, sbuf, 0, nil); err != nil {
		return err
	}
	sbuf = sbuf[:off]
	m.Data = append(m.Data, sbuf...)

	pack.Uint16(arcount+1, m.Data, msgArcount) // and +1 after we done for the new and improved TSIG that is added
	return nil
}

// Verify validates the message buf using the key k.
func SIG0Verify(m *Msg, y *KEY, k SIG0Signer, options *SIG0Option) error {
	if len(m.Data) == 0 {
		if err := m.Pack(); err != nil {
			return err
		}
	}

	s := hasSIG0(m)
	if s == nil {
		return ErrNoSIG0.Fmt(": %s", "verify")
	}

	last := len(m.Answer) + len(m.Ns) + len(m.Extra)
	off := jump.To(last, m.Data)
	if off == 0 {
		return ErrNoSIG0.Fmt(": %s", "verify")
	}

	m.Data = m.Data[:off]
	arcount := uint16(len(m.Extra))
	pack.Uint16(arcount, m.Data, msgArcount) // decrease additional section count, because we removed the TSIG

	err := k.Verify(s, m.Data, *options)

	pack.Uint16(arcount+1, m.Data, msgArcount) // restore arcount
	return err
}

// SIG0ption are options that are given to the signer and verifier.
type SIG0Option struct{}

// SIG0Signer defines an interface that allows for pluggeable signers and verifiers.
type SIG0Signer interface {
	// Sign is passed the to-be-signed binary data extracted from the DNS message in p. It should return the signature or an error.
	Sign(s *SIG, p []byte, options SIG0Option) ([]byte, error)
	// Verify is passed the binary data with the TSIG octets and the TSIG RR. If the signature is valid it will return nil, otherwise an error.
	Verify(s *SIG, p []byte, options SIG0Option) error
	// Key returns the key to sign or verify with.
	Key() *KEY
	// Signer returns the crypto signer to sign or verify with.
	Signer() crypto.Signer
}

func hasSIG0(m *Msg) *SIG {
	lp := len(m.Pseudo)
	if lp == 0 {
		return nil
	}
	s, _ := m.Pseudo[lp-1].(*SIG)
	return s
}
