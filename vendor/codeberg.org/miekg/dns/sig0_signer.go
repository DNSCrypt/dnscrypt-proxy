package dns

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"math/big"

	"codeberg.org/miekg/dns/internal/pack"
)

type CryptoSIG0 struct {
	CryptoSigner crypto.Signer
	PublicKey    *KEY
}

// We need SIG0Option as well here, because the request might be needed as well.

func (c CryptoSIG0) Key() *KEY             { return c.PublicKey }
func (c CryptoSIG0) Signer() crypto.Signer { return c.CryptoSigner }

func (c CryptoSIG0) Sign(s *SIG, p []byte) ([]byte, error) {
	var (
		off int
		err error
	)

	hash, ok := AlgorithmToHash[s.Algorithm]
	if !ok {
		return nil, ErrAlg
	}

	sbuf := make([]byte, s.Len())
	if _, off, err = packRR(s, sbuf, 0, nil); err != nil {
		return nil, err
	}
	sbuf = sbuf[:off]

	h := hash.New()
	h.Write(sbuf)
	h.Write(p)

	return sign(c.Signer(), h.Sum(nil), hash, s.Algorithm)
}

func (c CryptoSIG0) Verify(s *SIG, p []byte) error {
	var (
		off int
		err error
	)
	hash, ok := AlgorithmToHash[s.Algorithm]
	if !ok {
		return ErrAlg
	}

	signature := s.Signature
	s.Signature = "" // omit
	defer func() { s.Signature = signature }()

	sbuf := make([]byte, s.Len())
	if _, off, err = packRR(s, sbuf, 0, nil); err != nil {
		return err
	}
	sbuf = sbuf[:off]

	h := hash.New()

	binarysignature, _ := pack.Base64([]byte(signature))
	switch s.Algorithm {
	case RSASHA1, RSASHA256, RSASHA512:
		h.Write(sbuf)
		h.Write(p)
		return rsa.VerifyPKCS1v15(c.Key().publicKeyRSA(), hash, h.Sum(nil), binarysignature)

	case ECDSAP256SHA256, ECDSAP384SHA384:
		h.Write(sbuf)
		h.Write(p)
		r := new(big.Int).SetBytes(binarysignature[:len(binarysignature)/2])
		s := new(big.Int).SetBytes(binarysignature[len(binarysignature)/2:])
		if ecdsa.Verify(c.Key().publicKeyECDSA(), h.Sum(nil), r, s) {
			return nil
		}
		return ErrSig

	case ED25519:
		h.Write(sbuf)
		h.Write(p)
		if ed25519.Verify(c.Key().publicKeyED25519(), append(sbuf, p...), binarysignature) {
			return nil
		}
		return ErrSig

	}
	return ErrKeyAlg
}
