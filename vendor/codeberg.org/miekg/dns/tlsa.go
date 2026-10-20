package dns

import (
	"crypto/x509"
)

// Sign creates a TLSA record from a TLS certificate.
func (rr *TLSA) Sign(usage, selector, matchingtype int, cert *x509.Certificate) (err error) {
	rr.Usage = uint8(usage)
	rr.Selector = uint8(selector)
	rr.MatchingType = uint8(matchingtype)

	rr.Certificate, err = certificateToDANE(rr.Selector, rr.MatchingType, cert)
	return err
}

// Verify verifies a TLSA record against a TLS certificate. If it is OK a nil error is returned.
func (rr *TLSA) Verify(cert *x509.Certificate) error {
	c, err := certificateToDANE(rr.Selector, rr.MatchingType, cert)
	if err != nil {
		return err
	}
	if rr.Certificate == c {
		return nil
	}
	return ErrSig
}
