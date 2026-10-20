package dns

import (
	"crypto/x509"
)

// Sign creates a SMIMEA record from an SSL certificate.
func (rr *SMIMEA) Sign(usage, selector, matchingType int, cert *x509.Certificate) (err error) {
	rr.Usage = uint8(usage)
	rr.Selector = uint8(selector)
	rr.MatchingType = uint8(matchingType)

	rr.Certificate, err = certificateToDANE(rr.Selector, rr.MatchingType, cert)
	return err
}

// Verify verifies a SMIMEA record against a TLS certificate. If it is OK a nil error is returned.
func (rr *SMIMEA) Verify(cert *x509.Certificate) error {
	c, err := certificateToDANE(rr.Selector, rr.MatchingType, cert)
	if err != nil {
		return err
	}
	if rr.Certificate == c {
		return nil
	}
	return ErrSig
}
