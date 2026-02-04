package dnsutil

import (
	"crypto/sha256"
	"encoding/hex"
)

// SMIMEAName returns the ownername of a SMIMEA resource record as per the
// format specified in RFC 'draft-ietf-dane-smime-12' Section 2 and 3.
func SMIMEAName(s, mail string) (string, error) {
	h := sha256.New()
	h.Write([]byte(s))

	// RFC Section 3: "The local-part is hashed using the SHA2-256 algorithm with the hash truncated to 28
	// octets and represented in its hexadecimal representation to become the left-most label in the prepared
	// domain name"
	return hex.EncodeToString(h.Sum(nil)[:28]) + "." + "_smimecert." + s, nil
}
