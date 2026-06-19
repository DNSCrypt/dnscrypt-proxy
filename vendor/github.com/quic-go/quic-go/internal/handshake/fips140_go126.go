//go:build go1.26

package handshake

import "crypto/fips140"

func withoutFIPSEnforcement(f func()) {
	fips140.WithoutEnforcement(f)
}
