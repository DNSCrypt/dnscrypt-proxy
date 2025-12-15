package dns

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"math/big"
	"strconv"

	"codeberg.org/miekg/dns/internal/unpack"
)

const format = "Private-key-format: v1.3\n"

var bigIntOne = big.NewInt(1)

// PrivateKeyString converts a PrivateKey to a string. This string has the same
// format as the private-key-file of BIND9 (Private-key-format: v1.3).
// It needs some info from the key (the algorithm), so its a method of the DNSKEY.
// It supports *rsa.PrivateKey, *ecdsa.PrivateKey and ed25519.PrivateKey.
func (k *DNSKEY) PrivateKeyString(p crypto.PrivateKey) string {
	algorithm := strconv.Itoa(int(k.Algorithm))
	algorithm += " (" + AlgorithmToString[k.Algorithm] + ")"

	switch p := p.(type) {
	case *rsa.PrivateKey:
		modulus := unpack.Base64(p.N.Bytes())
		e := big.NewInt(int64(p.E))
		publicExponent := unpack.Base64(e.Bytes())
		privateExponent := unpack.Base64(p.D.Bytes())
		prime1 := unpack.Base64(p.Primes[0].Bytes())
		prime2 := unpack.Base64(p.Primes[1].Bytes())
		// Calculate Exponent1/2 and Coefficient as per: http://en.wikipedia.org/wiki/RSA#Using_the_Chinese_remainder_algorithm
		// and from: http://code.google.com/p/go/issues/detail?id=987
		p1 := new(big.Int).Sub(p.Primes[0], bigIntOne)
		q1 := new(big.Int).Sub(p.Primes[1], bigIntOne)
		exp1 := new(big.Int).Mod(p.D, p1)
		exp2 := new(big.Int).Mod(p.D, q1)
		coeff := new(big.Int).ModInverse(p.Primes[1], p.Primes[0])

		exponent1 := unpack.Base64(exp1.Bytes())
		exponent2 := unpack.Base64(exp2.Bytes())
		coefficient := unpack.Base64(coeff.Bytes())

		return format +
			"Algorithm: " + algorithm + "\n" +
			"Modulus: " + modulus + "\n" +
			"PublicExponent: " + publicExponent + "\n" +
			"PrivateExponent: " + privateExponent + "\n" +
			"Prime1: " + prime1 + "\n" +
			"Prime2: " + prime2 + "\n" +
			"Exponent1: " + exponent1 + "\n" +
			"Exponent2: " + exponent2 + "\n" +
			"Coefficient: " + coefficient + "\n"

	case *ecdsa.PrivateKey:
		var intlen int
		switch k.Algorithm {
		case ECDSAP256SHA256:
			intlen = 32
		case ECDSAP384SHA384:
			intlen = 48
		}
		private := unpack.Base64(intToBytes(p.D, intlen))
		return format +
			"Algorithm: " + algorithm + "\n" +
			"PrivateKey: " + private + "\n"

	case ed25519.PrivateKey:
		private := unpack.Base64(p.Seed())
		return format +
			"Algorithm: " + algorithm + "\n" +
			"PrivateKey: " + private + "\n"

	default:
		return ""
	}
}
