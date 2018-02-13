// Package p751sidh implements (ephemeral) supersingular isogeny
// Diffie-Hellman, as described in Costello-Longa-Naehrig 2016.  Portions of
// the field arithmetic implementation were based on their implementation.
// Internal functions useful for the implementation are published in the
// p751toolbox package.
//
// This package follows their naming convention, writing "Alice" for the party
// using 2^e-isogenies and "Bob" for the party using 3^e-isogenies.
//
// This package does NOT implement SIDH key validation, so it should only be
// used for ephemeral DH.  Each keypair should be used at most once.
//
// If you feel that SIDH may be appropriate for you, consult your
// cryptographer.
package p751sidh

import (
	"errors"
	"io"
)

import . "github.com/cloudflare/p751sidh/p751toolbox"

const (
	// The secret key size, in bytes.
	SecretKeySize = 48
	// The public key size, in bytes.
	PublicKeySize = 564
	// The shared secret size, in bytes.
	SharedSecretSize = 188
)

const maxAlice = 185

var aliceIsogenyStrategy = [maxAlice]int{0, 1, 1, 2, 2, 2, 3, 4, 4, 4, 4, 5, 5,
	6, 7, 8, 8, 9, 9, 9, 9, 9, 9, 9, 12, 11, 12, 12, 13, 14, 15, 16, 16, 16, 16,
	16, 16, 17, 17, 18, 18, 17, 21, 17, 18, 21, 20, 21, 21, 21, 21, 21, 22, 25, 25,
	25, 26, 27, 28, 28, 29, 30, 31, 32, 32, 32, 32, 32, 32, 32, 33, 33, 33, 35, 36,
	36, 33, 36, 35, 36, 36, 35, 36, 36, 37, 38, 38, 39, 40, 41, 42, 38, 39, 40, 41,
	42, 40, 46, 42, 43, 46, 46, 46, 46, 48, 48, 48, 48, 49, 49, 48, 53, 54, 51, 52,
	53, 54, 55, 56, 57, 58, 59, 59, 60, 62, 62, 63, 64, 64, 64, 64, 64, 64, 64, 64,
	65, 65, 65, 65, 65, 66, 67, 65, 66, 67, 66, 69, 70, 66, 67, 66, 69, 70, 69, 70,
	70, 71, 72, 71, 72, 72, 74, 74, 75, 72, 72, 74, 74, 75, 72, 72, 74, 75, 75, 72,
	72, 74, 75, 75, 77, 77, 79, 80, 80, 82}

const maxBob = 239

var bobIsogenyStrategy = [maxBob]int{0, 1, 1, 2, 2, 2, 3, 3, 4, 4, 4, 5, 5, 5, 6,
	7, 8, 8, 8, 8, 9, 9, 9, 9, 9, 10, 12, 12, 12, 12, 12, 12, 13, 14, 14, 15, 16,
	16, 16, 16, 16, 17, 16, 16, 17, 19, 19, 20, 21, 22, 22, 22, 22, 22, 22, 22, 22,
	22, 22, 24, 24, 25, 27, 27, 28, 28, 29, 28, 29, 28, 28, 28, 30, 28, 28, 28, 29,
	30, 33, 33, 33, 33, 34, 35, 37, 37, 37, 37, 38, 38, 37, 38, 38, 38, 38, 38, 39,
	43, 38, 38, 38, 38, 43, 40, 41, 42, 43, 48, 45, 46, 47, 47, 48, 49, 49, 49, 50,
	51, 50, 49, 49, 49, 49, 51, 49, 53, 50, 51, 50, 51, 51, 51, 52, 55, 55, 55, 56,
	56, 56, 56, 56, 58, 58, 61, 61, 61, 63, 63, 63, 64, 65, 65, 65, 65, 66, 66, 65,
	65, 66, 66, 66, 66, 66, 66, 66, 71, 66, 73, 66, 66, 71, 66, 73, 66, 66, 71, 66,
	73, 68, 68, 71, 71, 73, 73, 73, 75, 75, 78, 78, 78, 80, 80, 80, 81, 81, 82, 83,
	84, 85, 86, 86, 86, 86, 86, 87, 86, 88, 86, 86, 86, 86, 88, 86, 88, 86, 86, 86,
	88, 88, 86, 86, 86, 93, 90, 90, 92, 92, 92, 93, 93, 93, 93, 93, 97, 97, 97, 97,
	97, 97}

// Bob's public key.
type SIDHPublicKeyBob struct {
	affine_xP   ExtensionFieldElement
	affine_xQ   ExtensionFieldElement
	affine_xQmP ExtensionFieldElement
}

// Read a public key from a byte slice.  The input must be at least 564 bytes long.
func (pubKey *SIDHPublicKeyBob) FromBytes(input []byte) {
	if len(input) < 564 {
		panic("Too short input to SIDH pubkey FromBytes, expected 564 bytes")
	}
	pubKey.affine_xP.FromBytes(input[0:188])
	pubKey.affine_xQ.FromBytes(input[188:376])
	pubKey.affine_xQmP.FromBytes(input[376:564])
}

// Write a public key to a byte slice.  The output must be at least 564 bytes long.
func (pubKey *SIDHPublicKeyBob) ToBytes(output []byte) {
	if len(output) < 564 {
		panic("Too short output for SIDH pubkey FromBytes, expected 564 bytes")
	}
	pubKey.affine_xP.ToBytes(output[0:188])
	pubKey.affine_xQ.ToBytes(output[188:376])
	pubKey.affine_xQmP.ToBytes(output[376:564])
}

// Alice's public key.
type SIDHPublicKeyAlice struct {
	affine_xP   ExtensionFieldElement
	affine_xQ   ExtensionFieldElement
	affine_xQmP ExtensionFieldElement
}

// Read a public key from a byte slice.  The input must be at least 564 bytes long.
func (pubKey *SIDHPublicKeyAlice) FromBytes(input []byte) {
	if len(input) < 564 {
		panic("Too short input to SIDH pubkey FromBytes, expected 564 bytes")
	}
	pubKey.affine_xP.FromBytes(input[0:188])
	pubKey.affine_xQ.FromBytes(input[188:376])
	pubKey.affine_xQmP.FromBytes(input[376:564])
}

// Write a public key to a byte slice.  The output must be at least 564 bytes long.
func (pubKey *SIDHPublicKeyAlice) ToBytes(output []byte) {
	if len(output) < 564 {
		panic("Too short output for SIDH pubkey FromBytes, expected 564 bytes")
	}
	pubKey.affine_xP.ToBytes(output[0:188])
	pubKey.affine_xQ.ToBytes(output[188:376])
	pubKey.affine_xQmP.ToBytes(output[376:564])
}

// Bob's secret key.
type SIDHSecretKeyBob struct {
	Scalar [SecretKeySize]byte
}

// Alice's secret key.
type SIDHSecretKeyAlice struct {
	Scalar [SecretKeySize]byte
}

// Generate a keypair for "Alice".  Note that because this library does not
// implement SIDH validation, each keypair should be used for at most one
// shared secret computation.
func GenerateAliceKeypair(rand io.Reader) (publicKey *SIDHPublicKeyAlice, secretKey *SIDHSecretKeyAlice, err error) {
	publicKey = new(SIDHPublicKeyAlice)
	secretKey = new(SIDHSecretKeyAlice)

	_, err = io.ReadFull(rand, secretKey.Scalar[:])
	if err != nil {
		return nil, nil, err
	}

	// Bit-twiddle to ensure scalar is in 2*[0,2^371):
	secretKey.Scalar[47] = 0
	secretKey.Scalar[46] &= 15 // clear high bits, so scalar < 2^372
	secretKey.Scalar[0] &= 254 // clear low bit, so scalar is even

	// We actually want scalar in 2*(0,2^371), but the above procedure
	// generates 0 with probability 2^(-371), which isn't worth checking
	// for.

	*publicKey = secretKey.PublicKey()

	return
}

// Set result to zero if the input scalar is <= 3^238.
//go:noescape
func checkLessThanThree238(scalar *[48]byte, result *uint32)

// Set scalar = 3*scalar
//go:noescape
func multiplyByThree(scalar *[48]byte)

// Generate a keypair for "Bob".  Note that because this library does not
// implement SIDH validation, each keypair should be used for at most one
// shared secret computation.
func GenerateBobKeypair(rand io.Reader) (publicKey *SIDHPublicKeyBob, secretKey *SIDHSecretKeyBob, err error) {
	publicKey = new(SIDHPublicKeyBob)
	secretKey = new(SIDHSecretKeyBob)

	// Perform rejection sampling to obtain a random value in [0,3^238]:
	var ok uint32
	for i := 0; i < 102; i++ {
		_, err = io.ReadFull(rand, secretKey.Scalar[:])
		if err != nil {
			return nil, nil, err
		}
		// Mask the high bits to obtain a uniform value in [0,2^378):
		secretKey.Scalar[47] &= 3
		// Accept if scalar < 3^238 (this happens w/ prob ~0.5828)
		checkLessThanThree238(&secretKey.Scalar, &ok)
		if ok == 0 {
			break
		}
	}
	// ok is nonzero if all 102 trials failed.
	// This happens with probability 0.41719...^102 < 2^(-128), i.e., never
	if ok != 0 {
		return nil, nil, errors.New("WOW! An event with probability < 2^(-128) occurred!!")
	}

	// Multiply by 3 to get a scalar in 3*[0,3^238):
	multiplyByThree(&secretKey.Scalar)

	// We actually want scalar in 2*(0,2^371), but the above procedure
	// generates 0 with probability 3^(-238), which isn't worth checking
	// for.

	*publicKey = secretKey.PublicKey()

	return
}

// Compute the corresponding public key for the given secret key.
func (secretKey *SIDHSecretKeyAlice) PublicKey() SIDHPublicKeyAlice {
	var xP, xQ, xQmP, xR ProjectivePoint

	xP.FromAffinePrimeField(&Affine_xPB)     // = ( x_P : 1) = x(P_B)
	xQ.FromAffinePrimeField(&Affine_xPB)     //
	xQ.X.Neg(&xQ.X)                          // = (-x_P : 1) = x(Q_B)
	xQmP = DistortAndDifference(&Affine_xPB) // = x(Q_B - P_B)

	xR = SecretPoint(&Affine_xPA, &Affine_yPA, secretKey.Scalar[:])

	var currentCurve ProjectiveCurveParameters
	// Starting curve has a = 0, so (A:C) = (0,1)
	currentCurve.A.Zero()
	currentCurve.C.One()

	var firstPhi FirstFourIsogeny
	currentCurve, firstPhi = ComputeFirstFourIsogeny(&currentCurve)

	xP = firstPhi.Eval(&xP)
	xQ = firstPhi.Eval(&xQ)
	xQmP = firstPhi.Eval(&xQmP)
	xR = firstPhi.Eval(&xR)

	var points = make([]ProjectivePoint, 0, 8)
	var indices = make([]int, 0, 8)
	var phi FourIsogeny

	var i = 0

	for j := 1; j < 185; j++ {
		for i < 185-j {
			points = append(points, xR)
			indices = append(indices, i)
			k := int(aliceIsogenyStrategy[185-i-j])
			xR.Pow2k(&currentCurve, &xR, uint32(2*k))
			i = i + k
		}
		currentCurve, phi = ComputeFourIsogeny(&xR)

		for k := 0; k < len(points); k++ {
			points[k] = phi.Eval(&points[k])
		}

		xP = phi.Eval(&xP)
		xQ = phi.Eval(&xQ)
		xQmP = phi.Eval(&xQmP)

		// pop xR from points
		xR, points = points[len(points)-1], points[:len(points)-1]
		i, indices = int(indices[len(indices)-1]), indices[:len(indices)-1]
	}

	currentCurve, phi = ComputeFourIsogeny(&xR)
	xP = phi.Eval(&xP)
	xQ = phi.Eval(&xQ)
	xQmP = phi.Eval(&xQmP)

	var invZP, invZQ, invZQmP ExtensionFieldElement
	ExtensionFieldBatch3Inv(&xP.Z, &xQ.Z, &xQmP.Z, &invZP, &invZQ, &invZQmP)

	var publicKey SIDHPublicKeyAlice
	publicKey.affine_xP.Mul(&xP.X, &invZP)
	publicKey.affine_xQ.Mul(&xQ.X, &invZQ)
	publicKey.affine_xQmP.Mul(&xQmP.X, &invZQmP)

	return publicKey
}

// Compute the public key corresponding to the secret key.
func (secretKey *SIDHSecretKeyBob) PublicKey() SIDHPublicKeyBob {
	var xP, xQ, xQmP, xR ProjectivePoint

	xP.FromAffinePrimeField(&Affine_xPA)     // = ( x_P : 1) = x(P_A)
	xQ.FromAffinePrimeField(&Affine_xPA)     //
	xQ.X.Neg(&xQ.X)                          // = (-x_P : 1) = x(Q_A)
	xQmP = DistortAndDifference(&Affine_xPA) // = x(Q_B - P_B)

	xR = SecretPoint(&Affine_xPB, &Affine_yPB, secretKey.Scalar[:])

	var currentCurve ProjectiveCurveParameters
	// Starting curve has a = 0, so (A:C) = (0,1)
	currentCurve.A.Zero()
	currentCurve.C.One()

	var points = make([]ProjectivePoint, 0, 8)
	var indices = make([]int, 0, 8)
	var phi ThreeIsogeny

	var i = 0

	for j := 1; j < 239; j++ {
		for i < 239-j {
			points = append(points, xR)
			indices = append(indices, i)
			k := int(bobIsogenyStrategy[239-i-j])
			xR.Pow3k(&currentCurve, &xR, uint32(k))
			i = i + k
		}
		currentCurve, phi = ComputeThreeIsogeny(&xR)

		for k := 0; k < len(points); k++ {
			points[k] = phi.Eval(&points[k])
		}

		xP = phi.Eval(&xP)
		xQ = phi.Eval(&xQ)
		xQmP = phi.Eval(&xQmP)

		// pop xR from points
		xR, points = points[len(points)-1], points[:len(points)-1]
		i, indices = int(indices[len(indices)-1]), indices[:len(indices)-1]
	}

	currentCurve, phi = ComputeThreeIsogeny(&xR)
	xP = phi.Eval(&xP)
	xQ = phi.Eval(&xQ)
	xQmP = phi.Eval(&xQmP)

	var invZP, invZQ, invZQmP ExtensionFieldElement
	ExtensionFieldBatch3Inv(&xP.Z, &xQ.Z, &xQmP.Z, &invZP, &invZQ, &invZQmP)

	var publicKey SIDHPublicKeyBob
	publicKey.affine_xP.Mul(&xP.X, &invZP)
	publicKey.affine_xQ.Mul(&xQ.X, &invZQ)
	publicKey.affine_xQmP.Mul(&xQmP.X, &invZQmP)

	return publicKey
}

// Compute (Alice's view of) a shared secret using Alice's secret key and Bob's public key.
func (aliceSecret *SIDHSecretKeyAlice) SharedSecret(bobPublic *SIDHPublicKeyBob) [SharedSecretSize]byte {
	var currentCurve = RecoverCurveParameters(&bobPublic.affine_xP, &bobPublic.affine_xQ, &bobPublic.affine_xQmP)

	var xR, xP, xQ, xQmP ProjectivePoint

	xP.FromAffine(&bobPublic.affine_xP)
	xQ.FromAffine(&bobPublic.affine_xQ)
	xQmP.FromAffine(&bobPublic.affine_xQmP)

	xR.ThreePointLadder(&currentCurve, &xP, &xQ, &xQmP, aliceSecret.Scalar[:])

	var firstPhi FirstFourIsogeny
	currentCurve, firstPhi = ComputeFirstFourIsogeny(&currentCurve)
	xR = firstPhi.Eval(&xR)

	var points = make([]ProjectivePoint, 0, 8)
	var indices = make([]int, 0, 8)
	var phi FourIsogeny

	var i = 0

	for j := 1; j < 185; j++ {
		for i < 185-j {
			points = append(points, xR)
			indices = append(indices, i)
			k := int(aliceIsogenyStrategy[185-i-j])
			xR.Pow2k(&currentCurve, &xR, uint32(2*k))
			i = i + k
		}
		currentCurve, phi = ComputeFourIsogeny(&xR)

		for k := 0; k < len(points); k++ {
			points[k] = phi.Eval(&points[k])
		}

		// pop xR from points
		xR, points = points[len(points)-1], points[:len(points)-1]
		i, indices = int(indices[len(indices)-1]), indices[:len(indices)-1]
	}

	currentCurve, _ = ComputeFourIsogeny(&xR)

	var sharedSecret [SharedSecretSize]byte
	var jInv = currentCurve.JInvariant()
	jInv.ToBytes(sharedSecret[:])
	return sharedSecret
}

// Compute (Bob's view of) a shared secret using Bob's secret key and Alice's public key.
func (bobSecret *SIDHSecretKeyBob) SharedSecret(alicePublic *SIDHPublicKeyAlice) [SharedSecretSize]byte {
	var currentCurve = RecoverCurveParameters(&alicePublic.affine_xP, &alicePublic.affine_xQ, &alicePublic.affine_xQmP)

	var xR, xP, xQ, xQmP ProjectivePoint

	xP.FromAffine(&alicePublic.affine_xP)
	xQ.FromAffine(&alicePublic.affine_xQ)
	xQmP.FromAffine(&alicePublic.affine_xQmP)

	xR.ThreePointLadder(&currentCurve, &xP, &xQ, &xQmP, bobSecret.Scalar[:])

	var points = make([]ProjectivePoint, 0, 8)
	var indices = make([]int, 0, 8)
	var phi ThreeIsogeny

	var i = 0

	for j := 1; j < 239; j++ {
		for i < 239-j {
			points = append(points, xR)
			indices = append(indices, i)
			k := int(bobIsogenyStrategy[239-i-j])
			xR.Pow3k(&currentCurve, &xR, uint32(k))
			i = i + k
		}
		currentCurve, phi = ComputeThreeIsogeny(&xR)

		for k := 0; k < len(points); k++ {
			points[k] = phi.Eval(&points[k])
		}

		// pop xR from points
		xR, points = points[len(points)-1], points[:len(points)-1]
		i, indices = int(indices[len(indices)-1]), indices[:len(indices)-1]
	}
	currentCurve, _ = ComputeThreeIsogeny(&xR)

	var sharedSecret [SharedSecretSize]byte
	var jInv = currentCurve.JInvariant()
	jInv.ToBytes(sharedSecret[:])
	return sharedSecret
}
