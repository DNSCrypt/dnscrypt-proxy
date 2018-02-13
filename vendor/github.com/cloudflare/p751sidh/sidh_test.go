package p751sidh

import (
	"bytes"
	"crypto/rand"
	mathRand "math/rand"
	"reflect"
	"testing"
	"testing/quick"
)

import . "github.com/cloudflare/p751sidh/p751toolbox"

func TestMultiplyByThree(t *testing.T) {
	// sage: repr((3^238 -1).digits(256))
	var three238minus1 = [48]byte{248, 132, 131, 130, 138, 113, 205, 237, 20, 122, 66, 212, 191, 53, 59, 115, 56, 207, 215, 148, 207, 41, 130, 248, 214, 42, 124, 12, 153, 108, 197, 99, 199, 34, 66, 143, 126, 168, 88, 184, 245, 234, 37, 181, 198, 201, 84, 2}
	// sage: repr((3*(3^238 -1)).digits(256))
	var threeTimesThree238minus1 = [48]byte{232, 142, 138, 135, 159, 84, 104, 201, 62, 110, 199, 124, 63, 161, 177, 89, 169, 109, 135, 190, 110, 125, 134, 233, 132, 128, 116, 37, 203, 69, 80, 43, 86, 104, 198, 173, 123, 249, 9, 41, 225, 192, 113, 31, 84, 93, 254, 6}

	multiplyByThree(&three238minus1)

	for i := 0; i < 48; i++ {
		if three238minus1[i] != threeTimesThree238minus1[i] {
			t.Error("Digit", i, "error: found", three238minus1[i], "expected", threeTimesThree238minus1[i])
		}
	}
}

func TestCheckLessThanThree238(t *testing.T) {
	var three238minus1 = [48]byte{248, 132, 131, 130, 138, 113, 205, 237, 20, 122, 66, 212, 191, 53, 59, 115, 56, 207, 215, 148, 207, 41, 130, 248, 214, 42, 124, 12, 153, 108, 197, 99, 199, 34, 66, 143, 126, 168, 88, 184, 245, 234, 37, 181, 198, 201, 84, 2}
	var three238 = [48]byte{249, 132, 131, 130, 138, 113, 205, 237, 20, 122, 66, 212, 191, 53, 59, 115, 56, 207, 215, 148, 207, 41, 130, 248, 214, 42, 124, 12, 153, 108, 197, 99, 199, 34, 66, 143, 126, 168, 88, 184, 245, 234, 37, 181, 198, 201, 84, 2}
	var three238plus1 = [48]byte{250, 132, 131, 130, 138, 113, 205, 237, 20, 122, 66, 212, 191, 53, 59, 115, 56, 207, 215, 148, 207, 41, 130, 248, 214, 42, 124, 12, 153, 108, 197, 99, 199, 34, 66, 143, 126, 168, 88, 184, 245, 234, 37, 181, 198, 201, 84, 2}

	var result = uint32(57)

	checkLessThanThree238(&three238minus1, &result)
	if result != 0 {
		t.Error("Expected 0, got", result)
	}
	checkLessThanThree238(&three238, &result)
	if result == 0 {
		t.Error("Expected nonzero, got", result)
	}
	checkLessThanThree238(&three238plus1, &result)
	if result == 0 {
		t.Error("Expected nonzero, got", result)
	}
}

// This throws away the generated public key, forcing us to recompute it in the test,
// but generating the value *in* the quickcheck predicate breaks the testing.
func (x SIDHSecretKeyAlice) Generate(quickCheckRand *mathRand.Rand, size int) reflect.Value {
	// use crypto/rand instead of the quickCheck-provided RNG
	_, aliceSecret, err := GenerateAliceKeypair(rand.Reader)
	if err != nil {
		panic("error generating secret key")
	}
	return reflect.ValueOf(*aliceSecret)
}

func (x SIDHSecretKeyBob) Generate(quickCheckRand *mathRand.Rand, size int) reflect.Value {
	// use crypto/rand instead of the quickCheck-provided RNG
	_, bobSecret, err := GenerateBobKeypair(rand.Reader)
	if err != nil {
		panic("error generating secret key")
	}
	return reflect.ValueOf(*bobSecret)
}

func TestEphemeralSharedSecret(t *testing.T) {
	sharedSecretsMatch := func(aliceSecret SIDHSecretKeyAlice, bobSecret SIDHSecretKeyBob) bool {
		alicePublic := aliceSecret.PublicKey()
		bobPublic := bobSecret.PublicKey()

		aliceSharedSecret := aliceSecret.SharedSecret(&bobPublic)
		bobSharedSecret := bobSecret.SharedSecret(&alicePublic)

		return bytes.Equal(aliceSharedSecret[:], bobSharedSecret[:])
	}

	if err := quick.Check(sharedSecretsMatch, nil); err != nil {
		t.Error(err)
	}
}

// Perform Alice's (2-isogeny) key generation, using the slow but simple multiplication-based strategy.
//
// This function just exists to ensure that the fast isogeny-tree strategy works correctly.
func aliceKeyGenSlow(secretKey *SIDHSecretKeyAlice) SIDHPublicKeyAlice {
	var xP, xQ, xQmP, xR, xS ProjectivePoint

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

	var phi FourIsogeny
	for e := (372 - 4); e >= 0; e -= 2 {
		xS.Pow2k(&currentCurve, &xR, uint32(e))
		currentCurve, phi = ComputeFourIsogeny(&xS)
		xR = phi.Eval(&xR)
		xP = phi.Eval(&xP)
		xQ = phi.Eval(&xQ)
		xQmP = phi.Eval(&xQmP)
	}

	var invZP, invZQ, invZQmP ExtensionFieldElement
	ExtensionFieldBatch3Inv(&xP.Z, &xQ.Z, &xQmP.Z, &invZP, &invZQ, &invZQmP)

	var publicKey SIDHPublicKeyAlice
	publicKey.affine_xP.Mul(&xP.X, &invZP)
	publicKey.affine_xQ.Mul(&xQ.X, &invZQ)
	publicKey.affine_xQmP.Mul(&xQmP.X, &invZQmP)

	return publicKey
}

// Perform Bob's (3-isogeny) key generation, using the slow but simple multiplication-based strategy.
//
// This function just exists to ensure that the fast isogeny-tree strategy works correctly.
func bobKeyGenSlow(secretKey *SIDHSecretKeyBob) SIDHPublicKeyBob {
	var xP, xQ, xQmP, xR, xS ProjectivePoint

	xP.FromAffinePrimeField(&Affine_xPA)     // = ( x_P : 1) = x(P_A)
	xQ.FromAffinePrimeField(&Affine_xPA)     //
	xQ.X.Neg(&xQ.X)                          // = (-x_P : 1) = x(Q_A)
	xQmP = DistortAndDifference(&Affine_xPA) // = x(Q_B - P_B)

	xR = SecretPoint(&Affine_xPB, &Affine_yPB, secretKey.Scalar[:])

	var currentCurve ProjectiveCurveParameters
	// Starting curve has a = 0, so (A:C) = (0,1)
	currentCurve.A.Zero()
	currentCurve.C.One()

	var phi ThreeIsogeny
	for e := 238; e >= 0; e-- {
		xS.Pow3k(&currentCurve, &xR, uint32(e))
		currentCurve, phi = ComputeThreeIsogeny(&xS)
		xR = phi.Eval(&xR)
		xP = phi.Eval(&xP)
		xQ = phi.Eval(&xQ)
		xQmP = phi.Eval(&xQmP)
	}

	var invZP, invZQ, invZQmP ExtensionFieldElement
	ExtensionFieldBatch3Inv(&xP.Z, &xQ.Z, &xQmP.Z, &invZP, &invZQ, &invZQmP)

	var publicKey SIDHPublicKeyBob
	publicKey.affine_xP.Mul(&xP.X, &invZP)
	publicKey.affine_xQ.Mul(&xQ.X, &invZQ)
	publicKey.affine_xQmP.Mul(&xQmP.X, &invZQmP)

	return publicKey
}

// Perform Alice's key agreement, using the slow but simple multiplication-based strategy.
//
// This function just exists to ensure that the fast isogeny-tree strategy works correctly.
func aliceSharedSecretSlow(bobPublic *SIDHPublicKeyBob, aliceSecret *SIDHSecretKeyAlice) [188]byte {
	var currentCurve = RecoverCurveParameters(&bobPublic.affine_xP, &bobPublic.affine_xQ, &bobPublic.affine_xQmP)

	var xR, xS, xP, xQ, xQmP ProjectivePoint

	xP.FromAffine(&bobPublic.affine_xP)
	xQ.FromAffine(&bobPublic.affine_xQ)
	xQmP.FromAffine(&bobPublic.affine_xQmP)

	xR.ThreePointLadder(&currentCurve, &xP, &xQ, &xQmP, aliceSecret.Scalar[:])

	var firstPhi FirstFourIsogeny
	currentCurve, firstPhi = ComputeFirstFourIsogeny(&currentCurve)
	xR = firstPhi.Eval(&xR)

	var phi FourIsogeny
	for e := (372 - 4); e >= 2; e -= 2 {
		xS.Pow2k(&currentCurve, &xR, uint32(e))
		currentCurve, phi = ComputeFourIsogeny(&xS)
		xR = phi.Eval(&xR)
	}

	currentCurve, _ = ComputeFourIsogeny(&xR)

	var sharedSecret [SharedSecretSize]byte
	var jInv = currentCurve.JInvariant()
	jInv.ToBytes(sharedSecret[:])
	return sharedSecret
}

// Perform Bob's key agreement, using the slow but simple multiplication-based strategy.
//
// This function just exists to ensure that the fast isogeny-tree strategy works correctly.
func bobSharedSecretSlow(alicePublic *SIDHPublicKeyAlice, bobSecret *SIDHSecretKeyBob) [188]byte {
	var currentCurve = RecoverCurveParameters(&alicePublic.affine_xP, &alicePublic.affine_xQ, &alicePublic.affine_xQmP)

	var xR, xS, xP, xQ, xQmP ProjectivePoint

	xP.FromAffine(&alicePublic.affine_xP)
	xQ.FromAffine(&alicePublic.affine_xQ)
	xQmP.FromAffine(&alicePublic.affine_xQmP)

	xR.ThreePointLadder(&currentCurve, &xP, &xQ, &xQmP, bobSecret.Scalar[:])

	var phi ThreeIsogeny
	for e := 238; e >= 1; e-- {
		xS.Pow3k(&currentCurve, &xR, uint32(e))
		currentCurve, phi = ComputeThreeIsogeny(&xS)
		xR = phi.Eval(&xR)
	}

	currentCurve, _ = ComputeThreeIsogeny(&xR)

	var sharedSecret [SharedSecretSize]byte
	var jInv = currentCurve.JInvariant()
	jInv.ToBytes(sharedSecret[:])
	return sharedSecret
}

func TestBobKeyGenFastVsSlow(t *testing.T) {
	// m_B = 3*randint(0,3^238)
	var m_B = [48]uint8{246, 217, 158, 190, 100, 227, 224, 181, 171, 32, 120, 72, 92, 115, 113, 62, 103, 57, 71, 252, 166, 121, 126, 201, 55, 99, 213, 234, 243, 228, 171, 68, 9, 239, 214, 37, 255, 242, 217, 180, 25, 54, 242, 61, 101, 245, 78, 0}

	var bobSecretKey = SIDHSecretKeyBob{Scalar: m_B}
	var fastPubKey = bobSecretKey.PublicKey()
	var slowPubKey = bobKeyGenSlow(&bobSecretKey)

	if !fastPubKey.affine_xP.VartimeEq(&slowPubKey.affine_xP) {
		t.Error("Expected affine_xP = ", fastPubKey.affine_xP, "found", slowPubKey.affine_xP)
	}
	if !fastPubKey.affine_xQ.VartimeEq(&slowPubKey.affine_xQ) {
		t.Error("Expected affine_xQ = ", fastPubKey.affine_xQ, "found", slowPubKey.affine_xQ)
	}
	if !fastPubKey.affine_xQmP.VartimeEq(&slowPubKey.affine_xQmP) {
		t.Error("Expected affine_xQmP = ", fastPubKey.affine_xQmP, "found", slowPubKey.affine_xQmP)
	}
}

func TestAliceKeyGenFastVsSlow(t *testing.T) {
	// m_A = 2*randint(0,2^371)
	var m_A = [48]uint8{248, 31, 9, 39, 165, 125, 79, 135, 70, 97, 87, 231, 221, 204, 245, 38, 150, 198, 187, 184, 199, 148, 156, 18, 137, 71, 248, 83, 111, 170, 138, 61, 112, 25, 188, 197, 132, 151, 1, 0, 207, 178, 24, 72, 171, 22, 11, 0}

	var aliceSecretKey = SIDHSecretKeyAlice{Scalar: m_A}
	var fastPubKey = aliceSecretKey.PublicKey()
	var slowPubKey = aliceKeyGenSlow(&aliceSecretKey)

	if !fastPubKey.affine_xP.VartimeEq(&slowPubKey.affine_xP) {
		t.Error("Expected affine_xP = ", fastPubKey.affine_xP, "found", slowPubKey.affine_xP)
	}
	if !fastPubKey.affine_xQ.VartimeEq(&slowPubKey.affine_xQ) {
		t.Error("Expected affine_xQ = ", fastPubKey.affine_xQ, "found", slowPubKey.affine_xQ)
	}
	if !fastPubKey.affine_xQmP.VartimeEq(&slowPubKey.affine_xQmP) {
		t.Error("Expected affine_xQmP = ", fastPubKey.affine_xQmP, "found", slowPubKey.affine_xQmP)
	}
}

func TestSharedSecret(t *testing.T) {
	// m_A = 2*randint(0,2^371)
	var m_A = [48]uint8{248, 31, 9, 39, 165, 125, 79, 135, 70, 97, 87, 231, 221, 204, 245, 38, 150, 198, 187, 184, 199, 148, 156, 18, 137, 71, 248, 83, 111, 170, 138, 61, 112, 25, 188, 197, 132, 151, 1, 0, 207, 178, 24, 72, 171, 22, 11, 0}
	// m_B = 3*randint(0,3^238)
	var m_B = [48]uint8{246, 217, 158, 190, 100, 227, 224, 181, 171, 32, 120, 72, 92, 115, 113, 62, 103, 57, 71, 252, 166, 121, 126, 201, 55, 99, 213, 234, 243, 228, 171, 68, 9, 239, 214, 37, 255, 242, 217, 180, 25, 54, 242, 61, 101, 245, 78, 0}

	var aliceSecret = SIDHSecretKeyAlice{Scalar: m_A}
	var bobSecret = SIDHSecretKeyBob{Scalar: m_B}

	var alicePublic = aliceSecret.PublicKey()
	var bobPublic = bobSecret.PublicKey()

	var aliceSharedSecretSlow = aliceSharedSecretSlow(&bobPublic, &aliceSecret)
	var aliceSharedSecretFast = aliceSecret.SharedSecret(&bobPublic)
	var bobSharedSecretSlow = bobSharedSecretSlow(&alicePublic, &bobSecret)
	var bobSharedSecretFast = bobSecret.SharedSecret(&alicePublic)

	if !bytes.Equal(aliceSharedSecretFast[:], aliceSharedSecretSlow[:]) {
		t.Error("Shared secret (fast) mismatch: Alice has ", aliceSharedSecretFast, " Bob has ", bobSharedSecretFast)
	}
	if !bytes.Equal(aliceSharedSecretSlow[:], bobSharedSecretSlow[:]) {
		t.Error("Shared secret (slow) mismatch: Alice has ", aliceSharedSecretSlow, " Bob has ", bobSharedSecretSlow)
	}
	if !bytes.Equal(aliceSharedSecretSlow[:], bobSharedSecretFast[:]) {
		t.Error("Shared secret mismatch: Alice (slow) has ", aliceSharedSecretSlow, " Bob (fast) has ", bobSharedSecretFast)
	}
}

func TestSecretPoint(t *testing.T) {
	// m_A = 2*randint(0,2^371)
	var m_A = [48]uint8{248, 31, 9, 39, 165, 125, 79, 135, 70, 97, 87, 231, 221, 204, 245, 38, 150, 198, 187, 184, 199, 148, 156, 18, 137, 71, 248, 83, 111, 170, 138, 61, 112, 25, 188, 197, 132, 151, 1, 0, 207, 178, 24, 72, 171, 22, 11, 0}
	// m_B = 3*randint(0,3^238)
	var m_B = [48]uint8{246, 217, 158, 190, 100, 227, 224, 181, 171, 32, 120, 72, 92, 115, 113, 62, 103, 57, 71, 252, 166, 121, 126, 201, 55, 99, 213, 234, 243, 228, 171, 68, 9, 239, 214, 37, 255, 242, 217, 180, 25, 54, 242, 61, 101, 245, 78, 0}

	var xR_A = SecretPoint(&Affine_xPA, &Affine_yPA, m_A[:])
	var xR_B = SecretPoint(&Affine_xPB, &Affine_yPB, m_B[:])

	var sageAffine_xR_A = ExtensionFieldElement{A: Fp751Element{0x29f1dff12103d089, 0x7409b9bf955e0d87, 0xe812441c1cca7288, 0xc32b8b13efba55f9, 0xc3b76a80696d83da, 0x185dd4f93a3dc373, 0xfc07c1a9115b6717, 0x39bfcdd63b5c4254, 0xc4d097d51d41efd8, 0x4f893494389b21c7, 0x373433211d3d0446, 0x53c35ccc3d22}, B: Fp751Element{0x722e718f33e40815, 0x8c5fc0fdf715667, 0x850fd292bbe8c74c, 0x212938a60fcbf5d3, 0xfdb2a099d58dc6e7, 0x232f83ab63c9c205, 0x23eda62fa5543f5e, 0x49b5758855d9d04f, 0x6b455e6642ef25d1, 0x9651162537470202, 0xfeced582f2e96ff0, 0x33a9e0c0dea8}}
	var sageAffine_xR_B = ExtensionFieldElement{A: Fp751Element{0xdd4e66076e8499f5, 0xe7efddc6907519da, 0xe31f9955b337108c, 0x8e558c5479ffc5e1, 0xfee963ead776bfc2, 0x33aa04c35846bf15, 0xab77d91b23617a0d, 0xbdd70948746070e2, 0x66f71291c277e942, 0x187c39db2f901fce, 0x69262987d5d32aa2, 0xe1db40057dc}, B: Fp751Element{0xd1b766abcfd5c167, 0x4591059dc8a382fa, 0x1ddf9490736c223d, 0xc96db091bdf2b3dd, 0x7b8b9c3dc292f502, 0xe5b18ad85e4d3e33, 0xc3f3479b6664b931, 0xa4f17865299e21e6, 0x3f7ef5b332fa1c6e, 0x875bedb5dab06119, 0x9b5a06ea2e23b93, 0x43d48296fb26}}

	var affine_xR_A = xR_A.ToAffine()
	if !sageAffine_xR_A.VartimeEq(affine_xR_A) {
		t.Error("Expected \n", sageAffine_xR_A, "\nfound\n", affine_xR_A)
	}

	var affine_xR_B = xR_B.ToAffine()
	if !sageAffine_xR_B.VartimeEq(affine_xR_B) {
		t.Error("Expected \n", sageAffine_xR_B, "\nfound\n", affine_xR_B)
	}
}

var keygenBenchPubKeyAlice SIDHPublicKeyAlice
var keygenBenchPubKeyBob SIDHPublicKeyBob

func BenchmarkAliceKeyGen(b *testing.B) {
	for n := 0; n < b.N; n++ {
		GenerateAliceKeypair(rand.Reader)
	}
}

func BenchmarkAliceKeyGenSlow(b *testing.B) {
	// m_A = 2*randint(0,2^371)
	var m_A = [48]uint8{248, 31, 9, 39, 165, 125, 79, 135, 70, 97, 87, 231, 221, 204, 245, 38, 150, 198, 187, 184, 199, 148, 156, 18, 137, 71, 248, 83, 111, 170, 138, 61, 112, 25, 188, 197, 132, 151, 1, 0, 207, 178, 24, 72, 171, 22, 11, 0}

	var aliceSecretKey = SIDHSecretKeyAlice{Scalar: m_A}

	for n := 0; n < b.N; n++ {
		keygenBenchPubKeyAlice = aliceKeyGenSlow(&aliceSecretKey)
	}
}

func BenchmarkBobKeyGen(b *testing.B) {
	for n := 0; n < b.N; n++ {
		GenerateBobKeypair(rand.Reader)
	}
}

func BenchmarkBobKeyGenSlow(b *testing.B) {
	// m_B = 3*randint(0,3^238)
	var m_B = [48]uint8{246, 217, 158, 190, 100, 227, 224, 181, 171, 32, 120, 72, 92, 115, 113, 62, 103, 57, 71, 252, 166, 121, 126, 201, 55, 99, 213, 234, 243, 228, 171, 68, 9, 239, 214, 37, 255, 242, 217, 180, 25, 54, 242, 61, 101, 245, 78, 0}

	var bobSecretKey = SIDHSecretKeyBob{Scalar: m_B}

	for n := 0; n < b.N; n++ {
		keygenBenchPubKeyBob = bobKeyGenSlow(&bobSecretKey)
	}
}

var benchSharedSecretAlicePublic = SIDHPublicKeyAlice{affine_xP: ExtensionFieldElement{A: Fp751Element{0xea6b2d1e2aebb250, 0x35d0b205dc4f6386, 0xb198e93cb1830b8d, 0x3b5b456b496ddcc6, 0x5be3f0d41132c260, 0xce5f188807516a00, 0x54f3e7469ea8866d, 0x33809ef47f36286, 0x6fa45f83eabe1edb, 0x1b3391ae5d19fd86, 0x1e66daf48584af3f, 0xb430c14aaa87}, B: Fp751Element{0x97b41ebc61dcb2ad, 0x80ead31cb932f641, 0x40a940099948b642, 0x2a22fd16cdc7fe84, 0xaabf35b17579667f, 0x76c1d0139feb4032, 0x71467e1e7b1949be, 0x678ca8dadd0d6d81, 0x14445daea9064c66, 0x92d161eab4fa4691, 0x8dfbb01b6b238d36, 0x2e3718434e4e}}, affine_xQ: ExtensionFieldElement{A: Fp751Element{0xb055cf0ca1943439, 0xa9ff5de2fa6c69ed, 0x4f2761f934e5730a, 0x61a1dcaa1f94aa4b, 0xce3c8fadfd058543, 0xeac432aaa6701b8e, 0x8491d523093aea8b, 0xba273f9bd92b9b7f, 0xd8f59fd34439bb5a, 0xdc0350261c1fe600, 0x99375ab1eb151311, 0x14d175bbdbc5}, B: Fp751Element{0xffb0ef8c2111a107, 0x55ceca3825991829, 0xdbf8a1ccc075d34b, 0xb8e9187bd85d8494, 0x670aa2d5c34a03b0, 0xef9fe2ed2b064953, 0xc911f5311d645aee, 0xf4411f409e410507, 0x934a0a852d03e1a8, 0xe6274e67ae1ad544, 0x9f4bc563c69a87bc, 0x6f316019681e}}, affine_xQmP: ExtensionFieldElement{A: Fp751Element{0x6ffb44306a153779, 0xc0ffef21f2f918f3, 0x196c46d35d77f778, 0x4a73f80452edcfe6, 0x9b00836bce61c67f, 0x387879418d84219e, 0x20700cf9fc1ec5d1, 0x1dfe2356ec64155e, 0xf8b9e33038256b1c, 0xd2aaf2e14bada0f0, 0xb33b226e79a4e313, 0x6be576fad4e5}, B: Fp751Element{0x7db5dbc88e00de34, 0x75cc8cb9f8b6e11e, 0x8c8001c04ebc52ac, 0x67ef6c981a0b5a94, 0xc3654fbe73230738, 0xc6a46ee82983ceca, 0xed1aa61a27ef49f0, 0x17fe5a13b0858fe0, 0x9ae0ca945a4c6b3c, 0x234104a218ad8878, 0xa619627166104394, 0x556a01ff2e7e}}}

var benchSharedSecretBobPublic = SIDHPublicKeyBob{affine_xP: ExtensionFieldElement{A: Fp751Element{0x6e1b8b250595b5fb, 0x800787f5197d963b, 0x6f4a4e314162a8a4, 0xe75cba4d37c02128, 0x2212e7579817a216, 0xd8a5fdb0ab2f843c, 0x44230c9f998cfd6c, 0x311ff789b26aa292, 0x73d05c379ff53e40, 0xddd8f5a223bad56c, 0x94b611e6e931c8b5, 0x4d6b9bfe3555}, B: Fp751Element{0x1a3686cfc8381294, 0x57f089b14f639cc4, 0xdb6a1565f2f5cabe, 0x83d67e8f6a02f215, 0x1946272593815e87, 0x2d839631785ca74c, 0xf149dcb2dee2bee, 0x705acd79efe405bf, 0xae3769b67687fbed, 0xacd5e29f2c203cb0, 0xdd91f08fa3153e08, 0x5a9ad8cb7400}}, affine_xQ: ExtensionFieldElement{A: Fp751Element{0xd30ed48b8c0d0c4a, 0x949cad95959ec462, 0x188675581e9d1f2a, 0xf57ed3233d33031c, 0x564c6532f7283ce7, 0x80cbef8ee3b66ecb, 0x5c687359315f22ce, 0x1da950f8671fac50, 0x6fa6c045f513ef6, 0x25ffc65a8da12d4a, 0x8b0f4ac0f5244f23, 0xadcb0e07fd92}, B: Fp751Element{0x37a43cd933ebfec4, 0x2a2806ef28dacf84, 0xd671fe718611b71e, 0xef7d73f01a676326, 0x99db1524e5799cf2, 0x860271dfbf67ff62, 0xedc2a0a14114bcf, 0x6c7b9b14b1264e5a, 0xf52de61707dc38b4, 0xccddb13fcc691f5a, 0x80f37a1220163920, 0x6a9175b9d5a1}}, affine_xQmP: ExtensionFieldElement{A: Fp751Element{0xf08af9e695c626da, 0x7a4b4d52b54e1b38, 0x980272cd4c8b8c10, 0x1afcb6151d113176, 0xaef7dbd877c00f0c, 0xe8a5ea89078700c3, 0x520c1901aa8323fa, 0xfba049c947f3383a, 0x1c38abcab48be9af, 0x9f1212b923481ea, 0x1522da3457a7c293, 0xb746f78e3a61}, B: Fp751Element{0x48010d0b48491128, 0x6d1c5c509f99f450, 0xaa3522330e3a8a62, 0x872aaf46193b2bb2, 0xc89260a2d8508973, 0x98bbbebf5524be83, 0x35711d01d895c217, 0x5e44e09ec506ed7, 0xac653a760ef6fd58, 0x5837954e30ad688d, 0xcbd3e9a1b5661da8, 0x15547f5d091a}}}

func BenchmarkSharedSecretAlice(b *testing.B) {
	// m_A = 2*randint(0,2^371)
	var m_A = [48]uint8{248, 31, 9, 39, 165, 125, 79, 135, 70, 97, 87, 231, 221, 204, 245, 38, 150, 198, 187, 184, 199, 148, 156, 18, 137, 71, 248, 83, 111, 170, 138, 61, 112, 25, 188, 197, 132, 151, 1, 0, 207, 178, 24, 72, 171, 22, 11, 0}

	var aliceSecret = SIDHSecretKeyAlice{Scalar: m_A}

	for n := 0; n < b.N; n++ {
		aliceSecret.SharedSecret(&benchSharedSecretBobPublic)
	}
}

func BenchmarkSharedSecretAliceSlow(b *testing.B) {
	// m_A = 2*randint(0,2^371)
	var m_A = [48]uint8{248, 31, 9, 39, 165, 125, 79, 135, 70, 97, 87, 231, 221, 204, 245, 38, 150, 198, 187, 184, 199, 148, 156, 18, 137, 71, 248, 83, 111, 170, 138, 61, 112, 25, 188, 197, 132, 151, 1, 0, 207, 178, 24, 72, 171, 22, 11, 0}

	var aliceSecret = SIDHSecretKeyAlice{Scalar: m_A}

	for n := 0; n < b.N; n++ {
		aliceSharedSecretSlow(&benchSharedSecretBobPublic, &aliceSecret)
	}
}

func BenchmarkSharedSecretBob(b *testing.B) {
	// m_B = 3*randint(0,3^238)
	var m_B = [48]uint8{246, 217, 158, 190, 100, 227, 224, 181, 171, 32, 120, 72, 92, 115, 113, 62, 103, 57, 71, 252, 166, 121, 126, 201, 55, 99, 213, 234, 243, 228, 171, 68, 9, 239, 214, 37, 255, 242, 217, 180, 25, 54, 242, 61, 101, 245, 78, 0}

	var bobSecret = SIDHSecretKeyBob{Scalar: m_B}

	for n := 0; n < b.N; n++ {
		bobSecret.SharedSecret(&benchSharedSecretAlicePublic)
	}
}

func BenchmarkSharedSecretBobSlow(b *testing.B) {
	// m_B = 3*randint(0,3^238)
	var m_B = [48]uint8{246, 217, 158, 190, 100, 227, 224, 181, 171, 32, 120, 72, 92, 115, 113, 62, 103, 57, 71, 252, 166, 121, 126, 201, 55, 99, 213, 234, 243, 228, 171, 68, 9, 239, 214, 37, 255, 242, 217, 180, 25, 54, 242, 61, 101, 245, 78, 0}

	var bobSecret = SIDHSecretKeyBob{Scalar: m_B}

	for n := 0; n < b.N; n++ {
		bobSharedSecretSlow(&benchSharedSecretAlicePublic, &bobSecret)
	}
}
