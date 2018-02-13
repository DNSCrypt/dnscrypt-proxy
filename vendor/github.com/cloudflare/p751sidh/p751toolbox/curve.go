package p751toolbox

// A point on the projective line P^1(F_{p^2}).
//
// This is used to work projectively with the curve coefficients.
type ProjectiveCurveParameters struct {
	A ExtensionFieldElement
	C ExtensionFieldElement
}

func (params *ProjectiveCurveParameters) FromAffine(a *ExtensionFieldElement) {
	params.A = *a
	params.C = oneExtensionField
}

type CachedCurveParameters struct {
	Aplus2C ExtensionFieldElement
	C4      ExtensionFieldElement
}

// = 256
var const256 = ExtensionFieldElement{
	A: Fp751Element{0x249ad67, 0x0, 0x0, 0x0, 0x0, 0x730000000000000, 0x738154969973da8b, 0x856657c146718c7f, 0x461860e4e363a697, 0xf9fd6510bba838cd, 0x4e1a3c3f06993c0c, 0x55abef5b75c7},
	B: Fp751Element{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
}

// Recover the curve parameters from three points on the curve.
func RecoverCurveParameters(affine_xP, affine_xQ, affine_xQmP *ExtensionFieldElement) ProjectiveCurveParameters {
	var curveParams ProjectiveCurveParameters
	var t0, t1 ExtensionFieldElement
	t0.One()                               // = 1
	t1.Mul(affine_xP, affine_xQ)           // = x_P * x_Q
	t0.Sub(&t0, &t1)                       // = 1 - x_P * x_Q
	t1.Mul(affine_xP, affine_xQmP)         // = x_P * x_{Q-P}
	t0.Sub(&t0, &t1)                       // = 1 - x_P * x_Q - x_P * x_{Q-P}
	t1.Mul(affine_xQ, affine_xQmP)         // = x_Q * x_{Q-P}
	t0.Sub(&t0, &t1)                       // = 1 - x_P * x_Q - x_P * x_{Q-P} - x_Q * x_{Q-P}
	curveParams.A.Square(&t0)              // = (1 - x_P * x_Q - x_P * x_{Q-P} - x_Q * x_{Q-P})^2
	t1.Mul(&t1, affine_xP)                 // = x_P * x_Q * x_{Q-P}
	t1.Add(&t1, &t1)                       // = 2 * x_P * x_Q * x_{Q-P}
	curveParams.C.Add(&t1, &t1)            // = 4 * x_P * x_Q * x_{Q-P}
	t0.Add(affine_xP, affine_xQ)           // = x_P + x_Q
	t0.Add(&t0, affine_xQmP)               // = x_P + x_Q + x_{Q-P}
	t1.Mul(&curveParams.C, &t0)            // = 4 * x_P * x_Q * x_{Q-P} * (x_P + x_Q + x_{Q-P})
	curveParams.A.Sub(&curveParams.A, &t1) // = (1 - x_P * x_Q - x_P * x_{Q-P} - x_Q * x_{Q-P})^2 - 4 * x_P * x_Q * x_{Q-P} * (x_P + x_Q + x_{Q-P})

	return curveParams
}

// Compute the j-invariant (not the J-invariant) of the given curve.
func (curveParams *ProjectiveCurveParameters) JInvariant() ExtensionFieldElement {
	var v0, v1, v2, v3 ExtensionFieldElement
	A := &curveParams.A
	C := &curveParams.C
	v0.Square(C)           // C^2
	v1.Square(A)           // A^2
	v2.Add(&v0, &v0)       // 2C^2
	v3.Add(&v2, &v0)       // 3C^2
	v2.Add(&v2, &v2)       // 4C^2
	v2.Sub(&v1, &v2)       // A^2 - 4C^2
	v1.Sub(&v1, &v3)       // A^2 - 3C^2
	v3.Square(&v1)         // (A^2 - 3C^2)^2
	v3.Mul(&v3, &v1)       // (A^2 - 3C^2)^3
	v0.Square(&v0)         // C^4
	v3.Mul(&v3, &const256) // 256(A^2 - 3C^2)^3
	v2.Mul(&v2, &v0)       // C^4(A^2 - 4C^2)
	v2.Inv(&v2)            // 1/C^4(A^2 - 4C^2)
	v0.Mul(&v3, &v2)       // 256(A^2 - 3C^2)^3 / C^4(A^2 - 4C^2)
	return v0
}

// Compute cached parameters A + 2C, 4C.
func (curve *ProjectiveCurveParameters) cachedParams() CachedCurveParameters {
	var cached CachedCurveParameters
	cached.Aplus2C.Add(&curve.C, &curve.C)          // = 2*C
	cached.C4.Add(&cached.Aplus2C, &cached.Aplus2C) // = 4*C
	cached.Aplus2C.Add(&cached.Aplus2C, &curve.A)   // = 2*C + A
	return cached
}

// A point on the projective line P^1(F_{p^2}).
//
// This represents a point on the (Kummer line) of a Montgomery curve.  The
// curve is specified by a ProjectiveCurveParameters struct.
type ProjectivePoint struct {
	X ExtensionFieldElement
	Z ExtensionFieldElement
}

// A point on the projective line P^1(F_p).
//
// This represents a point on the (Kummer line) of the prime-field subgroup of
// the base curve E_0(F_p), defined by E_0 : y^2 = x^3 + x.
type ProjectivePrimeFieldPoint struct {
	X PrimeFieldElement
	Z PrimeFieldElement
}

func (point *ProjectivePoint) FromAffinePrimeField(x *PrimeFieldElement) {
	point.X.A = x.A
	point.X.B = zeroExtensionField.B
	point.Z = oneExtensionField
}

func (point *ProjectivePoint) FromAffine(x *ExtensionFieldElement) {
	point.X = *x
	point.Z = oneExtensionField
}

func (point *ProjectivePrimeFieldPoint) FromAffine(x *PrimeFieldElement) {
	point.X = *x
	point.Z = onePrimeField
}

func (point *ProjectivePoint) ToAffine() *ExtensionFieldElement {
	affine_x := new(ExtensionFieldElement)
	affine_x.Inv(&point.Z).Mul(affine_x, &point.X)
	return affine_x
}

func (point *ProjectivePrimeFieldPoint) ToAffine() *PrimeFieldElement {
	affine_x := new(PrimeFieldElement)
	affine_x.Inv(&point.Z).Mul(affine_x, &point.X)
	return affine_x
}

func (lhs *ProjectivePoint) VartimeEq(rhs *ProjectivePoint) bool {
	var t0, t1 ExtensionFieldElement
	t0.Mul(&lhs.X, &rhs.Z)
	t1.Mul(&lhs.Z, &rhs.X)
	return t0.VartimeEq(&t1)
}

func (lhs *ProjectivePrimeFieldPoint) VartimeEq(rhs *ProjectivePrimeFieldPoint) bool {
	var t0, t1 PrimeFieldElement
	t0.Mul(&lhs.X, &rhs.Z)
	t1.Mul(&lhs.Z, &rhs.X)
	return t0.VartimeEq(&t1)
}

func ProjectivePointConditionalSwap(xP, xQ *ProjectivePoint, choice uint8) {
	ExtensionFieldConditionalSwap(&xP.X, &xQ.X, choice)
	ExtensionFieldConditionalSwap(&xP.Z, &xQ.Z, choice)
}

func ProjectivePrimeFieldPointConditionalSwap(xP, xQ *ProjectivePrimeFieldPoint, choice uint8) {
	PrimeFieldConditionalSwap(&xP.X, &xQ.X, choice)
	PrimeFieldConditionalSwap(&xP.Z, &xQ.Z, choice)
}

// Given xP = x(P), xQ = x(Q), and xPmQ = x(P-Q), compute xR = x(P+Q).
//
// Returns xR to allow chaining.  Safe to overlap xP, xQ, xR.
func (xR *ProjectivePoint) Add(xP, xQ, xPmQ *ProjectivePoint) *ProjectivePoint {
	// Algorithm 1 of Costello-Smith.
	var v0, v1, v2, v3, v4 ExtensionFieldElement
	v0.Add(&xP.X, &xP.Z)               // X_P + Z_P
	v1.Sub(&xQ.X, &xQ.Z).Mul(&v1, &v0) // (X_Q - Z_Q)(X_P + Z_P)
	v0.Sub(&xP.X, &xP.Z)               // X_P - Z_P
	v2.Add(&xQ.X, &xQ.Z).Mul(&v2, &v0) // (X_Q + Z_Q)(X_P - Z_P)
	v3.Add(&v1, &v2).Square(&v3)       // 4(X_Q X_P - Z_Q Z_P)^2
	v4.Sub(&v1, &v2).Square(&v4)       // 4(X_Q Z_P - Z_Q X_P)^2
	v0.Mul(&xPmQ.Z, &v3)               // 4X_{P-Q}(X_Q X_P - Z_Q Z_P)^2
	xR.Z.Mul(&xPmQ.X, &v4)             // 4Z_{P-Q}(X_Q Z_P - Z_Q X_P)^2
	xR.X = v0
	return xR
}

// Given xP = x(P), xQ = x(Q), and xPmQ = x(P-Q), compute xR = x(P+Q).
//
// Returns xR to allow chaining.  Safe to overlap xP, xQ, xR.
func (xR *ProjectivePrimeFieldPoint) Add(xP, xQ, xPmQ *ProjectivePrimeFieldPoint) *ProjectivePrimeFieldPoint {
	// Algorithm 1 of Costello-Smith.
	var v0, v1, v2, v3, v4 PrimeFieldElement
	v0.Add(&xP.X, &xP.Z)               // X_P + Z_P
	v1.Sub(&xQ.X, &xQ.Z).Mul(&v1, &v0) // (X_Q - Z_Q)(X_P + Z_P)
	v0.Sub(&xP.X, &xP.Z)               // X_P - Z_P
	v2.Add(&xQ.X, &xQ.Z).Mul(&v2, &v0) // (X_Q + Z_Q)(X_P - Z_P)
	v3.Add(&v1, &v2).Square(&v3)       // 4(X_Q X_P - Z_Q Z_P)^2
	v4.Sub(&v1, &v2).Square(&v4)       // 4(X_Q Z_P - Z_Q X_P)^2
	v0.Mul(&xPmQ.Z, &v3)               // 4X_{P-Q}(X_Q X_P - Z_Q Z_P)^2
	xR.Z.Mul(&xPmQ.X, &v4)             // 4Z_{P-Q}(X_Q Z_P - Z_Q X_P)^2
	xR.X = v0
	return xR
}

// Given xP = x(P) and cached curve parameters Aplus2C = A + 2*C, C4 = 4*C, compute xQ = x([2]P).
//
// Returns xQ to allow chaining.  Safe to overlap xP, xQ.
func (xQ *ProjectivePoint) Double(xP *ProjectivePoint, curve *CachedCurveParameters) *ProjectivePoint {
	// Algorithm 2 of Costello-Smith, amended to work with projective curve coefficients.
	var v1, v2, v3, xz4 ExtensionFieldElement
	v1.Add(&xP.X, &xP.Z).Square(&v1) // (X+Z)^2
	v2.Sub(&xP.X, &xP.Z).Square(&v2) // (X-Z)^2
	xz4.Sub(&v1, &v2)                // 4XZ = (X+Z)^2 - (X-Z)^2
	v2.Mul(&v2, &curve.C4)           // 4C(X-Z)^2
	xQ.X.Mul(&v1, &v2)               // 4C(X+Z)^2(X-Z)^2
	v3.Mul(&xz4, &curve.Aplus2C)     // 4XZ(A + 2C)
	v3.Add(&v3, &v2)                 // 4XZ(A + 2C) + 4C(X-Z)^2
	xQ.Z.Mul(&v3, &xz4)              // (4XZ(A + 2C) + 4C(X-Z)^2)4XZ
	// Now (xQ.x : xQ.z)
	//   = (4C(X+Z)^2(X-Z)^2 : (4XZ(A + 2C) + 4C(X-Z)^2)4XZ )
	//   = ((X+Z)^2(X-Z)^2 : (4XZ((A + 2C)/4C) + (X-Z)^2)4XZ )
	//   = ((X+Z)^2(X-Z)^2 : (4XZ((a + 2)/4) + (X-Z)^2)4XZ )
	return xQ
}

// Given xP = x(P) and cached curve parameter aPlus2Over4 = (a+2)/4, compute xQ = x([2]P).
//
// Note that we don't use projective curve coefficients here because we only
// ever use a fixed curve (in our case, the base curve E_0).
//
// Returns xQ to allow chaining.  Safe to overlap xP, xQ.
func (xQ *ProjectivePrimeFieldPoint) Double(xP *ProjectivePrimeFieldPoint, aPlus2Over4 *PrimeFieldElement) *ProjectivePrimeFieldPoint {
	// Algorithm 2 of Costello-Smith
	var v1, v2, v3, xz4 PrimeFieldElement
	v1.Add(&xP.X, &xP.Z).Square(&v1) // (X+Z)^2
	v2.Sub(&xP.X, &xP.Z).Square(&v2) // (X-Z)^2
	xz4.Sub(&v1, &v2)                // 4XZ = (X+Z)^2 - (X-Z)^2
	xQ.X.Mul(&v1, &v2)               // (X+Z)^2(X-Z)^2
	v3.Mul(&xz4, aPlus2Over4)        // 4XZ((a+2)/4)
	v3.Add(&v3, &v2)                 // 4XZ((a+2)/4) + (X-Z)^2
	xQ.Z.Mul(&v3, &xz4)              // (4XZ((a+2)/4) + (X-Z)^2)4XZ
	// Now (xQ.x : xQ.z)
	//   = ((X+Z)^2(X-Z)^2 : (4XZ((a + 2)/4) + (X-Z)^2)4XZ )
	return xQ
}

// Given the curve parameters, xP = x(P), and k >= 0, compute xQ = x([2^k]P).
//
// Returns xQ to allow chaining.  Safe to overlap xP, xQ.
func (xQ *ProjectivePoint) Pow2k(curve *ProjectiveCurveParameters, xP *ProjectivePoint, k uint32) *ProjectivePoint {
	cachedParams := curve.cachedParams()
	*xQ = *xP
	for i := uint32(0); i < k; i++ {
		xQ.Double(xQ, &cachedParams)
	}

	return xQ
}

// Given xP = x(P) and cached curve parameters Aplus2C = A + 2*C, C4 = 4*C, compute xQ = x([3]P).
//
// Returns xQ to allow chaining.  Safe to overlap xP, xQ.
func (xQ *ProjectivePoint) Triple(xP *ProjectivePoint, curve *CachedCurveParameters) *ProjectivePoint {
	// Uses the efficient Montgomery tripling formulas from Costello-Longa-Naehrig.
	var v0, v1, v2, v3, v4, v5 ExtensionFieldElement
	// Compute (X_2 : Z_2) = x([2]P)
	v2.Sub(&xP.X, &xP.Z)           // X - Z
	v3.Add(&xP.X, &xP.Z)           // X + Z
	v0.Square(&v2)                 // (X-Z)^2
	v1.Square(&v3)                 // (X+Z)^2
	v4.Mul(&v0, &curve.C4)         // 4C(X-Z)^2
	v5.Mul(&v4, &v1)               // 4C(X-Z)^2(X+Z)^2 = X_2
	v1.Sub(&v1, &v0)               // (X+Z)^2 - (X-Z)^2 = 4XZ
	v0.Mul(&v1, &curve.Aplus2C)    // 4XZ(A+2C)
	v4.Add(&v4, &v0).Mul(&v4, &v1) // (4C(X-Z)^2 + 4XZ(A+2C))4XZ = Z_2
	// Compute (X_3 : Z_3) = x(P + [2]P)
	v0.Add(&v5, &v4).Mul(&v0, &v2) // (X_2 + Z_2)(X-Z)
	v1.Sub(&v5, &v4).Mul(&v1, &v3) // (X_2 - Z_2)(X+Z)
	v4.Sub(&v0, &v1).Square(&v4)   // 4(XZ_2 - ZX_2)^2
	v5.Add(&v0, &v1).Square(&v5)   // 4(XX_2 - ZZ_2)^2
	v2.Mul(&xP.Z, &v5)             // 4Z(XX_2 - ZZ_2)^2
	xQ.Z.Mul(&xP.X, &v4)           // 4X(XZ_2 - ZX_2)^2
	xQ.X = v2
	return xQ
}

// Given the curve parameters, xP = x(P), and k >= 0, compute xQ = x([2^k]P).
//
// Returns xQ to allow chaining.  Safe to overlap xP, xQ.
func (xQ *ProjectivePoint) Pow3k(curve *ProjectiveCurveParameters, xP *ProjectivePoint, k uint32) *ProjectivePoint {
	cachedParams := curve.cachedParams()
	*xQ = *xP
	for i := uint32(0); i < k; i++ {
		xQ.Triple(xQ, &cachedParams)
	}

	return xQ
}

// Given x(P) and a scalar m in little-endian bytes, compute x([m]P) using the
// Montgomery ladder.  This is described in Algorithm 8 of Costello-Smith.
//
// This function's execution time is dependent only on the byte-length of the
// input scalar.  All scalars of the same input length execute in uniform time.
// The scalar can be padded with zero bytes to ensure a uniform length.
//
// Safe to overlap the source with the destination.
func (xQ *ProjectivePoint) ScalarMult(curve *ProjectiveCurveParameters, xP *ProjectivePoint, scalar []uint8) *ProjectivePoint {
	cachedParams := curve.cachedParams()
	var x0, x1, tmp ProjectivePoint

	x0.X.One()
	x0.Z.Zero()
	x1 = *xP

	// Iterate over the bits of the scalar, top to bottom
	prevBit := uint8(0)
	for i := len(scalar) - 1; i >= 0; i-- {
		scalarByte := scalar[i]
		for j := 7; j >= 0; j-- {
			bit := (scalarByte >> uint(j)) & 0x1
			ProjectivePointConditionalSwap(&x0, &x1, (bit ^ prevBit))
			tmp.Double(&x0, &cachedParams)
			x1.Add(&x0, &x1, xP)
			x0 = tmp
			prevBit = bit
		}
	}
	// now prevBit is the lowest bit of the scalar
	ProjectivePointConditionalSwap(&x0, &x1, prevBit)
	*xQ = x0
	return xQ
}

// Given x(P) and a scalar m in little-endian bytes, compute x([m]P), x([m+1]P) using the
// Montgomery ladder.  This is described in Algorithm 8 of Costello-Smith.
//
// The extra value x([m+1]P) is returned to allow y-coordinate recovery;
// otherwise, it can be ignored.
//
// This function's execution time is dependent only on the byte-length of the
// input scalar.  All scalars of the same input length execute in uniform time.
// The scalar can be padded with zero bytes to ensure a uniform length.
func ScalarMultPrimeField(aPlus2Over4 *PrimeFieldElement, xP *ProjectivePrimeFieldPoint, scalar []uint8) (ProjectivePrimeFieldPoint, ProjectivePrimeFieldPoint) {
	var x0, x1, tmp ProjectivePrimeFieldPoint

	x0.X.One()
	x0.Z.Zero()
	x1 = *xP

	// Iterate over the bits of the scalar, top to bottom
	prevBit := uint8(0)
	for i := len(scalar) - 1; i >= 0; i-- {
		scalarByte := scalar[i]
		for j := 7; j >= 0; j-- {
			bit := (scalarByte >> uint(j)) & 0x1
			ProjectivePrimeFieldPointConditionalSwap(&x0, &x1, (bit ^ prevBit))
			tmp.Double(&x0, aPlus2Over4)
			x1.Add(&x0, &x1, xP)
			x0 = tmp
			prevBit = bit
		}
	}
	// now prevBit is the lowest bit of the scalar
	ProjectivePrimeFieldPointConditionalSwap(&x0, &x1, prevBit)
	return x0, x1
}

// Given P = (x_P, y_P) in affine coordinates, as well as projective points
// x(Q), x(R) = x(P+Q), all in the prime-field subgroup of the starting curve
// E_0(F_p), use the Okeya-Sakurai coordinate recovery strategy to recover Q =
// (X_Q : Y_Q : Z_Q).
//
// This is Algorithm 5 of Costello-Smith, with the constants a = 0, b = 1 hardcoded.
func OkeyaSakuraiCoordinateRecovery(affine_xP, affine_yP *PrimeFieldElement, xQ, xR *ProjectivePrimeFieldPoint) (X_Q, Y_Q, Z_Q PrimeFieldElement) {
	var v1, v2, v3, v4 PrimeFieldElement
	v1.Mul(affine_xP, &xQ.Z)       // = x_P*Z_Q
	v2.Add(&xQ.X, &v1)             // = X_Q + x_P*Z_Q
	v3.Sub(&xQ.X, &v1).Square(&v3) // = (X_Q - x_P*Z_Q)^2
	v3.Mul(&v3, &xR.X)             // = X_R*(X_Q - x_P*Z_Q)^2
	// Skip setting v1 = 2a*Z_Q (step 6) since we hardcode a = 0
	// Skip adding v1 to v2 (step 7) since v1 is zero
	v4.Mul(affine_xP, &xQ.X) // = x_P*X_Q
	v4.Add(&v4, &xQ.Z)       // = x_P*X_Q + Z_Q
	v2.Mul(&v2, &v4)         // = (x_P*X_Q + Z_Q)*(X_Q + x_P*Z_Q)
	// Skip multiplication by v1 (step 11) since v1 is zero
	// Skip subtracting v1 from v2 (step 12) since v1 is zero
	v2.Mul(&v2, &xR.Z)                 // = (x_P*X_Q + Z_Q)*(X_Q + x_P*Z_Q)*Z_R
	Y_Q.Sub(&v2, &v3)                  // = (x_P*X_Q + Z_Q)*(X_Q + x_P*Z_Q)*Z_R - X_R*(X_Q - x_P*Z_Q)^2
	v1.Add(affine_yP, affine_yP)       // = 2b*y_P
	v1.Mul(&v1, &xQ.Z).Mul(&v1, &xR.Z) // = 2b*y_P*Z_Q*Z_R
	X_Q.Mul(&v1, &xQ.X)                // = 2b*y_P*Z_Q*Z_R*X_Q
	Z_Q.Mul(&v1, &xQ.Z)                // = 2b*y_P*Z_Q^2*Z_R

	return
}

// Given x(P), x(Q), x(P-Q), as well as a scalar m in little-endian bytes,
// compute x(P + [m]Q) using the "three-point ladder" of de Feo, Jao, and Plut.
//
// Safe to overlap the source with the destination.
//
// This function's execution time is dependent only on the byte-length of the
// input scalar.  All scalars of the same input length execute in uniform time.
// The scalar can be padded with zero bytes to ensure a uniform length.
//
// The algorithm, as described in de Feo-Jao-Plut, is as follows:
//
// (x0, x1, x2) <--- (x(O), x(Q), x(P))
//
// for i = |m| down to 0, indexing the bits of m:
//     Invariant: (x0, x1, x2) == (x( [t]Q ), x( [t+1]Q ), x( P + [t]Q ))
//          where t = m//2^i is the high bits of m, starting at i
//     if m_i == 0:
//         (x0, x1, x2) <--- (xDBL(x0), xADD(x1, x0, x(Q)), xADD(x2, x0, x(P)))
//         Invariant: (x0, x1, x2) == (x( [2t]Q ), x( [2t+1]Q ), x( P + [2t]Q ))
//                                 == (x( [t']Q ), x( [t'+1]Q ), x( P + [t']Q ))
//              where t' = m//2^{i-1} is the high bits of m, starting at i-1
//     if m_i == 1:
//         (x0, x1, x2) <--- (xADD(x1, x0, x(Q)), xDBL(x1), xADD(x2, x1, x(P-Q)))
//         Invariant: (x0, x1, x2) == (x( [2t+1]Q ), x( [2t+2]Q ), x( P + [2t+1]Q ))
//                                 == (x( [t']Q ),   x( [t'+1]Q ), x( P + [t']Q ))
//              where t' = m//2^{i-1} is the high bits of m, starting at i-1
// return x2
//
// Notice that the roles of (x0,x1) and (x(P), x(P-Q)) swap depending on the
// current bit of the scalar.  Instead of swapping which operations we do, we
// can swap variable names, producing the following uniform algorithm:
//
// (x0, x1, x2) <--- (x(O), x(Q), x(P))
// (y0, y1) <--- (x(P), x(P-Q))
//
// for i = |m| down to 0, indexing the bits of m:
//      (x0, x1) <--- SWAP( m_{i+1} xor m_i, (x0,x1) )
//      (y0, y1) <--- SWAP( m_{i+1} xor m_i, (y0,y1) )
//      (x0, x1, x2) <--- ( xDBL(x0), xADD(x1,x0,x(Q)), xADD(x2, x0, y0) )
//
// return x2
//
func (xR *ProjectivePoint) ThreePointLadder(curve *ProjectiveCurveParameters, xP, xQ, xPmQ *ProjectivePoint, scalar []uint8) *ProjectivePoint {
	cachedParams := curve.cachedParams()
	var x0, x1, x2, y0, y1, tmp ProjectivePoint

	// (x0, x1, x2) <--- (x(O), x(Q), x(P))
	x0.X.One()
	x0.Z.Zero()
	x1 = *xQ
	x2 = *xP
	// (y0, y1) <--- (x(P), x(P-Q))
	y0 = *xP
	y1 = *xPmQ

	// Iterate over the bits of the scalar, top to bottom
	prevBit := uint8(0)
	for i := len(scalar) - 1; i >= 0; i-- {
		scalarByte := scalar[i]
		for j := 7; j >= 0; j-- {
			bit := (scalarByte >> uint(j)) & 0x1
			ProjectivePointConditionalSwap(&x0, &x1, (bit ^ prevBit))
			ProjectivePointConditionalSwap(&y0, &y1, (bit ^ prevBit))
			x2.Add(&x2, &x0, &y0) // = xADD(x2, x0, y0)
			tmp.Double(&x0, &cachedParams)
			x1.Add(&x1, &x0, xQ) // = xADD(x1, x0, x(Q))
			x0 = tmp             // = xDBL(x0)
			prevBit = bit
		}
	}

	*xR = x2
	return xR
}

// Given the affine x-coordinate affine_xP of P, compute the x-coordinate
// x(\tau(P)-P) of \tau(P)-P.
func DistortAndDifference(affine_xP *PrimeFieldElement) ProjectivePoint {
	var xR ProjectivePoint
	var t0, t1 PrimeFieldElement
	t0.Square(affine_xP)         // = x_P^2
	t1.One().Add(&t1, &t0)       // = x_P^2 + 1
	xR.X.B = t1.A                // = 0 + (x_P^2 + 1)*i
	t0.Add(affine_xP, affine_xP) // = 2*x_P
	xR.Z.A = t0.A                // = 2*x_P + 0*i

	return xR
}

// Given an affine point P = (x_P, y_P) in the prime-field subgroup of the
// starting curve E_0(F_p), together with a secret scalar m, compute x(P+[m]Q),
// where Q = \tau(P) is the image of P under the distortion map described
// below.
//
// The computation uses basically the same strategy as the
// Costello-Longa-Naehrig implementation:
//
// 1. Use the standard Montgomery ladder to compute x([m]Q), x([m+1]Q)
//
// 2. Use Okeya-Sakurai coordinate recovery to recover [m]Q from Q, x([m]Q),
// x([m+1]Q)
//
// 3. Use P and [m]Q to compute x(P + [m]Q)
//
// The distortion map \tau is defined as
//
// \tau : E_0(F_{p^2}) ---> E_0(F_{p^2})
//
// \tau : (x,y) |---> (-x, iy).
//
// The image of the distortion map is the _trace-zero_ subgroup of E_0(F_{p^2})
// defined by Tr(P) = P + \pi_p(P) = id, where \pi_p((x,y)) = (x^p, y^p) is the
// p-power Frobenius map.  To see this, take P = (x,y) \in E_0(F_{p^2}).  Then
// Tr(P) = id if and only if \pi_p(P) = -P, so that
//
// -P = (x, -y) = (x^p, y^p) = \pi_p(P);
//
// we have x^p = x if and only if x \in F_p, while y^p = -y if and only if y =
// i*y' for y' \in F_p.
//
// Thus (excepting the identity) every point in the trace-zero subgroup is of
// the form \tau((x,y)) = (-x,i*y) for (x,y) \in E_0(F_p).
//
// Since the Montgomery ladder only uses the x-coordinate, and the x-coordinate
// is always in the prime subfield, we can compute x([m]Q), x([m+1]Q) entirely
// in the prime subfield.
//
// The affine form of the relation for Okeya-Sakurai coordinate recovery is
// given on p. 13 of Costello-Smith:
//
// y_Q = ((x_P*x_Q + 1)*(x_P + x_Q + 2*a) - 2*a - x_R*(x_P - x_Q)^2)/(2*b*y_P),
//
// where R = Q + P and a,b are the Montgomery parameters.  In our setting
// (a,b)=(0,1) and our points are P=Q, Q=[m]Q, P+Q=[m+1]Q, so this becomes
//
// y_{mQ} = ((x_Q*x_{mQ} + 1)*(x_Q + x_{mQ}) - x_{m1Q}*(x_Q - x_{mQ})^2)/(2*y_Q)
//
// y_{mQ} = ((1 - x_P*x_{mQ})*(x_{mQ} - x_P) - x_{m1Q}*(x_P + x_{mQ})^2)/(2*y_P*i)
//
// y_{mQ} = i*((1 - x_P*x_{mQ})*(x_{mQ} - x_P) - x_{m1Q}*(x_P + x_{mQ})^2)/(-2*y_P)
//
// since (x_Q, y_Q) = (-x_P, y_P*i).  In projective coordinates this is
//
// Y_{mQ}' = ((Z_{mQ} - x_P*X_{mQ})*(X_{mQ} - x_P*Z_{mQ})*Z_{m1Q}
//          - X_{m1Q}*(X_{mQ} + x_P*Z_{mQ})^2)
//
// with denominator
//
// Z_{mQ}' = (-2*y_P*Z_{mQ}*Z_{m1Q})*Z_{mQ}.
//
// Setting
//
// X_{mQ}' = (-2*y_P*Z_{mQ}*Z_{m1Q})*X_{mQ}
//
// gives [m]Q = (X_{mQ}' : i*Y_{mQ}' : Z_{mQ}') with X,Y,Z all in F_p.  (Here
// the ' just denotes that we've added extra terms to the denominators during
// the computation of Y)
//
// To compute the x-coordinate x(P+[m]Q) from P and [m]Q, we use the affine
// addition formulas of section 2.2 of Costello-Smith.  We're only interested
// in the x-coordinate, giving
//
// X_R = Z_{mQ}*(i*Y_{mQ} - y_P*Z_{mQ})^2 - (x_P*Z_{mQ} + X_{mQ})*(X_{mQ} - x_P*Z_{mQ})^2
//
// Z_R = Z_{mQ}*(X_{mQ} - x_P*Z_{mQ})^2.
//
// Notice that although X_R \in F_{p^2}, we can split the computation into
// coordinates X_R = X_{R,a} + X_{R,b}*i as
//
// (i*Y_{mQ} - y_P*Z_{mQ})^2 = (y_P*Z_{mQ})^2 - Y_{mQ}^2 - 2*y_P*Z_{mQ}*Y_{mQ}*i,
//
// giving
//
// X_{R,a} = Z_{mQ}*((y_P*Z_{mQ})^2 - Y_{mQ}^2)
//         - (x_P*Z_{mQ} + X_{mQ})*(X_{mQ} - x_P*Z_{mQ})^2
//
// X_{R,b} = -2*y_P*Y_{mQ}*Z_{mQ}^2
//
// Z_R = Z_{mQ}*(X_{mQ} - x_P*Z_{mQ})^2.
//
// These formulas could probably be combined with the formulas for y-recover
// and computed more efficiently, but efficiency isn't the biggest concern
// here, since the bulk of the cost is already in the ladder.
func SecretPoint(affine_xP, affine_yP *PrimeFieldElement, scalar []uint8) ProjectivePoint {
	var xQ ProjectivePrimeFieldPoint
	xQ.FromAffine(affine_xP)
	xQ.X.Neg(&xQ.X)

	// Compute x([m]Q) = (X_{mQ} : Z_{mQ}), x([m+1]Q) = (X_{m1Q} : Z_{m1Q})
	var xmQ, xm1Q = ScalarMultPrimeField(&E0_aPlus2Over4, &xQ, scalar)

	// Now perform coordinate recovery:
	// [m]Q = (X_{mQ} : Y_{mQ}*i : Z_{mQ})
	var XmQ, YmQ, ZmQ PrimeFieldElement
	var t0, t1 PrimeFieldElement

	// Y_{mQ} = (Z_{mQ} - x_P*X_{mQ})*(X_{mQ} - x_P*Z_{mQ})*Z_{m1Q}
	//         - X_{m1Q}*(X_{mQ} + x_P*Z_{mQ})^2
	t0.Mul(affine_xP, &xmQ.X)       // = x_P*X_{mQ}
	YmQ.Sub(&xmQ.Z, &t0)            // = Z_{mQ} - x_P*X_{mQ}
	t1.Mul(affine_xP, &xmQ.Z)       // = x_P*Z_{mQ}
	t0.Sub(&xmQ.X, &t1)             // = X_{mQ} - x_P*Z_{mQ}
	YmQ.Mul(&YmQ, &t0)              // = (Z_{mQ} - x_P*X_{mQ})*(X_{mQ} - x_P*Z_{mQ})
	YmQ.Mul(&YmQ, &xm1Q.Z)          // = (Z_{mQ} - x_P*X_{mQ})*(X_{mQ} - x_P*Z_{mQ})*Z_{m1Q}
	t1.Add(&t1, &xmQ.X).Square(&t1) // = (X_{mQ} + x_P*Z_{mQ})^2
	t1.Mul(&t1, &xm1Q.X)            // = X_{m1Q}*(X_{mQ} + x_P*Z_{mQ})^2
	YmQ.Sub(&YmQ, &t1)              // = Y_{mQ}

	// Z_{mQ} = -2*(Z_{mQ}^2 * Z_{m1Q} * y_P)
	t0.Mul(&xmQ.Z, &xm1Q.Z).Mul(&t0, affine_yP) // = Z_{mQ} * Z_{m1Q} * y_P
	t0.Neg(&t0)                                 // = -1*(Z_{mQ} * Z_{m1Q} * y_P)
	t0.Add(&t0, &t0)                            // = -2*(Z_{mQ} * Z_{m1Q} * y_P)
	ZmQ.Mul(&xmQ.Z, &t0)                        // = -2*(Z_{mQ}^2 * Z_{m1Q} * y_P)

	// We added terms to the denominator Z_{mQ}, so multiply them to X_{mQ}
	// X_{mQ} = -2*X_{mQ}*Z_{mQ}*Z_{m1Q}*y_P
	XmQ.Mul(&xmQ.X, &t0)

	// Now compute x(P + [m]Q) = (X_Ra + i*X_Rb : Z_R)
	var XRa, XRb, ZR PrimeFieldElement

	XRb.Square(&ZmQ).Mul(&XRb, &YmQ) // = Y_{mQ} * Z_{mQ}^2
	XRb.Mul(&XRb, affine_yP)         // = Y_{mQ} * y_P * Z_{mQ}^2
	XRb.Add(&XRb, &XRb)              // = 2 * Y_{mQ} * y_P * Z_{mQ}^2
	XRb.Neg(&XRb)                    // = -2 * Y_{mQ} * y_P * Z_{mQ}^2

	t0.Mul(affine_yP, &ZmQ).Square(&t0) // = (y_P * Z_{mQ})^2
	t1.Square(&YmQ)                     // = Y_{mQ}^2
	XRa.Sub(&t0, &t1)                   // = (y_P * Z_{mQ})^2 - Y_{mQ}^2
	XRa.Mul(&XRa, &ZmQ)                 // = Z_{mQ}*((y_P * Z_{mQ})^2 - Y_{mQ}^2)
	t0.Mul(affine_xP, &ZmQ)             // = x_P * Z_{mQ}
	t1.Add(&XmQ, &t0)                   // = X_{mQ} + x_P*Z_{mQ}
	t0.Sub(&XmQ, &t0)                   // = X_{mQ} - x_P*Z_{mQ}
	t0.Square(&t0)                      // = (X_{mQ} - x_P*Z_{mQ})^2
	t1.Mul(&t1, &t0)                    // = (X_{mQ} + x_P*Z_{mQ})*(X_{mQ} - x_P*Z_{mQ})^2
	XRa.Sub(&XRa, &t1)                  // = Z_{mQ}*((y_P*Z_{mQ})^2 - Y_{mQ}^2) - (X_{mQ} + x_P*Z_{mQ})*(X_{mQ} - x_P*Z_{mQ})^2

	ZR.Mul(&ZmQ, &t0) // = Z_{mQ}*(X_{mQ} - x_P*Z_{mQ})^2

	var xR ProjectivePoint
	xR.X.A = XRa.A
	xR.X.B = XRb.A
	xR.Z.A = ZR.A

	return xR
}
