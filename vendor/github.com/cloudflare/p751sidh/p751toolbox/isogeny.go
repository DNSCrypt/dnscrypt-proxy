package p751toolbox

// Represents a 3-isogeny phi, holding the data necessary to evaluate phi.
type ThreeIsogeny struct {
	x ExtensionFieldElement
	z ExtensionFieldElement
}

// Given a three-torsion point x3 = x(P_3) on the curve E_(A:C), construct the
// three-isogeny phi : E_(A:C) -> E_(A:C)/<P_3> = E_(A':C').
//
// Returns a tuple (codomain, isogeny) = (E_(A':C'), phi).
func ComputeThreeIsogeny(x3 *ProjectivePoint) (ProjectiveCurveParameters, ThreeIsogeny) {
	var isogeny ThreeIsogeny
	isogeny.x = x3.X
	isogeny.z = x3.Z
	// We want to compute
	// (A':C') = (Z^4 + 18X^2Z^2 - 27X^4 : 4XZ^3)
	// To do this, use the identity 18X^2Z^2 - 27X^4 = 9X^2(2Z^2 - 3X^2)
	var codomain ProjectiveCurveParameters
	var v0, v1, v2, v3 ExtensionFieldElement
	v1.Square(&x3.X)               // = X^2
	v0.Add(&v1, &v1).Add(&v1, &v0) // = 3X^2
	v1.Add(&v0, &v0).Add(&v1, &v0) // = 9X^2
	v2.Square(&x3.Z)               // = Z^2
	v3.Square(&v2)                 // = Z^4
	v2.Add(&v2, &v2)               // = 2Z^2
	v0.Sub(&v2, &v0)               // = 2Z^2 - 3X^2
	v1.Mul(&v1, &v0)               // = 9X^2(2Z^2 - 3X^2)
	v0.Mul(&x3.X, &x3.Z)           // = XZ
	v0.Add(&v0, &v0)               // = 2XZ
	codomain.A.Add(&v3, &v1)       // = Z^4 + 9X^2(2Z^2 - 3X^2)
	codomain.C.Mul(&v0, &v2)       // = 4XZ^3

	return codomain, isogeny
}

// Given a 3-isogeny phi and a point xP = x(P), compute x(Q), the x-coordinate
// of the image Q = phi(P) of P under phi : E_(A:C) -> E_(A':C').
//
// The output xQ = x(Q) is then a point on the curve E_(A':C'); the curve
// parameters are returned by the Compute3Isogeny function used to construct
// phi.
func (phi *ThreeIsogeny) Eval(xP *ProjectivePoint) ProjectivePoint {
	var xQ ProjectivePoint
	var t0, t1, t2 ExtensionFieldElement
	t0.Mul(&phi.x, &xP.X) // = X3*XP
	t1.Mul(&phi.z, &xP.Z) // = Z3*XP
	t2.Sub(&t0, &t1)      // = X3*XP - Z3*ZP
	t0.Mul(&phi.z, &xP.X) // = Z3*XP
	t1.Mul(&phi.x, &xP.Z) // = X3*ZP
	t0.Sub(&t0, &t1)      // = Z3*XP - X3*ZP
	t2.Square(&t2)        // = (X3*XP - Z3*ZP)^2
	t0.Square(&t0)        // = (Z3*XP - X3*ZP)^2
	xQ.X.Mul(&t2, &xP.X)  // = XP*(X3*XP - Z3*ZP)^2
	xQ.Z.Mul(&t0, &xP.Z)  // = ZP*(Z3*XP - X3*ZP)^2

	return xQ
}

// Represents a 4-isogeny phi, holding the data necessary to evaluate phi.
//
// See ComputeFourIsogeny for more details.
type FourIsogeny struct {
	Xsq_plus_Zsq  ExtensionFieldElement
	Xsq_minus_Zsq ExtensionFieldElement
	XZ2           ExtensionFieldElement
	Xpow4         ExtensionFieldElement
	Zpow4         ExtensionFieldElement
}

// Given a four-torsion point x4 = x(P_4) on the curve E_(A:C), compute the
// coefficients of the codomain E_(A':C') of the four-isogeny phi : E_(A:C) ->
// E_(A:C)/<P_4>.
//
// Returns a tuple (codomain, isogeny) = (E_(A':C') : phi).
//
// There are two sets of formulas in Costello-Longa-Naehrig for computing
// four-isogenies.  One set is for the case where (1,...) lies in the kernel of
// the isogeny (this is the FirstFourIsogeny), and the other (this set) is for
// the case that (1,...) is *not* in the kernel.
func ComputeFourIsogeny(x4 *ProjectivePoint) (ProjectiveCurveParameters, FourIsogeny) {
	var codomain ProjectiveCurveParameters
	var isogeny FourIsogeny
	var v0, v1 ExtensionFieldElement
	v0.Square(&x4.X)                                     // = X4^2
	v1.Square(&x4.Z)                                     // = Z4^2
	isogeny.Xsq_plus_Zsq.Add(&v0, &v1)                   // = X4^2 + Z4^2
	isogeny.Xsq_minus_Zsq.Sub(&v0, &v1)                  // = X4^2 - Z4^2
	isogeny.XZ2.Add(&x4.X, &x4.Z)                        // = X4 + Z4
	isogeny.XZ2.Square(&isogeny.XZ2)                     // = X4^2 + Z4^2 + 2X4Z4
	isogeny.XZ2.Sub(&isogeny.XZ2, &isogeny.Xsq_plus_Zsq) // = 2X4Z4
	isogeny.Xpow4.Square(&v0)                            // = X4^4
	isogeny.Zpow4.Square(&v1)                            // = Z4^4
	v0.Add(&isogeny.Xpow4, &isogeny.Xpow4)               // = 2X4^4
	v0.Sub(&v0, &isogeny.Zpow4)                          // = 2X4^4 - Z4^4
	codomain.A.Add(&v0, &v0)                             // = 2(2X4^4 - Z4^4)
	codomain.C = isogeny.Zpow4                           // = Z4^4

	return codomain, isogeny
}

// Given a 4-isogeny phi and a point xP = x(P), compute x(Q), the x-coordinate
// of the image Q = phi(P) of P under phi : E_(A:C) -> E_(A':C').
//
// The output xQ = x(Q) is then a point on the curve E_(A':C'); the curve
// parameters are returned by the ComputeFourIsogeny function used to construct
// phi.
func (phi *FourIsogeny) Eval(xP *ProjectivePoint) ProjectivePoint {
	var xQ ProjectivePoint
	var t0, t1, t2 ExtensionFieldElement
	// We want to compute formula (7) of Costello-Longa-Naehrig, namely
	//
	// Xprime = (2*X_4*Z*Z_4 - (X_4^2 + Z_4^2)*X)*(X*X_4 - Z*Z_4)^2*X
	// Zprime = (2*X*X_4*Z_4 - (X_4^2 + Z_4^2)*Z)*(X_4*Z - X*Z_4)^2*Z
	//
	// To do this we adapt the method in the MSR implementation, which computes
	//
	// X_Q = Xprime*( 16*(X_4 + Z_4)*(X_4 - Z_4)*X_4^2*Z_4^4 )
	// Z_Q = Zprime*( 16*(X_4 + Z_4)*(X_4 - Z_4)*X_4^2*Z_4^4 )
	//
	t0.Mul(&xP.X, &phi.XZ2)                      // = 2*X*X_4*Z_4
	t1.Mul(&xP.Z, &phi.Xsq_plus_Zsq)             // = (X_4^2 + Z_4^2)*Z
	t0.Sub(&t0, &t1)                             // = -X_4^2*Z + 2*X*X_4*Z_4 - Z*Z_4^2
	t1.Mul(&xP.Z, &phi.Xsq_minus_Zsq)            // = (X_4^2 - Z_4^2)*Z
	t2.Sub(&t0, &t1).Square(&t2)                 // = 4*(X_4*Z - X*Z_4)^2*X_4^2
	t0.Mul(&t0, &t1).Add(&t0, &t0).Add(&t0, &t0) // = 4*(2*X*X_4*Z_4 - (X_4^2 + Z_4^2)*Z)*(X_4^2 - Z_4^2)*Z
	t1.Add(&t0, &t2)                             // = 4*(X*X_4 - Z*Z_4)^2*Z_4^2
	t0.Mul(&t0, &t2)                             // = Zprime * 16*(X_4 + Z_4)*(X_4 - Z_4)*X_4^2
	xQ.Z.Mul(&t0, &phi.Zpow4)                    // = Zprime * 16*(X_4 + Z_4)*(X_4 - Z_4)*X_4^2*Z_4^4
	t2.Mul(&t2, &phi.Zpow4)                      // = 4*(X_4*Z - X*Z_4)^2*X_4^2*Z_4^4
	t0.Mul(&t1, &phi.Xpow4)                      // = 4*(X*X_4 - Z*Z_4)^2*X_4^4*Z_4^2
	t0.Sub(&t2, &t0)                             // = -4*(X*X_4^2 - 2*X_4*Z*Z_4 + X*Z_4^2)*X*(X_4^2 - Z_4^2)*X_4^2*Z_4^2
	xQ.X.Mul(&t1, &t0)                           // = Xprime * 16*(X_4 + Z_4)*(X_4 - Z_4)*X_4^2*Z_4^4

	return xQ
}

// Represents a 4-isogeny phi.  See ComputeFourIsogeny for details.
type FirstFourIsogeny struct {
	A ExtensionFieldElement
	C ExtensionFieldElement
}

// Compute the "first" four-isogeny from the given curve.  See also
// ComputeFourIsogeny and Costello-Longa-Naehrig for more details.
func ComputeFirstFourIsogeny(domain *ProjectiveCurveParameters) (ProjectiveCurveParameters, FirstFourIsogeny) {
	var codomain ProjectiveCurveParameters
	var isogeny FirstFourIsogeny
	var t0, t1 ExtensionFieldElement

	t0.Add(&domain.C, &domain.C)   // = 2*C
	codomain.C.Sub(&domain.A, &t0) // = A - 2*C
	t1.Add(&t0, &t0)               // = 4*C
	t1.Add(&t1, &t0)               // = 6*C
	t0.Add(&t1, &domain.A)         // = A + 6*C
	codomain.A.Add(&t0, &t0)       // = 2*(A + 6*C)

	isogeny.A = domain.A
	isogeny.C = domain.C

	return codomain, isogeny
}

// Given a 4-isogeny phi and a point xP = x(P), compute x(Q), the x-coordinate
// of the image Q = phi(P) of P under phi : E_(A:C) -> E_(A':C').
//
// The output xQ = x(Q) is then a point on the curve E_(A':C'); the curve
// parameters are returned by the ComputeFirstFourIsogeny function used to construct
// phi.
func (phi *FirstFourIsogeny) Eval(xP *ProjectivePoint) ProjectivePoint {
	var xQ ProjectivePoint
	var t0, t1, t2, t3 ExtensionFieldElement

	t0.Add(&xP.X, &xP.Z).Square(&t0) // = (X+Z)^2
	t2.Mul(&xP.X, &xP.Z)             // = X*Z
	t1.Add(&t2, &t2)                 // = 2*X*Z
	t1.Sub(&t0, &t1)                 // = X^2 + Z^2
	xQ.X.Mul(&phi.A, &t2)            // = A*X*Z
	t3.Mul(&phi.C, &t1)              // = C*(X^2 + Z^2)
	xQ.X.Add(&xQ.X, &t3)             // = A*X*Z + C*(X^2 + Z^2)
	xQ.X.Mul(&xQ.X, &t0)             // = (X+Z)^2 * (A*X*Z + C*(X^2 + Z^2))
	t0.Sub(&xP.X, &xP.Z).Square(&t0) // = (X-Z)^2
	t0.Mul(&t0, &t2)                 // = X*Z*(X-Z)^2
	t1.Add(&phi.C, &phi.C)           // = 2*C
	t1.Sub(&t1, &phi.A)              // = 2*C - A
	xQ.Z.Mul(&t1, &t0)               // = (2*C - A)*X*Z*(X-Z)^2

	return xQ
}
