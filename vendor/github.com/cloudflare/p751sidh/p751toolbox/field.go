package p751toolbox

//------------------------------------------------------------------------------
// Extension Field
//------------------------------------------------------------------------------

// Represents an element of the extension field F_{p^2}.
type ExtensionFieldElement struct {
	// This field element is in Montgomery form, so that the value `A` is
	// represented by `aR mod p`.
	A Fp751Element
	// This field element is in Montgomery form, so that the value `B` is
	// represented by `bR mod p`.
	B Fp751Element
}

var zeroExtensionField = ExtensionFieldElement{
	A: Fp751Element{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
	B: Fp751Element{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
}

var oneExtensionField = ExtensionFieldElement{
	A: Fp751Element{0x249ad, 0x0, 0x0, 0x0, 0x0, 0x8310000000000000, 0x5527b1e4375c6c66, 0x697797bf3f4f24d0, 0xc89db7b2ac5c4e2e, 0x4ca4b439d2076956, 0x10f7926c7512c7e9, 0x2d5b24bce5e2},
	B: Fp751Element{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
}

// Set dest = 0.
//
// Returns dest to allow chaining operations.
func (dest *ExtensionFieldElement) Zero() *ExtensionFieldElement {
	*dest = zeroExtensionField
	return dest
}

// Set dest = 1.
//
// Returns dest to allow chaining operations.
func (dest *ExtensionFieldElement) One() *ExtensionFieldElement {
	*dest = oneExtensionField
	return dest
}

// Set dest = lhs * rhs.
//
// Allowed to overlap lhs or rhs with dest.
//
// Returns dest to allow chaining operations.
func (dest *ExtensionFieldElement) Mul(lhs, rhs *ExtensionFieldElement) *ExtensionFieldElement {
	// Let (a,b,c,d) = (lhs.a,lhs.b,rhs.a,rhs.b).
	a := &lhs.A
	b := &lhs.B
	c := &rhs.A
	d := &rhs.B

	// We want to compute
	//
	// (a + bi)*(c + di) = (a*c - b*d) + (a*d + b*c)i
	//
	// Use Karatsuba's trick: note that
	//
	// (b - a)*(c - d) = (b*c + a*d) - a*c - b*d
	//
	// so (a*d + b*c) = (b-a)*(c-d) + a*c + b*d.

	var ac, bd fp751X2
	fp751Mul(&ac, a, c) // = a*c*R*R
	fp751Mul(&bd, b, d) // = b*d*R*R

	var b_minus_a, c_minus_d Fp751Element
	fp751SubReduced(&b_minus_a, b, a) // = (b-a)*R
	fp751SubReduced(&c_minus_d, c, d) // = (c-d)*R

	var ad_plus_bc fp751X2
	fp751Mul(&ad_plus_bc, &b_minus_a, &c_minus_d) // = (b-a)*(c-d)*R*R
	fp751X2AddLazy(&ad_plus_bc, &ad_plus_bc, &ac) // = ((b-a)*(c-d) + a*c)*R*R
	fp751X2AddLazy(&ad_plus_bc, &ad_plus_bc, &bd) // = ((b-a)*(c-d) + a*c + b*d)*R*R

	fp751MontgomeryReduce(&dest.B, &ad_plus_bc) // = (a*d + b*c)*R mod p

	var ac_minus_bd fp751X2
	fp751X2SubLazy(&ac_minus_bd, &ac, &bd)       // = (a*c - b*d)*R*R
	fp751MontgomeryReduce(&dest.A, &ac_minus_bd) // = (a*c - b*d)*R mod p

	return dest
}

// Set dest = -x
//
// Allowed to overlap dest with x.
//
// Returns dest to allow chaining operations.
func (dest *ExtensionFieldElement) Neg(x *ExtensionFieldElement) *ExtensionFieldElement {
	dest.Sub(&zeroExtensionField, x)
	return dest
}

// Set dest = 1/x
//
// Allowed to overlap dest with x.
//
// Returns dest to allow chaining operations.
func (dest *ExtensionFieldElement) Inv(x *ExtensionFieldElement) *ExtensionFieldElement {
	a := &x.A
	b := &x.B

	// We want to compute
	//
	//    1          1     (a - bi)	    (a - bi)
	// -------- = -------- -------- = -----------
	// (a + bi)   (a + bi) (a - bi)   (a^2 + b^2)
	//
	// Letting c = 1/(a^2 + b^2), this is
	//
	// 1/(a+bi) = a*c - b*ci.

	var asq_plus_bsq PrimeFieldElement
	var asq, bsq fp751X2
	fp751Mul(&asq, a, a)                         // = a*a*R*R
	fp751Mul(&bsq, b, b)                         // = b*b*R*R
	fp751X2AddLazy(&asq, &asq, &bsq)             // = (a^2 + b^2)*R*R
	fp751MontgomeryReduce(&asq_plus_bsq.A, &asq) // = (a^2 + b^2)*R mod p
	// Now asq_plus_bsq = a^2 + b^2

	var asq_plus_bsq_inv PrimeFieldElement
	asq_plus_bsq_inv.Inv(&asq_plus_bsq)
	c := &asq_plus_bsq_inv.A

	var ac fp751X2
	fp751Mul(&ac, a, c)
	fp751MontgomeryReduce(&dest.A, &ac)

	var minus_b Fp751Element
	fp751SubReduced(&minus_b, &minus_b, b)
	var minus_bc fp751X2
	fp751Mul(&minus_bc, &minus_b, c)
	fp751MontgomeryReduce(&dest.B, &minus_bc)

	return dest
}

// Set (y1, y2, y3)  = (1/x1, 1/x2, 1/x3).
//
// All xi, yi must be distinct.
func ExtensionFieldBatch3Inv(x1, x2, x3, y1, y2, y3 *ExtensionFieldElement) {
	var x1x2, t ExtensionFieldElement
	x1x2.Mul(x1, x2)           // x1*x2
	t.Mul(&x1x2, x3).Inv(&t)   // 1/(x1*x2*x3)
	y1.Mul(&t, x2).Mul(y1, x3) // 1/x1
	y2.Mul(&t, x1).Mul(y2, x3) // 1/x2
	y3.Mul(&t, &x1x2)          // 1/x3
}

// Set dest = x * x
//
// Allowed to overlap dest with x.
//
// Returns dest to allow chaining operations.
func (dest *ExtensionFieldElement) Square(x *ExtensionFieldElement) *ExtensionFieldElement {
	a := &x.A
	b := &x.B

	// We want to compute
	//
	// (a + bi)*(a + bi) = (a^2 - b^2) + 2abi.

	var a2, a_plus_b, a_minus_b Fp751Element
	fp751AddReduced(&a2, a, a)        // = a*R + a*R = 2*a*R
	fp751AddReduced(&a_plus_b, a, b)  // = a*R + b*R = (a+b)*R
	fp751SubReduced(&a_minus_b, a, b) // = a*R - b*R = (a-b)*R

	var asq_minus_bsq, ab2 fp751X2
	fp751Mul(&asq_minus_bsq, &a_plus_b, &a_minus_b) // = (a+b)*(a-b)*R*R = (a^2 - b^2)*R*R
	fp751Mul(&ab2, &a2, b)                          // = 2*a*b*R*R

	fp751MontgomeryReduce(&dest.A, &asq_minus_bsq) // = (a^2 - b^2)*R mod p
	fp751MontgomeryReduce(&dest.B, &ab2)           // = 2*a*b*R mod p

	return dest
}

// Set dest = lhs + rhs.
//
// Allowed to overlap lhs or rhs with dest.
//
// Returns dest to allow chaining operations.
func (dest *ExtensionFieldElement) Add(lhs, rhs *ExtensionFieldElement) *ExtensionFieldElement {
	fp751AddReduced(&dest.A, &lhs.A, &rhs.A)
	fp751AddReduced(&dest.B, &lhs.B, &rhs.B)

	return dest
}

// Set dest = lhs - rhs.
//
// Allowed to overlap lhs or rhs with dest.
//
// Returns dest to allow chaining operations.
func (dest *ExtensionFieldElement) Sub(lhs, rhs *ExtensionFieldElement) *ExtensionFieldElement {
	fp751SubReduced(&dest.A, &lhs.A, &rhs.A)
	fp751SubReduced(&dest.B, &lhs.B, &rhs.B)

	return dest
}

// If choice = 1u8, set (x,y) = (y,x). If choice = 0u8, set (x,y) = (x,y).
//
// Returns dest to allow chaining operations.
func ExtensionFieldConditionalSwap(x, y *ExtensionFieldElement, choice uint8) {
	fp751ConditionalSwap(&x.A, &y.A, choice)
	fp751ConditionalSwap(&x.B, &y.B, choice)
}

// Set dest = if choice == 0 { x } else { y }, in constant time.
//
// Can overlap z with x or y or both.
//
// Returns dest to allow chaining operations.
func (dest *ExtensionFieldElement) ConditionalAssign(x, y *ExtensionFieldElement, choice uint8) *ExtensionFieldElement {
	fp751ConditionalAssign(&dest.A, &x.A, &y.A, choice)
	fp751ConditionalAssign(&dest.B, &x.B, &y.B, choice)

	return dest
}

// Returns true if lhs = rhs.  Takes variable time.
func (lhs *ExtensionFieldElement) VartimeEq(rhs *ExtensionFieldElement) bool {
	return lhs.A.vartimeEq(rhs.A) && lhs.B.vartimeEq(rhs.B)
}

// Convert the input to wire format.
//
// The output byte slice must be at least 188 bytes long.
func (x *ExtensionFieldElement) ToBytes(output []byte) {
	if len(output) < 188 {
		panic("output byte slice too short, need 188 bytes")
	}
	x.A.toBytesFromMontgomeryForm(output[0:94])
	x.B.toBytesFromMontgomeryForm(output[94:188])
}

// Read 188 bytes into the given ExtensionFieldElement.
//
// It is an error to call this function if the input byte slice is less than 188 bytes long.
func (x *ExtensionFieldElement) FromBytes(input []byte) {
	if len(input) < 188 {
		panic("input byte slice too short, need 188 bytes")
	}
	x.A.montgomeryFormFromBytes(input[:94])
	x.B.montgomeryFormFromBytes(input[94:188])
}

//------------------------------------------------------------------------------
// Prime Field
//------------------------------------------------------------------------------

// Represents an element of the prime field F_p.
type PrimeFieldElement struct {
	// This field element is in Montgomery form, so that the value `A` is
	// represented by `aR mod p`.
	A Fp751Element
}

var zeroPrimeField = PrimeFieldElement{
	A: Fp751Element{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
}

var onePrimeField = PrimeFieldElement{
	A: Fp751Element{0x249ad, 0x0, 0x0, 0x0, 0x0, 0x8310000000000000, 0x5527b1e4375c6c66, 0x697797bf3f4f24d0, 0xc89db7b2ac5c4e2e, 0x4ca4b439d2076956, 0x10f7926c7512c7e9, 0x2d5b24bce5e2},
}

// Set dest = 0.
//
// Returns dest to allow chaining operations.
func (dest *PrimeFieldElement) Zero() *PrimeFieldElement {
	*dest = zeroPrimeField
	return dest
}

// Set dest = 1.
//
// Returns dest to allow chaining operations.
func (dest *PrimeFieldElement) One() *PrimeFieldElement {
	*dest = onePrimeField
	return dest
}

// Set dest to x.
//
// Returns dest to allow chaining operations.
func (dest *PrimeFieldElement) SetUint64(x uint64) *PrimeFieldElement {
	var xRR fp751X2
	dest.A = Fp751Element{}                 // = 0
	dest.A[0] = x                           // = x
	fp751Mul(&xRR, &dest.A, &montgomeryRsq) // = x*R*R
	fp751MontgomeryReduce(&dest.A, &xRR)    // = x*R mod p

	return dest
}

// Set dest = lhs * rhs.
//
// Allowed to overlap lhs or rhs with dest.
//
// Returns dest to allow chaining operations.
func (dest *PrimeFieldElement) Mul(lhs, rhs *PrimeFieldElement) *PrimeFieldElement {
	a := &lhs.A // = a*R
	b := &rhs.A // = b*R

	var ab fp751X2
	fp751Mul(&ab, a, b)                 // = a*b*R*R
	fp751MontgomeryReduce(&dest.A, &ab) // = a*b*R mod p

	return dest
}

// Set dest = x^(2^k), for k >= 1, by repeated squarings.
//
// Allowed to overlap x with dest.
//
// Returns dest to allow chaining operations.
func (dest *PrimeFieldElement) Pow2k(x *PrimeFieldElement, k uint8) *PrimeFieldElement {
	dest.Square(x)
	for i := uint8(1); i < k; i++ {
		dest.Square(dest)
	}

	return dest
}

// Set dest = x^2
//
// Allowed to overlap x with dest.
//
// Returns dest to allow chaining operations.
func (dest *PrimeFieldElement) Square(x *PrimeFieldElement) *PrimeFieldElement {
	a := &x.A // = a*R
	b := &x.A // = b*R

	var ab fp751X2
	fp751Mul(&ab, a, b)                 // = a*b*R*R
	fp751MontgomeryReduce(&dest.A, &ab) // = a*b*R mod p

	return dest
}

// Set dest = -x
//
// Allowed to overlap x with dest.
//
// Returns dest to allow chaining operations.
func (dest *PrimeFieldElement) Neg(x *PrimeFieldElement) *PrimeFieldElement {
	dest.Sub(&zeroPrimeField, x)
	return dest
}

// Set dest = lhs + rhs.
//
// Allowed to overlap lhs or rhs with dest.
//
// Returns dest to allow chaining operations.
func (dest *PrimeFieldElement) Add(lhs, rhs *PrimeFieldElement) *PrimeFieldElement {
	fp751AddReduced(&dest.A, &lhs.A, &rhs.A)

	return dest
}

// Set dest = lhs - rhs.
//
// Allowed to overlap lhs or rhs with dest.
//
// Returns dest to allow chaining operations.
func (dest *PrimeFieldElement) Sub(lhs, rhs *PrimeFieldElement) *PrimeFieldElement {
	fp751SubReduced(&dest.A, &lhs.A, &rhs.A)

	return dest
}

// Returns true if lhs = rhs.  Takes variable time.
func (lhs *PrimeFieldElement) VartimeEq(rhs *PrimeFieldElement) bool {
	return lhs.A.vartimeEq(rhs.A)
}

// If choice = 1u8, set (x,y) = (y,x). If choice = 0u8, set (x,y) = (x,y).
//
// Returns dest to allow chaining operations.
func PrimeFieldConditionalSwap(x, y *PrimeFieldElement, choice uint8) {
	fp751ConditionalSwap(&x.A, &y.A, choice)
}

// Set dest = if choice == 0 { x } else { y }, in constant time.
//
// Can overlap z with x or y or both.
//
// Returns dest to allow chaining operations.
func (dest *PrimeFieldElement) ConditionalAssign(x, y *PrimeFieldElement, choice uint8) *PrimeFieldElement {
	fp751ConditionalAssign(&dest.A, &x.A, &y.A, choice)

	return dest
}

// Set dest = sqrt(x), if x is a square.  If x is nonsquare dest is undefined.
//
// Allowed to overlap x with dest.
//
// Returns dest to allow chaining operations.
func (dest *PrimeFieldElement) Sqrt(x *PrimeFieldElement) *PrimeFieldElement {
	tmp_x := *x // Copy x in case dest == x
	// Since x is assumed to be square, x = y^2
	dest.P34(x)            // dest = (y^2)^((p-3)/4) = y^((p-3)/2)
	dest.Mul(dest, &tmp_x) // dest = y^2 * y^((p-3)/2) = y^((p+1)/2)
	// Now dest^2 = y^(p+1) = y^2 = x, so dest = sqrt(x)

	return dest
}

// Set dest = 1/x.
//
// Allowed to overlap x with dest.
//
// Returns dest to allow chaining operations.
func (dest *PrimeFieldElement) Inv(x *PrimeFieldElement) *PrimeFieldElement {
	tmp_x := *x            // Copy x in case dest == x
	dest.Square(x)         // dest = x^2
	dest.P34(dest)         // dest = (x^2)^((p-3)/4) = x^((p-3)/2)
	dest.Square(dest)      // dest = x^(p-3)
	dest.Mul(dest, &tmp_x) // dest = x^(p-2)

	return dest
}

// Set dest = x^((p-3)/4).  If x is square, this is 1/sqrt(x).
//
// Allowed to overlap x with dest.
//
// Returns dest to allow chaining operations.
func (dest *PrimeFieldElement) P34(x *PrimeFieldElement) *PrimeFieldElement {
	// Sliding-window strategy computed with Sage, awk, sed, and tr.
	//
	// This performs sum(powStrategy) = 744 squarings and len(mulStrategy)
	// = 137 multiplications, in addition to 1 squaring and 15
	// multiplications to build a lookup table.
	//
	// In total this is 745 squarings, 152 multiplications.  Since squaring
	// is not implemented for the prime field, this is 897 multiplications
	// in total.
	powStrategy := [137]uint8{5, 7, 6, 2, 10, 4, 6, 9, 8, 5, 9, 4, 7, 5, 5, 4, 8, 3, 9, 5, 5, 4, 10, 4, 6, 6, 6, 5, 8, 9, 3, 4, 9, 4, 5, 6, 6, 2, 9, 4, 5, 5, 5, 7, 7, 9, 4, 6, 4, 8, 5, 8, 6, 6, 2, 9, 7, 4, 8, 8, 8, 4, 6, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 2}
	mulStrategy := [137]uint8{31, 23, 21, 1, 31, 7, 7, 7, 9, 9, 19, 15, 23, 23, 11, 7, 25, 5, 21, 17, 11, 5, 17, 7, 11, 9, 23, 9, 1, 19, 5, 3, 25, 15, 11, 29, 31, 1, 29, 11, 13, 9, 11, 27, 13, 19, 15, 31, 3, 29, 23, 31, 25, 11, 1, 21, 19, 15, 15, 21, 29, 13, 23, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 31, 3}
	initialMul := uint8(27)

	// Build a lookup table of odd multiples of x.
	lookup := [16]PrimeFieldElement{}
	xx := &PrimeFieldElement{}
	xx.Square(x) // Set xx = x^2
	lookup[0] = *x
	for i := 1; i < 16; i++ {
		lookup[i].Mul(&lookup[i-1], xx)
	}
	// Now lookup = {x, x^3, x^5, ... }
	// so that lookup[i] = x^{2*i + 1}
	// so that lookup[k/2] = x^k, for odd k

	*dest = lookup[initialMul/2]
	for i := uint8(0); i < 137; i++ {
		dest.Pow2k(dest, powStrategy[i])
		dest.Mul(dest, &lookup[mulStrategy[i]/2])
	}

	return dest
}

//------------------------------------------------------------------------------
// Internals
//------------------------------------------------------------------------------

const fp751NumWords = 12

// (2^768) mod p.
// This can't be a constant because Go doesn't allow array constants, so try
// not to modify it.
var montgomeryR = Fp751Element{149933, 0, 0, 0, 0, 9444048418595930112, 6136068611055053926, 7599709743867700432, 14455912356952952366, 5522737203492907350, 1222606818372667369, 49869481633250}

// (2^768)^2 mod p
// This can't be a constant because Go doesn't allow array constants, so try
// not to modify it.
var montgomeryRsq = Fp751Element{2535603850726686808, 15780896088201250090, 6788776303855402382, 17585428585582356230, 5274503137951975249, 2266259624764636289, 11695651972693921304, 13072885652150159301, 4908312795585420432, 6229583484603254826, 488927695601805643, 72213483953973}

// Internal representation of an element of the base field F_p.
//
// This type is distinct from PrimeFieldElement in that no particular meaning
// is assigned to the representation -- it could represent an element in
// Montgomery form, or not.  Tracking the meaning of the field element is left
// to higher types.
type Fp751Element [fp751NumWords]uint64

// Represents an intermediate product of two elements of the base field F_p.
type fp751X2 [2 * fp751NumWords]uint64

// If choice = 0, leave x,y unchanged. If choice = 1, set x,y = y,x.
// This function executes in constant time.
//go:noescape
func fp751ConditionalSwap(x, y *Fp751Element, choice uint8)

// If choice = 0, set z = x. If choice = 1, set z = y.
// This function executes in constant time.
//
// Can overlap z with x or y or both.
//go:noescape
func fp751ConditionalAssign(z, x, y *Fp751Element, choice uint8)

// Compute z = x + y (mod p).
//go:noescape
func fp751AddReduced(z, x, y *Fp751Element)

// Compute z = x - y (mod p).
//go:noescape
func fp751SubReduced(z, x, y *Fp751Element)

// Compute z = x + y, without reducing mod p.
//go:noescape
func fp751AddLazy(z, x, y *Fp751Element)

// Compute z = x + y, without reducing mod p.
//go:noescape
func fp751X2AddLazy(z, x, y *fp751X2)

// Compute z = x - y, without reducing mod p.
//go:noescape
func fp751X2SubLazy(z, x, y *fp751X2)

// Compute z = x * y.
//go:noescape
func fp751Mul(z *fp751X2, x, y *Fp751Element)

// Perform Montgomery reduction: set z = x R^{-1} (mod p).
// Destroys the input value.
//go:noescape
func fp751MontgomeryReduce(z *Fp751Element, x *fp751X2)

// Reduce a field element in [0, 2*p) to one in [0,p).
//go:noescape
func fp751StrongReduce(x *Fp751Element)

func (x Fp751Element) vartimeEq(y Fp751Element) bool {
	fp751StrongReduce(&x)
	fp751StrongReduce(&y)
	eq := true
	for i := 0; i < fp751NumWords; i++ {
		eq = (x[i] == y[i]) && eq
	}

	return eq
}

// Read an Fp751Element from little-endian bytes and convert to Montgomery form.
//
// The input byte slice must be at least 94 bytes long.
func (x *Fp751Element) montgomeryFormFromBytes(input []byte) {
	if len(input) < 94 {
		panic("input byte slice too short")
	}

	var a Fp751Element
	for i := 0; i < 94; i++ {
		// set i = j*8 + k
		j := i / 8
		k := uint64(i % 8)
		a[j] |= uint64(input[i]) << (8 * k)
	}

	var aRR fp751X2
	fp751Mul(&aRR, &a, &montgomeryRsq) // = a*R*R
	fp751MontgomeryReduce(x, &aRR)     // = a*R mod p
}

// Given an Fp751Element in Montgomery form, convert to little-endian bytes.
//
// The output byte slice must be at least 94 bytes long.
func (x *Fp751Element) toBytesFromMontgomeryForm(output []byte) {
	if len(output) < 94 {
		panic("output byte slice too short")
	}

	var a Fp751Element
	var aR fp751X2
	copy(aR[:], x[:])              // = a*R
	fp751MontgomeryReduce(&a, &aR) // = a mod p in [0, 2p)
	fp751StrongReduce(&a)          // = a mod p in [0, p)

	// 8*12 = 96, but we drop the last two bytes since p is 751 < 752=94*8 bits.
	for i := 0; i < 94; i++ {
		// set i = j*8 + k
		j := i / 8
		k := uint64(i % 8)
		// Need parens because Go's operator precedence would interpret
		// a[j] >> 8*k as (a[j] >> 8) * k
		output[i] = byte(a[j] >> (8 * k))
	}
}
