package fp25519

import (
	"math/bits"
	"unsafe"
)

type elt64 [4]uint64

func cmovGeneric(x, y *Elt, n uint) {
	xx, yy := (*elt64)(unsafe.Pointer(x)), (*elt64)(unsafe.Pointer(y))
	m := -uint64(n & 0x1)
	xx[0] = (xx[0] &^ m) | (yy[0] & m)
	xx[1] = (xx[1] &^ m) | (yy[1] & m)
	xx[2] = (xx[2] &^ m) | (yy[2] & m)
	xx[3] = (xx[3] &^ m) | (yy[3] & m)
}

func cswapGeneric(x, y *Elt, n uint) {
	xx, yy := (*elt64)(unsafe.Pointer(x)), (*elt64)(unsafe.Pointer(y))
	m := -uint64(n & 0x1)
	t0 := m & (xx[0] ^ yy[0])
	t1 := m & (xx[1] ^ yy[1])
	t2 := m & (xx[2] ^ yy[2])
	t3 := m & (xx[3] ^ yy[3])
	xx[0] ^= t0
	xx[1] ^= t1
	xx[2] ^= t2
	xx[3] ^= t3
	yy[0] ^= t0
	yy[1] ^= t1
	yy[2] ^= t2
	yy[3] ^= t3
}

func addGeneric(z, x, y *Elt) {
	zz := (*elt64)(unsafe.Pointer(z))
	xx := (*elt64)(unsafe.Pointer(x))
	yy := (*elt64)(unsafe.Pointer(y))

	z0, c0 := bits.Add64(xx[0], yy[0], 0)
	z1, c1 := bits.Add64(xx[1], yy[1], c0)
	z2, c2 := bits.Add64(xx[2], yy[2], c1)
	z3, c3 := bits.Add64(xx[3], yy[3], c2)

	z0, c0 = bits.Add64(z0, (-c3)&38, 0)
	zz[1], c1 = bits.Add64(z1, 0, c0)
	zz[2], c2 = bits.Add64(z2, 0, c1)
	zz[3], c3 = bits.Add64(z3, 0, c2)
	zz[0], _ = bits.Add64(z0, (-c3)&38, 0)
}

func subGeneric(z, x, y *Elt) {
	zz := (*elt64)(unsafe.Pointer(z))
	xx := (*elt64)(unsafe.Pointer(x))
	yy := (*elt64)(unsafe.Pointer(y))

	z0, c0 := bits.Sub64(xx[0], yy[0], 0)
	z1, c1 := bits.Sub64(xx[1], yy[1], c0)
	z2, c2 := bits.Sub64(xx[2], yy[2], c1)
	z3, c3 := bits.Sub64(xx[3], yy[3], c2)

	z0, c0 = bits.Sub64(z0, (-c3)&38, 0)
	zz[1], c1 = bits.Sub64(z1, 0, c0)
	zz[2], c2 = bits.Sub64(z2, 0, c1)
	zz[3], c3 = bits.Sub64(z3, 0, c2)
	zz[0], _ = bits.Sub64(z0, (-c3)&38, 0)
}

func addsubGeneric(x, y *Elt) {
	z := &Elt{}
	addGeneric(z, x, y)
	subGeneric(y, x, y)
	*x = *z
}

func mulGeneric(z, x, y *Elt) {
	zz := (*elt64)(unsafe.Pointer(z))
	xx := (*elt64)(unsafe.Pointer(x))
	yy := (*elt64)(unsafe.Pointer(y))

	x0, x1, x2, x3 := xx[0], xx[1], xx[2], xx[3]
	yi := yy[0]
	h0, l0 := bits.Mul64(x0, yi)
	h1, l1 := bits.Mul64(x1, yi)
	h2, l2 := bits.Mul64(x2, yi)
	h3, l3 := bits.Mul64(x3, yi)

	zz[0] = l0
	a0, c0 := bits.Add64(h0, l1, 0)
	a1, c1 := bits.Add64(h1, l2, c0)
	a2, c2 := bits.Add64(h2, l3, c1)
	a3, _ := bits.Add64(h3, 0, c2)

	yi = yy[1]
	h0, l0 = bits.Mul64(x0, yi)
	h1, l1 = bits.Mul64(x1, yi)
	h2, l2 = bits.Mul64(x2, yi)
	h3, l3 = bits.Mul64(x3, yi)

	zz[1], c0 = bits.Add64(a0, l0, 0)
	h0, c1 = bits.Add64(h0, l1, c0)
	h1, c2 = bits.Add64(h1, l2, c1)
	h2, c3 := bits.Add64(h2, l3, c2)
	h3, _ = bits.Add64(h3, 0, c3)

	a0, c0 = bits.Add64(a1, h0, 0)
	a1, c1 = bits.Add64(a2, h1, c0)
	a2, c2 = bits.Add64(a3, h2, c1)
	a3, _ = bits.Add64(0, h3, c2)

	yi = yy[2]
	h0, l0 = bits.Mul64(x0, yi)
	h1, l1 = bits.Mul64(x1, yi)
	h2, l2 = bits.Mul64(x2, yi)
	h3, l3 = bits.Mul64(x3, yi)

	zz[2], c0 = bits.Add64(a0, l0, 0)
	h0, c1 = bits.Add64(h0, l1, c0)
	h1, c2 = bits.Add64(h1, l2, c1)
	h2, c3 = bits.Add64(h2, l3, c2)
	h3, _ = bits.Add64(h3, 0, c3)

	a0, c0 = bits.Add64(a1, h0, 0)
	a1, c1 = bits.Add64(a2, h1, c0)
	a2, c2 = bits.Add64(a3, h2, c1)
	a3, _ = bits.Add64(0, h3, c2)

	yi = yy[3]
	h0, l0 = bits.Mul64(x0, yi)
	h1, l1 = bits.Mul64(x1, yi)
	h2, l2 = bits.Mul64(x2, yi)
	h3, l3 = bits.Mul64(x3, yi)

	zz[3], c0 = bits.Add64(a0, l0, 0)
	h0, c1 = bits.Add64(h0, l1, c0)
	h1, c2 = bits.Add64(h1, l2, c1)
	h2, c3 = bits.Add64(h2, l3, c2)
	h3, _ = bits.Add64(h3, 0, c3)

	b4, c0 := bits.Add64(a1, h0, 0)
	b5, c1 := bits.Add64(a2, h1, c0)
	b6, c2 := bits.Add64(a3, h2, c1)
	b7, _ := bits.Add64(0, h3, c2)

	red64(zz, &elt64{b4, b5, b6, b7})
}

func sqrGeneric(z, x *Elt) {
	zz := (*elt64)(unsafe.Pointer(z))
	xx := (*elt64)(unsafe.Pointer(x))

	x0, x1, x2, x3 := xx[0], xx[1], xx[2], xx[3]
	h0, a0 := bits.Mul64(x0, x1)
	h1, l1 := bits.Mul64(x0, x2)
	h2, l2 := bits.Mul64(x0, x3)
	h3, l3 := bits.Mul64(x3, x1)
	h4, l4 := bits.Mul64(x3, x2)
	h, l := bits.Mul64(x1, x2)

	a1, c0 := bits.Add64(l1, h0, 0)
	a2, c1 := bits.Add64(l2, h1, c0)
	a3, c2 := bits.Add64(l3, h2, c1)
	a4, c3 := bits.Add64(l4, h3, c2)
	a5, _ := bits.Add64(h4, 0, c3)

	a2, c0 = bits.Add64(a2, l, 0)
	a3, c1 = bits.Add64(a3, h, c0)
	a4, c2 = bits.Add64(a4, 0, c1)
	a5, c3 = bits.Add64(a5, 0, c2)
	a6, _ := bits.Add64(0, 0, c3)

	a0, c0 = bits.Add64(a0, a0, 0)
	a1, c1 = bits.Add64(a1, a1, c0)
	a2, c2 = bits.Add64(a2, a2, c1)
	a3, c3 = bits.Add64(a3, a3, c2)
	a4, c4 := bits.Add64(a4, a4, c3)
	a5, c5 := bits.Add64(a5, a5, c4)
	a6, _ = bits.Add64(a6, a6, c5)

	b1, b0 := bits.Mul64(x0, x0)
	b3, b2 := bits.Mul64(x1, x1)
	b5, b4 := bits.Mul64(x2, x2)
	b7, b6 := bits.Mul64(x3, x3)

	b1, c0 = bits.Add64(b1, a0, 0)
	b2, c1 = bits.Add64(b2, a1, c0)
	b3, c2 = bits.Add64(b3, a2, c1)
	b4, c3 = bits.Add64(b4, a3, c2)
	b5, c4 = bits.Add64(b5, a4, c3)
	b6, c5 = bits.Add64(b6, a5, c4)
	b7, _ = bits.Add64(b7, a6, c5)
	zz[0] = b0
	zz[1] = b1
	zz[2] = b2
	zz[3] = b3
	red64(zz, &elt64{b4, b5, b6, b7})
}

func modpGeneric(x *Elt) {
	xx := (*elt64)(unsafe.Pointer(x))
	x3 := xx[3]
	// CX = C[255] ? 38 : 19
	cx := uint64(19) << (x3 >> 63)
	// PUT BIT 255 IN CARRY FLAG AND CLEAR
	x3 &^= 1 << 63

	x0, c0 := bits.Add64(xx[0], cx, 0)
	x1, c1 := bits.Add64(xx[1], 0, c0)
	x2, c2 := bits.Add64(xx[2], 0, c1)
	x3, _ = bits.Add64(x3, 0, c2)

	// TEST FOR BIT 255 AGAIN; ONLY TRIGGERED ON OVERFLOW MODULO 2^255-19
	// cx = C[255] ? 0 : 19
	cx = uint64(19) &^ (-(x3 >> 63))
	// CLEAR BIT 255
	x3 &^= 1 << 63

	xx[0], c0 = bits.Sub64(x0, cx, 0)
	xx[1], c1 = bits.Sub64(x1, 0, c0)
	xx[2], c2 = bits.Sub64(x2, 0, c1)
	xx[3], _ = bits.Sub64(x3, 0, c2)
}

func red64(z, h *elt64) {
	h0, l0 := bits.Mul64(h[0], 38)
	h1, l1 := bits.Mul64(h[1], 38)
	h2, l2 := bits.Mul64(h[2], 38)
	h3, l3 := bits.Mul64(h[3], 38)

	l1, c0 := bits.Add64(h0, l1, 0)
	l2, c1 := bits.Add64(h1, l2, c0)
	l3, c2 := bits.Add64(h2, l3, c1)
	l4, _ := bits.Add64(h3, 0, c2)

	l0, c0 = bits.Add64(l0, z[0], 0)
	l1, c1 = bits.Add64(l1, z[1], c0)
	l2, c2 = bits.Add64(l2, z[2], c1)
	l3, c3 := bits.Add64(l3, z[3], c2)
	l4, _ = bits.Add64(l4, 0, c3)

	_, l4 = bits.Mul64(l4, 38)
	l0, c0 = bits.Add64(l0, l4, 0)
	z[1], c1 = bits.Add64(l1, 0, c0)
	z[2], c2 = bits.Add64(l2, 0, c1)
	z[3], c3 = bits.Add64(l3, 0, c2)
	z[0], _ = bits.Add64(l0, (-c3)&38, 0)
}
