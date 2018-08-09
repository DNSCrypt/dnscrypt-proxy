// Copyright (c) 2016 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

// +build amd64, !gccgo, !appengine

package poly1305

import (
	"golang.org/x/sys/cpu"
	"io"
)

var useAVX2 = cpu.X86.HasAVX2

//go:noescape
func initialize(state *[7]uint64, key *[32]byte)

//go:noescape
func initializeAVX2(state *[512]byte, key *[32]byte)

//go:noescape
func update(state *[7]uint64, msg []byte)

//go:noescape
func updateAVX2(state *[512]byte, msg []byte)

//go:noescape
func finalize(tag *[TagSize]byte, state *[7]uint64)

//go:noescape
func finalizeAVX2(tag *[TagSize]byte, state *[512]byte)

// compiler asserts - check that poly1305Hash and poly1305HashAVX2 implements the hash interface
var (
	_ (hash) = &poly1305Hash{}
	_ (hash) = &poly1305HashAVX2{}
)

type hash interface {
	io.Writer

	Sum(b []byte) []byte
}

// Sum generates an authenticator for msg using a one-time key and returns the
// 16-byte result. Authenticating two different messages with the same key allows
// an attacker to forge messages at will.
func Sum(msg []byte, key [32]byte) [TagSize]byte {
	if len(msg) == 0 {
		msg = []byte{}
	}
	var out [TagSize]byte
	if useAVX2 && len(msg) > 8*TagSize {
		var state [512]byte
		initializeAVX2(&state, &key)
		updateAVX2(&state, msg)
		finalizeAVX2(&out, &state)
	} else {
		var state [7]uint64 // := uint64{ h0, h1, h2, r0, r1, pad0, pad1 }
		initialize(&state, &key)
		update(&state, msg)
		finalize(&out, &state)
	}
	return out
}

// New returns a Hash computing the poly1305 sum.
// Notice that Poly1305 is insecure if one key is used twice.
func New(key [32]byte) *Hash {
	if useAVX2 {
		h := new(poly1305HashAVX2)
		initializeAVX2(&(h.state), &key)
		return &Hash{h, false}
	}
	h := new(poly1305Hash)
	initialize(&(h.state), &key)
	return &Hash{h, false}
}

// Hash implements the poly1305 authenticator.
// Poly1305 cannot be used like common hash.Hash implementations,
// because using a poly1305 key twice breaks its security.
type Hash struct {
	hash

	done bool
}

// Size returns the number of bytes Sum will append.
func (h *Hash) Size() int { return TagSize }

// Write adds more data to the running Poly1305 hash.
// This function should return a non-nil error if a call
// to Write happens after a call to Sum. So it is not possible
// to compute the checksum and than add more data.
func (h *Hash) Write(msg []byte) (int, error) {
	if h.done {
		return 0, errWriteAfterSum
	}
	return h.hash.Write(msg)
}

// Sum appends the Poly1305 hash of the previously
// processed data to b and returns the resulting slice.
// It is safe to call this function multiple times.
func (h *Hash) Sum(b []byte) []byte {
	b = h.hash.Sum(b)
	h.done = true
	return b
}

type poly1305Hash struct {
	state [7]uint64 // := uint64{ h0, h1, h2, r0, r1, pad0, pad1 }

	buf [TagSize]byte
	off int
}

func (h *poly1305Hash) Write(p []byte) (n int, err error) {
	n = len(p)
	if h.off > 0 {
		dif := TagSize - h.off
		if n <= dif {
			h.off += copy(h.buf[h.off:], p)
			return n, nil
		}
		copy(h.buf[h.off:], p[:dif])
		update(&(h.state), h.buf[:])
		p = p[dif:]
		h.off = 0
	}
	// process full 16-byte blocks
	if nn := len(p) & (^(TagSize - 1)); nn > 0 {
		update(&(h.state), p[:nn])
		p = p[nn:]
	}
	if len(p) > 0 {
		h.off += copy(h.buf[h.off:], p)
	}
	return
}

func (h *poly1305Hash) Sum(b []byte) []byte {
	var out [TagSize]byte
	state := h.state
	if h.off > 0 {
		update(&state, h.buf[:h.off])
	}
	finalize(&out, &state)
	return append(b, out[:]...)
}

type poly1305HashAVX2 struct {
	//  r[0] | r^2[0] | r[1] | r^2[1] | r[2] | r^2[2] | r[3] | r^2[3] | r[4] | r^2[4] | r[1]*5 | r^2[1]*5 | r[2]*5 | r^2[2]*5 r[3]*5 | r^2[3]*5 r[4]*5 | r^2[4]*5
	state [512]byte

	buffer [8 * TagSize]byte
	offset int
}

func (h *poly1305HashAVX2) Write(p []byte) (n int, err error) {
	n = len(p)
	if h.offset > 0 {
		remaining := 8*TagSize - h.offset
		if n <= remaining {
			h.offset += copy(h.buffer[h.offset:], p)
			return n, nil
		}
		copy(h.buffer[h.offset:], p[:remaining])
		updateAVX2(&h.state, h.buffer[:])
		p = p[remaining:]
		h.offset = 0
	}
	// process full 8*16-byte blocks
	if nn := len(p) & (^(8*TagSize - 1)); nn > 0 {
		updateAVX2(&h.state, p[:nn])
		p = p[nn:]
	}
	if len(p) > 0 {
		h.offset += copy(h.buffer[:], p)
	}
	return
}

func (h *poly1305HashAVX2) Sum(b []byte) []byte {
	var out [TagSize]byte
	state := h.state

	if h.offset > 0 {
		updateAVX2(&state, h.buffer[:h.offset])
	}
	finalizeAVX2(&out, &state)
	return append(b, out[:]...)
}
