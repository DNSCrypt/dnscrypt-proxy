// Copyright (c) 2016 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

// +build 386,!gccgo,!appengine,!nacl

#include "const.s"
#include "macro.s"

// FINALIZE xors len bytes from src and block using
// the temp. registers t0 and t1 and writes the result
// to dst.
#define FINALIZE(dst, src, block, len, t0, t1) \
	XORL t0, t0;       \
	XORL t1, t1;       \
	FINALIZE_LOOP:;    \
	MOVB 0(src), t0;   \
	MOVB 0(block), t1; \
	XORL t0, t1;       \
	MOVB t1, 0(dst);   \
	INCL src;          \
	INCL block;        \
	INCL dst;          \
	DECL len;          \
	JA   FINALIZE_LOOP \

// func supportsSSE2() bool
TEXT ·supportsSSE2(SB), NOSPLIT, $0-1
	XORL AX, AX
	INCL AX
	CPUID
	SHRL $26, DX
	ANDL $1, DX
	MOVB DX, ret+0(FP)
	RET

// func supportsSSSE3() bool
TEXT ·supportsSSSE3(SB), NOSPLIT, $0-1
	XORL AX, AX
	INCL AX
	CPUID
	SHRL $9, CX
	ANDL $1, CX
	MOVB CX, ret+0(FP)
	RET

#define Dst DI
#define Nonce AX
#define Key BX
#define Rounds CX

// func hChaCha20SSE2(out *[32]byte, nonce *[16]byte, key *[32]byte)
TEXT ·hChaCha20SSE2(SB), 4, $0-12
	MOVL out+0(FP), Dst
	MOVL nonce+4(FP), Nonce
	MOVL key+8(FP), Key

	MOVOU ·sigma<>(SB), X0
	MOVOU 0*16(Key), X1
	MOVOU 1*16(Key), X2
	MOVOU 0*16(Nonce), X3
	MOVL  $20, Rounds

chacha_loop:
	CHACHA_QROUND_SSE2(X0, X1, X2, X3, X4)
	CHACHA_SHUFFLE_SSE(X1, X2, X3)
	CHACHA_QROUND_SSE2(X0, X1, X2, X3, X4)
	CHACHA_SHUFFLE_SSE(X3, X2, X1)
	SUBL $2, Rounds
	JNZ  chacha_loop

	MOVOU X0, 0*16(Dst)
	MOVOU X3, 1*16(Dst)
	RET

// func hChaCha20SSSE3(out *[32]byte, nonce *[16]byte, key *[32]byte)
TEXT ·hChaCha20SSSE3(SB), 4, $0-12
	MOVL out+0(FP), Dst
	MOVL nonce+4(FP), Nonce
	MOVL key+8(FP), Key

	MOVOU ·sigma<>(SB), X0
	MOVOU 0*16(Key), X1
	MOVOU 1*16(Key), X2
	MOVOU 0*16(Nonce), X3
	MOVL  $20, Rounds

	MOVOU ·rol16<>(SB), X5
	MOVOU ·rol8<>(SB), X6

chacha_loop:
	CHACHA_QROUND_SSSE3(X0, X1, X2, X3, X4, X5, X6)
	CHACHA_SHUFFLE_SSE(X1, X2, X3)
	CHACHA_QROUND_SSSE3(X0, X1, X2, X3, X4, X5, X6)
	CHACHA_SHUFFLE_SSE(X3, X2, X1)
	SUBL $2, Rounds
	JNZ  chacha_loop

	MOVOU X0, 0*16(Dst)
	MOVOU X3, 1*16(Dst)
	RET

#undef Dst
#undef Nonce
#undef Key
#undef Rounds

#define State AX
#define Dst DI
#define Src SI
#define Len CX
#define Rounds DX
#define Tmp0 BX
#define Tmp1 BP

// func xorKeyStreamSSE2(dst, src []byte, block, state *[64]byte, rounds int) int
TEXT ·xorKeyStreamSSE2(SB), 4, $0-40
	MOVL dst_base+0(FP), Dst
	MOVL src_base+12(FP), Src
	MOVL src_len+16(FP), Len
	MOVL state+28(FP), State
	MOVL rounds+32(FP), Rounds

	MOVOU 0*16(State), X0
	MOVOU 1*16(State), X1
	MOVOU 2*16(State), X2
	MOVOU 3*16(State), X3
	TESTL Len, Len
	JZ    DONE

GENERATE_KEYSTREAM:
	MOVO X0, X4
	MOVO X1, X5
	MOVO X2, X6
	MOVO X3, X7
	MOVL Rounds, Tmp0

CHACHA_LOOP:
	CHACHA_QROUND_SSE2(X4, X5, X6, X7, X0)
	CHACHA_SHUFFLE_SSE(X5, X6, X7)
	CHACHA_QROUND_SSE2(X4, X5, X6, X7, X0)
	CHACHA_SHUFFLE_SSE(X7, X6, X5)
	SUBL $2, Tmp0
	JA   CHACHA_LOOP

	MOVOU 0*16(State), X0 // Restore X0 from state
	PADDL X0, X4
	PADDL X1, X5
	PADDL X2, X6
	PADDL X3, X7
	MOVOU ·one<>(SB), X0
	PADDQ X0, X3

	CMPL Len, $64
	JB   BUFFER_KEYSTREAM

	XOR_SSE(Dst, Src, 0, X4, X5, X6, X7, X0)
	MOVOU 0*16(State), X0    // Restore X0 from state
	ADDL  $64, Src
	ADDL  $64, Dst
	SUBL  $64, Len
	JZ    DONE
	JMP   GENERATE_KEYSTREAM // There is at least one more plaintext byte

BUFFER_KEYSTREAM:
	MOVL  block+24(FP), State
	MOVOU X4, 0(State)
	MOVOU X5, 16(State)
	MOVOU X6, 32(State)
	MOVOU X7, 48(State)
	MOVL  Len, Rounds         // Use Rounds as tmp. register for Len - we don't need Rounds anymore
	FINALIZE(Dst, Src, State, Rounds, Tmp0, Tmp1)

DONE:
	MOVL  state+28(FP), State
	MOVOU X3, 3*16(State)
	MOVL  Len, ret+36(FP)     // Number of bytes written to the keystream buffer - 0 iff Len mod 64 == 0
	RET

#undef State
#undef Dst
#undef Src
#undef Len
#undef Rounds
#undef Tmp0
#undef Tmp1

#define Dst DI
#define Src SI
#define Len CX
#define Rounds DX
#define State SP
#define Stack State
#define Tmp0 AX
#define Tmp1 BX
#define Tmp2 BP

// func xorKeyStreamSSSE3(dst, src []byte, block, state *[64]byte, rounds int) int
TEXT ·xorKeyStreamSSSE3(SB), 4, $80-40
	MOVL dst_base+0(FP), Dst
	MOVL src_base+12(FP), Src
	MOVL src_len+16(FP), Len
	MOVL state+28(FP), Tmp0
	MOVL rounds+32(FP), Rounds

	MOVL Stack, Tmp2 // save stack pointer
	ADDL $16, Stack  // ensure 16 byte stack alignment
	ANDL $-16, Stack

	MOVOU 0*16(Tmp0), X0
	MOVOU 1*16(Tmp0), X1
	MOVOU 2*16(Tmp0), X2
	MOVOU 3*16(Tmp0), X3
	TESTL Len, Len
	JZ    DONE

	MOVOU ·one<>(SB), X4
	MOVO  X0, 0*16(State)
	MOVO  X1, 1*16(State)
	MOVO  X2, 2*16(State)
	MOVO  X4, 3*16(Stack) // store constant on stack

	MOVOU ·rol16<>(SB), X1
	MOVOU ·rol8<>(SB), X2

GENERATE_KEYSTREAM:
	MOVO 0*16(State), X4
	MOVO 1*16(State), X5
	MOVO 2*16(State), X6
	MOVO X3, X7
	MOVL Rounds, Tmp0

CHACHA_LOOP:
	CHACHA_QROUND_SSSE3(X4, X5, X6, X7, X0, X1, X2)
	CHACHA_SHUFFLE_SSE(X5, X6, X7)
	CHACHA_QROUND_SSSE3(X4, X5, X6, X7, X0, X1, X2)
	CHACHA_SHUFFLE_SSE(X7, X6, X5)
	SUBL $2, Tmp0
	JA   CHACHA_LOOP

	PADDL 0*16(State), X4
	PADDL 1*16(State), X5
	PADDL 2*16(State), X6
	PADDL X3, X7
	PADDQ 3*16(Stack), X3

	CMPL Len, $64
	JB   BUFFER_KEYSTREAM

	XOR_SSE(Dst, Src, 0, X4, X5, X6, X7, X0)
	ADDL $64, Src
	ADDL $64, Dst
	SUBL $64, Len
	JZ   DONE
	JMP  GENERATE_KEYSTREAM

BUFFER_KEYSTREAM:
	MOVL  Tmp2, Stack        // restore stack pointer
	MOVL  Len, Tmp2
	MOVL  block+24(FP), Tmp1
	MOVOU X4, 0*16(Tmp1)
	MOVOU X5, 1*16(Tmp1)
	MOVOU X6, 2*16(Tmp1)
	MOVOU X7, 3*16(Tmp1)
	FINALIZE(DI, SI, Tmp1, Tmp2, Tmp0, Rounds)// we don't need the number of rounds anymore
	MOVL  Stack, Tmp2        // set BP to SP so that DONE resets SP correctly

DONE:
	MOVL  Tmp2, Stack        // restore stack pointer
	MOVL  state+28(FP), Tmp0
	MOVOU X3, 3*16(Tmp0)
	MOVL  Len, ret+36(FP)
	RET

#undef Dst
#undef Src
#undef Len
#undef Rounds
#undef State
#undef Stack
#undef Tmp0
#undef Tmp1
#undef Tmp2
