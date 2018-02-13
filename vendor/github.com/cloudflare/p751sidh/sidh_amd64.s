#include "textflag.h"

// Digits of 3^238 - 1
#define THREE238M1_0 $0xedcd718a828384f8
#define THREE238M1_1 $0x733b35bfd4427a14
#define THREE238M1_2 $0xf88229cf94d7cf38
#define THREE238M1_3 $0x63c56c990c7c2ad6
#define THREE238M1_4 $0xb858a87e8f4222c7
#define THREE238M1_5 $0x254c9c6b525eaf5

TEXT ·checkLessThanThree238(SB), NOSPLIT, $0-16
	MOVQ	scalar+0(FP), SI
	MOVQ 	result+8(FP), DI

	XORQ	AX, AX

	// Set [R10,...,R15] = 3^238
	MOVQ	THREE238M1_0, R10
	MOVQ	THREE238M1_1, R11
	MOVQ	THREE238M1_2, R12
	MOVQ	THREE238M1_3, R13
	MOVQ	THREE238M1_4, R14
	MOVQ	THREE238M1_5, R15

	// Set [R10,...,R15] = 3^238 - scalar
	SUBQ	    (SI), R10
	SBBQ	 (8)(SI), R11
	SBBQ	(16)(SI), R12
	SBBQ	(24)(SI), R13
	SBBQ	(32)(SI), R14
	SBBQ	(40)(SI), R15

	// Save borrow flag indicating 3^238 - scalar < 0 as a mask in AX (eax)
	SBBL	$0, AX
	MOVL	AX, (DI)

	RET

TEXT ·multiplyByThree(SB), NOSPLIT, $0-8
	MOVQ	scalar+0(FP), SI
	
	// Set [R10,...,R15] = scalar
	MOVQ	    (SI), R10
	MOVQ	 (8)(SI), R11
	MOVQ	(16)(SI), R12
	MOVQ	(24)(SI), R13
	MOVQ	(32)(SI), R14
	MOVQ	(40)(SI), R15

	// Add scalar twice to compute 3*scalar
	ADDQ	R10, (SI)
	ADCQ	R11, (8)(SI)
	ADCQ	R12, (16)(SI)
	ADCQ	R13, (24)(SI)
	ADCQ	R14, (32)(SI)
	ADCQ	R15, (40)(SI)
	ADDQ	R10, (SI)
	ADCQ	R11, (8)(SI)
	ADCQ	R12, (16)(SI)
	ADCQ	R13, (24)(SI)
	ADCQ	R14, (32)(SI)
	ADCQ	R15, (40)(SI)

	RET

