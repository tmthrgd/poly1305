// Created by poly1305_x64.pl - DO NOT EDIT
// perl poly1305_x64.pl golang poly1305_x64_amd64.s

// +build amd64,!gccgo,!appengine

#include "textflag.h"

DATA LrSet<>+0x00(SB)/8, $0x0FFFFFFC0FFFFFFF
DATA LrSet<>+0x08(SB)/8, $0x0FFFFFFC0FFFFFFC
GLOBL LrSet<>(SB), RODATA, $16

TEXT ·poly1305_init_x64(SB),$0-16
	MOVQ	state+0(FP),DI
	MOVQ	key+8(FP),SI

	XORQ	AX,AX
	MOVQ	AX,8*0(DI)
	MOVQ	AX,8*1(DI)
	MOVQ	AX,8*2(DI)

	// MOVDQU	16*0(SI),X0
	BYTE $0xf3; BYTE $0x0f; BYTE $0x6f; BYTE $0x06
	// MOVDQU	16*1(SI),X1
	BYTE $0xf3; BYTE $0x0f; BYTE $0x6f; BYTE $0x4e; BYTE $0x10
	PAND	LrSet<>(SB),X0

	// MOVDQU	X0,8*3(DI)
	BYTE $0xf3; BYTE $0x0f; BYTE $0x7f; BYTE $0x47; BYTE $0x18
	// MOVDQU	X1,8*3+16(DI)
	BYTE $0xf3; BYTE $0x0f; BYTE $0x7f; BYTE $0x4f; BYTE $0x28
	MOVQ	$0,8*7(DI)

	RET

TEXT ·poly1305_update_x64(SB),$0-24
	MOVQ	state+0(FP),DI
	MOVQ	in+8(FP),SI
	MOVQ	in_len+16(FP),DX

	MOVQ	DX,R10

	MOVQ	8*0(DI),BX
	MOVQ	8*1(DI),R8
	MOVQ	8*2(DI),R9
	MOVQ	8*3(DI),R15

	CMPQ	R10,$16
	JB	label2a
	JMP	label1a

label1a:

	ADDQ	8*0(SI),BX
	ADCQ	8*1(SI),R8
	LEAQ	16(SI),SI
	ADCQ	$1,R9

label5a:
	MOVQ	R15,AX
	MULQ	BX
	MOVQ	AX,R11
	MOVQ	DX,R12

	MOVQ	R15,AX
	MULQ	R8
	ADDQ	AX,R12
	ADCQ	$0,DX

	MOVQ	R15,R13
	IMULQ	R9,R13
	ADDQ	DX,R13

	MOVQ	8*4(DI),AX
	MULQ	BX
	ADDQ	AX,R12
	ADCQ	$0,DX
	MOVQ	DX,BX

	MOVQ	8*4(DI),AX
	MULQ	R8
	ADDQ	BX,R13
	ADCQ	$0,DX
	ADDQ	AX,R13
	ADCQ	$0,DX

	MOVQ	8*4(DI),R14
	IMULQ	R9,R14
	ADDQ	DX,R14


	MOVQ	R11,BX
	MOVQ	R12,R8
	MOVQ	R13,R9
	ANDQ	$3,R9

	MOVQ	R13,R11
	MOVQ	R14,R12

	ANDQ	$-4,R11
	// SHRDQ	$2,R14,R13
	BYTE $0x4d; BYTE $0x0f; BYTE $0xac; BYTE $0xf5; BYTE $0x02
	SHRQ	$2,R14

	ADDQ	R11,BX
	ADCQ	R12,R8
	ADCQ	$0,R9

	ADDQ	R13,BX
	ADCQ	R14,R8
	ADCQ	$0,R9

	SUBQ	$16,R10
	CMPQ	R10,$16
	JAE	label1a

label2a:
	TESTQ	R10,R10
	JZ	label3a

	MOVQ	$1,R11
	XORQ	R12,R12
	XORQ	R13,R13
	ADDQ	R10,SI

label4a:
	// SHLDQ	$8,R11,R12
	BYTE $0x4d; BYTE $0x0f; BYTE $0xa4; BYTE $0xdc; BYTE $0x08
	SHLQ	$8,R11
	// MOVZXB	-1(SI),R13
	BYTE $0x4c; BYTE $0x0f; BYTE $0xb6; BYTE $0x6e; BYTE $0xff
	XORQ	R13,R11
	DECQ	SI
	DECQ	R10
	JNZ	label4a

	ADDQ	R11,BX
	ADCQ	R12,R8
	ADCQ	$0,R9

	MOVQ	$16,R10
	JMP	label5a

label3a:

	MOVQ	BX,8*0(DI)
	MOVQ	R8,8*1(DI)
	MOVQ	R9,8*2(DI)

	RET

TEXT ·poly1305_finish_x64(SB),$0-16
	MOVQ	state+0(FP),DI
	MOVQ	mac+8(FP),SI

	MOVQ	8*0(DI),BX
	MOVQ	8*1(DI),AX
	MOVQ	8*2(DI),DX

	MOVQ	BX,R8
	MOVQ	AX,R9
	MOVQ	DX,R10

	SUBQ	$-5,BX
	SBBQ	$-1,AX
	SBBQ	$3,DX

	CMOVQCS	R8,BX
	CMOVQCS	R9,AX
	CMOVQCS	R10,DX

	ADDQ	8*5(DI),BX
	ADCQ	8*6(DI),AX
	MOVQ	BX,(SI)
	MOVQ	AX,8(SI)

	RET

