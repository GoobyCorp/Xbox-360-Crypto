.set nand_patch_offset, 0x00100000
.set HvpGetFlashBaseAddress, 0x0000068C
.set HvpFlashCopy, 0x00000484 # XeCryptCopyQwVec(void* dest, void* src, int iter)
.set HvpMemCpy, 0x0000A4E0 #  memcpy(void *destination, const void *source, int len)

    .globl _start
_start:
0:
	mflr	r12
	std		r31, -0x10(r1)
	std		r12, -8(r1)
	stwu	r1, -0x100(r1)
	mr		r31, r4

	# Check to see if its Peek
	cmpwi	r31, 0
	beq		PeekBYTE
	cmpwi	r31, 1
	beq		PeekWORD
	cmpwi	r31, 2
	beq		PeekDWORD
	cmpwi	r31, 3
	beq		PeekQWORD
	cmpwi	r31, 10
	beq		PeekSPR
	
	# Check to see if its Poke
	cmpwi	r31, 5
	beq		PokeBYTE
	cmpwi	r31, 6
	beq		PokeWORD
	cmpwi	r31, 7
	beq		PokeDWORD
	cmpwi	r31, 8
	beq		PokeQWORD
	cmpwi	r31, 0xB

	# We should never get here...
deadLoop: 
	bge		deadLoop

	# Its either peek or poke data so lets get our dest address
	# Get function "HvpPhysicalToReal"
	lwz		r3, 0x4c(0)
	add		r3, r2, r3
	lwz		r3, 8(r3)
	mtctr	r3
	mr		r3, r6
	li		r4, 1
	bctrl
	mr		r6, r3
	mtctr	r7
	cmpwi	r31, 4
	beq		PeekBytes
	cmpwi	r31, 9
	beq		PokeBytes

	# We should never get here...
deadLoop2:
	b		deadLoop2

PeekSPR: 
	bl		PatchPeekSPR

PatchPeekSPR:
	mr		r6, r5
	lis		r4, 0x7C60 # 0x7C6002A6
	insrwi	r6, r5, 5,17
	ori		r4, r4, 0x2A6 # 0x7C6002A6
	rlwimi	r4, r6, 6,11,20
	mflr	r3
	addi	r3, r3, (ReadSPR - PatchPeekSPR) 
	stw		r4, 0(r3) 
	dcbst	r0, r3
	icbi	r0, r3
	sync	0
	isync

ReadSPR:
	mfspr	r3, 64 # SPR_HRMOR
	b		Done

PeekBYTE:					
	bl		CheckFixAddr
	lbz		r3, 0(r5)
	b		Done

PeekWORD:					
	bl		CheckFixAddr
	lhz		r3, 0(r5)
	b		Done

PeekDWORD:					
	bl		CheckFixAddr
	lwz		r3, 0(r5)
	b		Done

PeekQWORD:					
	bl		CheckFixAddr
	ld		r3, 0(r5)
	b		Done

PeekBytes:
	bl		CheckFixAddr
PeekBytesLoop:
	lbz		r31, 0(r5)
	stb		r31, 0(r6)
	addi	r5, r5, 1
	addi	r6, r6, 1
	bdnz	PeekBytesLoop
	li		r3, 0
	b		Done

CheckFixAddr: # don't clobber r5 (source) or r6 (dest)
    # 0x10000 - 0x40
    lis		r3, 1  # FakeFuseAddr
	subi	r3, r3, 0x40

	lwz		r4, 0(r3)
	cmplwi  cr6, r4, 0
	beq		cr6, no_ff
	cmpldi 	cr6, r5, 0x30  # r5 < 0x31
	bgt		cr6, no_hvfuse
	cmpldi	cr6, r5, 0x20  # r5 > 0x20
	blt		cr6, no_ff
	add		r5, r5, r3	#if reading between 0x20 and 0x30 add fake fuse address and do memcpy (not bulletproof, one could just read from 0x10 on or similar...)
	subi	r5, r5, 0x20
	blr
	
no_hvfuse:
    # 0x8000020000020600 - 0x8000020000020A00 first half of cpu key mirrors
	lis     r4, 0x8000
	ori     r4, r4, 0x0200
	rldicr  r4, r4, 32, 31
	oris    r4, r4, 0x2
	ori		r4, r4, 0x600	# 8000020000020600
	cmpld	cr6, r5, r4
	blt		cr6, no_ff		# address < 0x8000020000020600
	addi	r4, r4, 0x400	# 8000020000020A00
	cmpld	cr6, r5, r4
	bge		cr6, sec_ff		# address >= 0x8000020000020A00
	mr		r5, r3
	li		r7, 0x8
	b		no_ff
	# 0x8000020000020A00 - 0x8000020000020E00 second half of cpu key mirrors
sec_ff:	
	addi	r4, r4, 0x400	# 8000020000020E00
	cmpld	cr6, r5, r4
	bge		cr6, no_ff		# address >= 0x8000020000020E00
	mr		r5, r3
	addi	r5, r5, 0x8
	li		r7, 0x8
no_ff:
	blr

PokeBYTE:
	stb		r6, 0(r5)
	b		PokeFlush

PokeWORD:					
	sth		r6, 0(r5)
	b		PokeFlush

PokeDWORD:					
	stw		r6, 0(r5)
	b		PokeFlush

PokeQWORD:					
	std		r6, 0(r5)
	b		PokeFlush

PokeBytes:
	lbz		r31, 0(r6)
	stb		r31, 0(r5)
	dcbst	r0, r5
	icbi	r0, r5
	sync
	isync
	addi	r5, r5, 1
	addi	r6, r6, 1
	bdnz	PokeBytes

PokeFlush:
	li		r3, 0
	dcbst	r0, r5
	icbi	r0, r5
	sync
	isync

Done:
	addi	r1, r1, 0x100
	ld		r31, -0x10(r1)
	ld		r12, -8(r1)
	mtlr	r12
	blr
9:
#============================================================================
	.end
#============================================================================
