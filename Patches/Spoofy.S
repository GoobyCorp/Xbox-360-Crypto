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
	bl		check_fix_address
	lbz		r3, 0(r5)
	b		Done

PeekWORD:
	bl		check_fix_address
	lhz		r3, 0(r5)
	b		Done

PeekDWORD:
	bl		check_fix_address
	lwz		r3, 0(r5)
	b		Done

PeekQWORD:
	bl		check_fix_address
	ld		r3, 0(r5)
	b		Done

PeekBytes:
	bl		check_fix_address
PeekBytesLoop:
	lbz		r31, 0(r5)
	stb		r31, 0(r6)
	addi	r5, r5, 1
	addi	r6, r6, 1
	bdnz	PeekBytesLoop
	li		r3, 0
	b		Done

# don't clobber r5 (source) or r6 (dest)
check_fix_address:
    # fuseline 0
	# r4 = 0x8000020000020000
	lis     r4, 0x8000
	ori     r4, r4, 0x0200
	rldicr  r4, r4, 32, 31
	oris    r4, r4, 0x2
	cmpld   r5, r4
	beq     fuseline_0

	# fuseline 1
	# r4 = 0x8000020000020200
	addi    r4, r4, 0x200
	cmpld   r5, r4
	beq     fuseline_1

	# fuseline 2
	# r4 = 0x8000020000020400
	addi    r4, r4, 0x200
	cmpld   r5, r4
	beq     fuseline_2

	# fuseline 3
	# r4 = 0x8000020000020600
	addi    r4, r4, 0x200
	cmpld   r5, r4
	beq     fuseline_3

	# fuseline 4
	# r4 = 0x8000020000020800
	addi    r4, r4, 0x200
	cmpld   r5, r4
	beq     fuseline_4

	# fuseline 5
	# r4 = 0x8000020000020A00
	addi    r4, r4, 0x200
	cmpld   r5, r4
	beq     fuseline_5

	# fuseline 6
	# r4 = 0x8000020000020C00
	addi    r4, r4, 0x200
	cmpld   r5, r4
	beq     fuseline_6

	# fuseline 7
	# r4 = 0x8000020000020E00
	addi    r4, r4, 0x200
	cmpld   r5, r4
	beq     fuseline_7

	# fuseline 8
	# r4 = 0x8000020000021000
	addi    r4, r4, 0x200
	cmpld   r5, r4
	beq     fuseline_8

	# fuseline 9
	# r4 = 0x8000020000021200
	addi    r4, r4, 0x200
	cmpld   r5, r4
	beq     fuseline_9

	# fuseline 10
	# r4 = 0x8000020000021400
	addi    r4, r4, 0x200
	cmpld   r5, r4
	beq     fuseline_10

	# fuseline 11
	# r4 = 0x8000020000021600
	addi    r4, r4, 0x200
	cmpld   r5, r4
	beq     fuseline_11

	blr
fuseline_0:
	lis     r5, 1
	subi	r5, r5, 0x60
	blr
fuseline_1:
	lis     r5, 1
	subi	r5, r5, 0x60
	addi    r5, r5, 0x8
	blr
fuseline_2:
	lis     r5, 1
	subi	r5, r5, 0x60
	addi    r5, r5, 0x10
	blr
fuseline_3:
	lis     r5, 1
	subi	r5, r5, 0x60
	addi    r5, r5, 0x18
	blr
fuseline_4:
	lis     r5, 1
	subi	r5, r5, 0x60
	addi    r5, r5, 0x20
	blr
fuseline_5:
	lis     r5, 1
	subi	r5, r5, 0x60
	addi    r5, r5, 0x28
	blr
fuseline_6:
	lis     r5, 1
	subi	r5, r5, 0x60
	addi    r5, r5, 0x30
	blr
fuseline_7:
	lis     r5, 1
	subi	r5, r5, 0x60
	addi    r5, r5, 0x38
	blr
fuseline_8:
	lis     r5, 1
	subi	r5, r5, 0x60
	addi    r5, r5, 0x40
	blr
fuseline_9:
	lis     r5, 1
	subi	r5, r5, 0x60
	addi    r5, r5, 0x48
	blr
fuseline_10:
	lis     r5, 1
	subi	r5, r5, 0x60
	addi    r5, r5, 0x50
	blr
fuseline_11:
	lis     r5, 1
	subi	r5, r5, 0x60
	addi    r5, r5, 0x58
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
