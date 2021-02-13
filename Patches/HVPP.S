# Xbox 360 HV Peek/Poke Expansion

.globl _start

_start:
	mflr	r12
	std		r31, -0x10(r1)
	std		r12, -8(r1)
	stwu	r1, -0x100(r1)
	mr		r31, r4
	cmpwi	r31, 0
	beq		PeekBYTE
	cmpwi	r31, 1
	beq		PeekWORD
	cmpwi	r31, 2
	beq		PeekDWORD
	cmpwi	r31, 3
	beq		PeekQWORD
	cmpwi	r31, 0xA
	beq		PeekSPR
	cmpwi	r31, 0xC
	beq		HvExecute
	cmpwi	r31, 5
	beq		PokeByte
	cmpwi	r31, 6
	beq		PokeWORD
	cmpwi	r31, 7
	beq		PokeDWORD
	cmpwi	r31, 8
	beq		PokeQWORD
	cmpwi	r31, 0xB

deadLoop:
	bge		deadLoop
	
	lwz		r3, 0x4c(0) # Get function "HvpPhysicalToReal", table offset at 0x4c of hv
	add		r3, r2, r3
	lwz		r3, 8(r3) 	# Get function "HvpPhysicalToReal", function is second in table at 0x4c's offset
	mtctr	r3
	mr		r3, r6
	li		r4, 1
	bctrl				# Call function "HvpPhysicalToReal",
	mr		r6, r3
	mtctr	r7
	cmpwi	r31, 4
	beq		PeekBytes
	cmpwi	r31, 9
	beq		PokeBytes

PeekSPR:
	bl		PatchPeekSPR

PatchPeekSPR:
	mr		r6, r5
	lis		r4, 0x7C60 # 0x7C6002A6
	insrwi	r6, r5, 5, 17
	ori		r4, r4, 0x2A6	# 0x7C6002A6
	rlwimi	r4, r6, 6, 11, 20
	mflr	r3
	addi	r3, r3, (ReadSPR - PatchPeekSPR) 
	stw		r4, 0(r3)
	dcbst	r0, r3
	icbi	r0, r3
	sync
	isync

ReadSPR:
	mfspr	r3, 64 # SPR_HRMOR just a placeholder, this instruction gets patched above
	b		Exit1

PeekBYTE:
	lbz		r3, 0(r5)
	b		Exit1

PeekWORD:
	lhz		r3, 0(r5)
	b		Exit1

PeekDWORD:
	lwz		r3, 0(r5)
	b		Exit1

PeekQWORD:
	ld		r3, 0(r5)
	b		Exit1

PeekBytes:
	lbz		r31, 0(r5)
	stb		r31, 0(r6)
	addi	r5, r5, 1
	addi	r6, r6, 1
	bdnz	PeekBytes
	li		r3, 0
	b		Exit1

PokeByte:
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

# Copy dest=r5 src = r6 cnt = r7
HvExecute:
	mtlr	r5
	mtctr	r7
lcopyloop:
	lwz		r4, 0(r6)
	stw		r4, 0(r5)
	dcbst	r0, r5    
	icbi	r0, r5
	sync    0
	isync
	addi    r5, r5, 4
	addi    r6, r6, 4
	bdnz    lcopyloop
	blr
	b		Exit1

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

Exit1:
	addi	r1, r1, 0x100
	ld		r31, -0x10(r1)
	ld		r12, -8(r1)
	mtlr	r12
	blr

# End of function PayloadEntryPoint


