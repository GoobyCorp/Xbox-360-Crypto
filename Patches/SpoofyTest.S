	.globl _start
_start:
	mflr    r12
	std     r31, -0x10(r1)
	std     r12, -8(r1)
	stwu    r1, -0x100(r1)
	mr      r31, r4

	# Check to see if its Peek
	cmpwi   r31, 0x0
	beq     PeekBYTE
	cmpwi   r31, 0x1
	beq     PeekWORD
	cmpwi   r31, 0x2
	beq     PeekDWORD
	cmpwi   r31, 0x3
	beq     PeekQWORD
	cmpwi   r31, 0xA
	beq     PeekSPR
	cmpwi	r31, 0xC
	beq		HvExecute
	cmpwi   r31, 0xD
	beq     PeekMSR
	
	# Check to see if its Poke
	cmpwi   r31, 0x5
	beq     PokeBYTE
	cmpwi   r31, 0x6
	beq     PokeWORD
	cmpwi   r31, 0x7
	beq     PokeDWORD
	cmpwi   r31, 0x8
	beq     PokeQWORD
	cmpwi   r31, 0xB

	# We should never get here...
deadLoop:
	bge     deadLoop

	# Its either peek or poke data so lets get our dest address
	# Get function "HvpPhysicalToReal"
	lwz     r3, 0x4c(0)
	add     r3, r2, r3
	lwz     r3, 0x8(r3)
	mtctr   r3
	mr      r3, r6
	li      r4, 0x1
	bctrl
	mr      r6, r3
	mtctr   r7
	cmpwi   r31, 0x4
	beq     PeekBytes
	cmpwi   r31, 0x9
	beq     PokeBytes

	# We should never get here...
deadLoop2:
	b       deadLoop2

PeekSPR:
	bl      PatchPeekSPR

PatchPeekSPR:
	mr      r6, r5
	lis     r4, 0x7C60 # 0x7C6002A6
	insrwi  r6, r5, 0x5, 0x11
	ori     r4, r4, 0x2A6 # 0x7C6002A6
	rlwimi  r4, r6, 0x6, 0xB, 0x14
	mflr    r3
	addi    r3, r3, (ReadSPR - PatchPeekSPR) 
	stw     r4, 0(r3)
	dcbst   r0, r3
	icbi    r0, r3
	sync    0
	isync

ReadSPR:
	mfspr   r3, 0x40 # SPR_HRMOR
	b       Done

PeekBYTE:
	bl      check_fix_address
	lbz     r3, 0(r5)
	b       Done

PeekWORD:
	bl      check_fix_address
	lhz     r3, 0(r5)
	b       Done

PeekDWORD:
	bl      check_fix_address
	lwz     r3, 0(r5)
	b       Done

PeekQWORD:
	bl      check_fix_address
	ld      r3, 0(r5)
	b       Done

PeekBytes:
	bl      check_fix_address
PeekBytesLoop:
	lbz     r31, 0(r5)
	stb     r31, 0(r6)
	addi    r5, r5, 1
	addi    r6, r6, 1
	bdnz    PeekBytesLoop
	li      r3, 0
	b       Done

PeekMSR:
	mfmsr r3
	b     Done

# don't clobber r5 (source) or r6 (dest)
check_fix_address:
	# r4 = 0x8000020000020000
	lis     r4, 0x8000
	ori     r4, r4, 0x0200
	rldicr  r4, r4, 0x20, 0x1F
	oris    r4, r4, 0x2

    # clear r13 for use as CTR
    xor     r13, r13, r13
    li      r13, 0xC  # 0xC = number of fuse lines

    # clear r14 for use as fuse offset
    xor     r14, r14, r14
    li      r14, 0x60

    # set CTR to 0xC
	mtctr   r13

    # r4 = (0x8000020000020000 <-> 0x8000020000021600)
check_fix_address_loop:
    # compare r4 to r5 (source)
	cmpld   r5, r4

	# jump to check_fix_address_match if the address matches a fuseline
	beq     check_fix_address_match

	# subtract fuse size from r14 (fuse offset)
    subi    r14, r14, 0x8

    # increment address by 0x200
	addi    r4, r4, 0x200
	bdnz    check_fix_address_loop

    # loop fell through so return
	blr

check_fix_address_match:
	lis     r5, 1
	# subtract r14 (fuse offset) from r5 (source)
	subi    r5, r5, r14

	blr

PokeBYTE:
	stb     r6, 0(r5)
	b       PokeFlush

PokeWORD:
	sth     r6, 0(r5)
	b       PokeFlush

PokeDWORD:
	stw     r6, 0(r5)
	b       PokeFlush

PokeQWORD:
	std     r6, 0(r5)
	b       PokeFlush

# Copy dest = r5 src = r6 cnt = r7
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
	b		Done

PokeBytes:
	lbz     r31, 0(r6)
	stb     r31, 0(r5)
	dcbst   r0, r5
	icbi    r0, r5
	sync
	isync
	addi    r5, r5, 1
	addi    r6, r6, 1
	bdnz    PokeBytes

PokeFlush:
	li      r3, 0
	dcbst   r0, r5
	icbi    r0, r5
	sync
	isync

Done:
	addi    r1, r1, 0x100
	ld      r31, -0x10(r1)
	ld      r12, -8(r1)
	mtlr    r12
	blr
#============================================================================
	.end
#============================================================================
