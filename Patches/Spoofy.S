#============================================================================
#    Spoofy
#============================================================================

/*
typedef enum {
	PeekBYTE  = 0,
	PeekWORD  = 1,
	PeekDWORD = 2,
	PeekQWORD = 3,
	PeekBytes = 4,
	PeekSPR   = 0xA,
	PeekMSR   = 0xB,

	PokeBYTE  = 5,
	PokeWORD  = 6,
	PokeDWORD = 7,
	PokeQWORD = 8,
	PokeBytes = 9,

	PeekBYTEBypass = 0xC,
	PeekWORDBypass = 0xD,
	PeekDWORDBypass = 0xE,
	PeekQWORDBypass = 0xF,
	PeekBytesBypass = 0x10,

	PokeBYTEBypass  = 0x11,
	PokeWORDBypass  = 0x12,
	PokeDWORDBypass = 0x13,
	PokeQWORDBypass = 0x14,
	PokeBytesBypass = 0x15,
};
*/

# devkit/retail
.set HvpGetSocMMIORegs, 0x6A0

.if DEVKIT == 1
    # devkit - 17489/21256.18
    .set HvpPhysicalToReal, 0x2828
    .set memcpy, 0xA4E0
.elseif RETAIL == 1
    # retail - 17559
    .set HvpPhysicalToReal, 0x29D8
    .set memcpy, 0xA880
.else
    .abort  # DEVKIT or RETAIL must be defined!
.endif

    .globl _start
_start:
    mflr    r12
    std     r31, -0x28(r1)
    std     r15, -0x20(r1)
    std     r14, -0x18(r1)
    std     r13, -0x10(r1)
    std     r12, -8(r1)
    stwu    r1, -0x100(r1)
    mr      r31, r4

    # peek
    cmpwi   r31, 0x0
    beq     PeekBYTE
    cmpwi   r31, 0x1
    beq     PeekWORD
    cmpwi   r31, 0x2
    beq     PeekDWORD
    cmpwi   r31, 0x3
    beq     PeekQWORD
    cmpwi   r31, 0x4
    beq     PeekBytes
    cmpwi   r31, 0xA
    beq     PeekSPR
    cmpwi   r31, 0xB
    beq     PeekMSR
    
    # poke
    cmpwi   r31, 0x5
    beq     PokeBYTE
    cmpwi   r31, 0x6
    beq     PokeWORD
    cmpwi   r31, 0x7
    beq     PokeDWORD
    cmpwi   r31, 0x8
    beq     PokeQWORD
    cmpwi   r31, 0x9
    beq     PokeBytes

    # peek bypasses
    cmpwi   r31, 0xC
    beq     PeekBYTEBypass
    cmpwi   r31, 0xD
    beq     PeekWORDBypass
    cmpwi   r31, 0xE
    beq     PeekDWORDBypass
    cmpwi   r31, 0xF
    beq     PeekQWORDBypass
    cmpwi   r31, 0x10
    beq     PeekBytesBypass

    # poke bypasses
    cmpwi   r31, 0x11
    beq     PokeBYTEBypass
    cmpwi   r31, 0x12
    beq     PokeWORDBypass
    cmpwi   r31, 0x13
    beq     PokeDWORDBypass
    cmpwi   r31, 0x14
    beq     PokeQWORDBypass
    cmpwi   r31, 0x15
    beq     PokeBytesBypass

    cmpwi   r31, 0x16

    # We should never get here #1...
deadLoop1:
    bge     deadLoop1

    # We should never get here #2...
deadLoop2:
    b       deadLoop2

peek_check_fix_address:
    /* Cipher (and possibly xbOnline) spoofing
    This prevents the syscall zero payload from being copied */

    # r5 (source), r6 (dest), and r7 (size)

    # Check for write to 0xB200 for modified syscall
    # r3 = 0
    li      r3, 0
    # r4 = 0
    li      r4, 0
    # r4 = r4 | 0xFFFF
    # r4 = 0xFFFF
    ori     r4, r4, 0xFFFF
    # r3 = r5 & r4
    # r3 = r5 & 0xFFFF
    and     r3, r5, r4
    # r4 = 0
    li      r4, 0
    # r4 = 0xB200
    ori     r4, r4, 0xB200

    # r3 == r4
    # r3 == 0xB200
    cmpw    r3, r4
    bne     (. + 8)  # skip two instructions
    # r7 == 0x1000
    cmpwi   r7, 0x1000
    beq     PeekPokeBytesDone

    # CPU key spoofing
    # r4 = 0
    li      r4, 0

    # r4 = 0x8000020000020000
    lis     r4, 0x8000
	ori     r4, r4, 0x0200
	rldicr  r4, r4, 0x20, 0x1F
	oris    r4, r4, 0x2

    # sanity check #1
    # r5 < r4
    # r5 < 0x8000020000020000
    cmpld   r5, r4
    bltlr
    # r4 = r4 + 0x1600
    # r4 = 0x8000020000021600
    ori     r4, r4, 0x1600
    # r5 > r4
    # r5 > 0x8000020000021600
    cmpld   r5, r4
    bgtlr

    # r4 = r4 ^ 0x1600
    # r4 = 0x8000020000021600 ^ 0x1600
    # r4 = 0x8000020000021600 - 0x1600
    # r4 = 0x8000020000020000
    xori    r4, r4, 0x1600

    # r12 = 0x1FFF
    li      r12, 0x1FFF
    # r12 = r5 & r12
    # r12 = r5 & 0x1FFF
    and     r12, r5, r12

    # r12 //= 0x200
    srwi    r12, r12, 9  # pow(2, 9) == 0x200 (512)

    # sanity check #2
    # r12 < 0
    cmpwi   r12, 0
    bltlr
    # r12 > 0xC
    cmpwi   r12, 0xC
    bgtlr

    # r13 = 0
    li      r13, 0
    # r13 = 0x60
    li      r13, 0x60

    # r14 = 0
    li      r14, 0
    # r14 = r12 * 8
    slwi    r14, r12, 3  # pow(2, 3) == 0x8 (8)
    # r14 = r13 - r14
    sub     r14, r13, r14

    # r15 = 0
    li      r15, 0
    # r15 = r12 * 0x200
    slwi    r15, r12, 9  # pow(2, 9) == 0x200 (512)

    # r4 = r4 + r15
    or      r4, r4, r15

    # r5 = (1 << 16)
    lis     r5, 1
    # r5 = r5 - r14
    sub     r5, r5, r14

    # return;
    blr

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
    bl      peek_check_fix_address
PeekBYTEBypass:
    lbz     r3, 0(r5)
    b       Done

PeekWORD:
    bl      peek_check_fix_address
PeekWORDBypass:
    lhz     r3, 0(r5)
    b       Done

PeekDWORD:
    bl      peek_check_fix_address
PeekDWORDBypass:
    lwz     r3, 0(r5)
    b       Done

PeekQWORD:
    bl      peek_check_fix_address
PeekQWORDBypass:
    ld      r3, 0(r5)
    b       Done

PeekBytes:
    # HvxExpansionCall(EXPANSION_SIG, PeekBytesBypass, Address, daddr, Size);
    # r5 (source), r6 (dest), and r7 (size)
    bl      peek_check_fix_address
PeekBytesBypass:
    mr      r3, r6
    mr      r4, r7

    bla     HvpPhysicalToReal

    mr      r4, r5
    mr      r5, r7

    # r3 (dest), r4 (source), r5 (size)
    bla     memcpy

    b       PeekPokeBytesDone

PeekMSR:
    mfmsr   r3
    b       Done

poke_check_fix_address:
    /* Cipher (and possibly xbOnline) spoofing
    This prevents the syscall zero payload from being copied */

    # r5 (dest), r6 (source), and r7 (size)

    # Check for write to 0xB200 for modified syscall
    # r3 = 0
    li      r3, 0
    # r4 = 0
    li      r4, 0
    # r4 = r4 | 0xFFFF
    # r4 = 0xFFFF
    ori     r4, r4, 0xFFFF
    # r3 = r5 & r4
    # r3 = r5 & 0xFFFF
    and     r3, r5, r4
    # r4 = 0
    li      r4, 0
    # r4 = 0xB200
    ori     r4, r4, 0xB200

    # r3 == r4
    # r3 == 0xB200
    cmpw    r3, r4
    bne     (. + 8)  # skip two instructions
    # r7 == 0xCC
    cmpwi   r7, 0xCC
    beq     PeekPokeBytesDone

    # Check for write to syscall zero pointer in the syscall table
    # r3 = 0
    li      r3, 0
    # r4 = 0
    li      r4, 0
    # r4 = (0xF << 16)
    oris    r4, r4, 0xF
    # r4 += 0xFFFF
    ori     r4, r4, 0xFFFF
    # r3 = r5 & r4
    and     r3, r5, r4

    # r4 = 0
    li      r4, 0
    # r4 = (1 << 16)
    oris    r4, r4, 1
    # r4 += 0x5EC0
    ori     r4, r4, 0x5EC0

    # r3 == r4
    cmpw    r3, r4
    beq     PeekPokeBytesDone

    blr

PokeBYTE:
    bl      poke_check_fix_address
PokeBYTEBypass:
    stb     r6, 0(r5)
    b       PokeFlush

PokeWORD:
    bl      poke_check_fix_address
PokeWORDBypass:
    sth     r6, 0(r5)
    b       PokeFlush

PokeDWORD:
    bl      poke_check_fix_address
PokeDWORDBypass:
    stw     r6, 0(r5)
    b       PokeFlush

PokeQWORD:
    bl      poke_check_fix_address
PokeQWORDBypass:
    std     r6, 0(r5)
    b       PokeFlush

PokeBytes:
    # HvxExpansionCall(EXPANSION_SIG, PokeBytesBypass, Address, daddr, Size);
    # r5 (dest), r6 (source), and r7 (size)
    bl      poke_check_fix_address
PokeBytesBypass:
    mr      r3, r6
    mr      r4, r7

    bla     HvpPhysicalToReal

    mr      r4, r3
    mr      r3, r5
    mr      r5, r7

    # r3 (dest), r4 (source), r5 (size)
    bla     memcpy

    b       PeekPokeBytesDone

PokeFlush:
    li      r3, 0
    dcbst   r0, r5
    icbi    r0, r5
    sync    0
    isync

PeekPokeBytesDone:
    li      r3, 0

Done:
    addi    r1, r1, 0x100
    ld      r31, -0x28(r1)
    ld      r15, -0x20(r1)
    ld      r14, -0x18(r1)
    ld      r13, -0x10(r1)
    ld      r12, -8(r1)
    mtlr    r12
    blr
#============================================================================
    .end
#============================================================================
