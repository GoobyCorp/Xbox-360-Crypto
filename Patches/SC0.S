#============================================================================
#   Syscall Zero Payload
#============================================================================

# mode == 4  # HV execute
# r3 (magic), r4 (mode), r5 (target), r6 (source), and r7 (size)
# mode == 5  # Peek bytes
# r3 (magic), r4 (mode), r5 (source), r6 (dest), and r7 (size)

# devkit/retail
.set HvpGetSocMMIORegs, 0x6A0

.if DEVKIT == 1
    # devkit - 17489/21256.18
    .set HvxGetVersions, 0x1B98
    .set memcpy, 0xA4E0
.elseif RETAIL == 1
    # retail - 17559
    .set HvxGetVersions, 0x1CC8
    .set memcpy, 0xA880
.else
    .abort  # DEVKIT or RETAIL must be defined!
.endif

    .globl _start
_start:
    lis     r11, 0x7262
    ori     r11, r11, 0x7472
    cmplw   cr6, r3, r11
    beq     cr6, LAB_00000014
    ba      HvxGetVersions

LAB_00000014:
    cmplwi  cr6, r4, 0x4
    bgt     cr6, HvPeekPoke
    beq     cr6, HvExecute
    li      r5, 0x154C
    lis     r6, 0x3880
    cmplwi  cr6, r4, 0x2
    bne     cr6, LAB_00000038
    ori     r6, r6, 0x7
    b       LAB_00000040

LAB_00000038:
    cmplwi  cr6, r4, 0x3
    bne     cr6, ReturnONE

LAB_00000040:
    li      r0, 0
    stw     r6, 0(r5)
    dcbst   r0, r5
    icbi    r0, r5
    sync    0
    isync

ReturnONE:
    li      r3, 0x1
    blr

HvExecute:
    mflr    r12
    std     r12, -0x8(r1)
    stdu    r1, -0x10(r1)
    mtlr    r5
    mtctr   r7

lcopyloop:
    lwz     r4, 0(r6)
    stw     r4, 0(r5)
    dcbst   r0, r5
    icbi    r0, r5
    sync    0
    isync
    addi    r5, r5, 0x4
    addi    r6, r6, 0x4
    bdnz    lcopyloop
    blr

LAB_0000009C:
    addi    r1, r1, 0x10
    ld      r12, -0x8(r1)
    mtlr    r12
    blr

HvPeekPoke:
    cmplwi  cr6, r4, 0x5
    bne     cr6, ReturnTWO

.if SPOOFY == 1
    b       peek_check_fix_address
HvPeekPoke_resumed:
.endif

    mr      r3, r6
    mr      r4, r5
    mr      r5, r7
    ba      memcpy

ReturnTWO:
    li      r3, 0x2
    blr

.if SPOOFY == 1
peek_check_fix_address:
    # r5 (source), r6 (dest), and r7 (size)

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
    # bltlr
    blt     HvPeekPoke_resumed
    # r4 = r4 + 0x1600
    # r4 = 0x8000020000021600
    ori     r4, r4, 0x1600
    # r5 > r4
    # r5 > 0x8000020000021600
    cmpld   r5, r4
    # bgtlr
    bgt     HvPeekPoke_resumed

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
    # bltlr
    blt     HvPeekPoke_resumed
    # r12 > 0xC
    cmpwi   r12, 0xC
    # bgtlr
    bgt     HvPeekPoke_resumed

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
    b       HvPeekPoke_resumed
.endif

#============================================================================
    .end
#============================================================================
