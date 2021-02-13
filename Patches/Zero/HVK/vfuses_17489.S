# VFuse patches for 17489/21256.18

.include "macros.S"

#============================================================================
#   Patches for Hypervisor 21256.18_17489
#============================================================================
	.globl _start
_start:

#============================================================================
#   disable copying transform key from SoC
#============================================================================
	MAKEPATCH 0x00002D04
0:
	nop
9:

#============================================================================
# pbkey xex2key make transform key 81300D49C232F145
#============================================================================
	MAKEPATCH  0x00000018
0:
	.long 0x81300D49
	.long 0xC232F145
9:

#============================================================================
#   Setup Fuse Row Pointer to point at Virtual Fuses
#   Change Increment and Range Check of Fuse Row Pointer
#============================================================================
    MAKEPATCH 0x00001BE0
0:
    bla     FixFusesAddr
9:
#--------------------------------------
    MAKEPATCH 0x00001BF4
0:
    addi    r11, r11, 0x0001
    cmplwi  cr6, r11, 0x000c
9:
#------blow fuses ?CORONA? !!! ISNT CORRECT!!!-----------
    MAKEPATCH 0x00008038
0:
    bla     FixFusesAddr
9:
# ;--------------------------------------
    MAKEPATCH 0x00008058
0:
    addi    r11, r11, 0x0001
9:
# ;--------------------------------------
    MAKEPATCH 0x00008064
0:
    cmplwi  cr6, r11, 0x000c
9:
#--------------------------------------------------
    MAKEPATCH 0x00009438
0:
    bla     FixFusesAddr
9:
#--------------------------------------
    MAKEPATCH 0x00009468
0:
    addi    r11, r11, 0x0001
    cmplwi  cr6, r11, 0x000c
9:
#--------------------------------------------------
    MAKEPATCH 0x000095D8
0:
    bla     FixFusesAddr
9:
#--------------------------------------
    MAKEPATCH 0x00009608
0:
    addi    r11, r11, 0x0001
    cmplwi  cr6, r11, 0x000c
9:
#--------------------------------------------------
    MAKEPATCH 0x0000972C
0:
    bla     FixFusesAddr
9:
#--------------------------------------
    MAKEPATCH 0x0000975C
0:
    addi    r11, r11, 0x0001
    cmplwi  cr6, r11, 0x000c
9:
#--------------------------------------------------
    MAKEPATCH 0x00009A58
0:
    bla     FixFusesAddr
9:
#--------------------------------------
    MAKEPATCH 0x00009A88
0:
    addi    r11, r11, 0x0001
    cmplwi  cr6, r11, 0x000c
9:
#--------------------------------------------------
    MAKEPATCH 0x00009DE4
0:
    bla     FixFusesAddr
9:
#--------------------------------------
    MAKEPATCH 0x00009E14
0:
    addi    r11, r11, 0x0001
    rldicr  r9, r9, 3,60
    cmpwi   cr6, r11, 0x000c
9:
#--------------------------------------------------
    MAKEPATCH 0x0000A0D8
0:
    bla     FixFusesAddr
9:
#--------------------------------------
    MAKEPATCH 0x0000A104
0:
    addi    r11, r11, 0x0001
    rldicr  r9, r9, 3,60
    cmpwi   cr6, r11, 0x000c
9:

#============================================================================
#   Send Dot Character over Serial as Progress Indicator (ikari)
#============================================================================
	MAKEPATCH 0x000018C0
	.set PrintDotDest, 0x000002D8
0:
	bla      PrintDot  # patches
9:

#============================================================================
#   Utility Functions (c0z and ikari)
#============================================================================
	MAKEPATCH  0x0000B188
	.set nand_patch_offset, 0x00100000
	.set HvpGetFlashBaseAddress, 0x0000068C
	.set HvpFlashCopy, 0x00000484 # XeCryptCopyQwVec(void* dest, void* src, int iter)
	.set HvpMemCpy, 0x0000A4E0 #  memcpy(void *destination, const void *source, int len)
	.set PrintDot, PatchAddr
	.set FixFusesAddr, (PatchAddr + (1f - 0f))
	.set PrintChar, (PatchAddr + (2f - 0f))

#--------------------------------------------------
# PrintDot
#--------------------------------------------------
0:
	mflr	r8
	bla		HvpGetFlashBaseAddress
	oris	r4, r3, nand_patch_offset@h
	ori		r4, r4, nand_patch_offset@l # source
	
	lis		r3, 1
	subi	r3, r3, 0x60
	# 0x60 bytes, 0xC 64bit vals to copy
	li		r5, 0xC
	bla		HvpFlashCopy

	# remove KV signature check
	lhz     r3, BldrFlags(0)
	li		r4, 0x20
	andc	r3, r3, r4
	sth     r3, BldrFlags(0)

	li      r3, '!'
	bla     PrintChar
	li      r3, '\n'
	bla     PrintChar
	mtlr	r8
	ba      PrintDotDest
#--------------------------------------------------
# FixFusesAddr
#--------------------------------------------------
1:
	lis		r3, 1
	subi	r3, r3, 0x60
	blr
#--------------------------------------------------
# PrintChar
#--------------------------------------------------
2:
	lis     r4, 0x8000
	ori     r4, r4, 0x0200
	rldicr  r4, r4, 32, 31
	oris    r4, r4, 0xea00
	slwi    r3, r3, 24
	stw     r3, 0x1014(r4)
charwait:
	lwz     r3, 0x1018(r4)
	rlwinm. r3, r3, 0, 6, 6
	beq     charwait
	blr
9:

#============================================================================
		.long 0xFFFFFFFF
		.end
#============================================================================
