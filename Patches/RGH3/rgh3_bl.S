# Intermediary bootloader for RGH3

.include "macros.S"

#============================================================================
#   Intermediary bootloader for RGH3
#============================================================================

# variables
.set MAGIC,   0x4342  # CB
.set BUILD,   17559
.set QFE,     0x8000
.set FLAGS,   0x0
.set PADDING, 0x0

# make the bootloader header
# MAKEBLHDR Magic Build QFE Flags Padding
MAKEBLHDR MAGIC BUILD QFE FLAGS PADDING

# FUSE TESTER (OPTIONAL)
	.globl _start
_start:
0:
	li        r11, 0
	oris      r10, r3, 2

loc_358:
	li        r12, 0
	insrdi    r12, r11, 32, 29
	addi      r11, r11, 0x40
	cmplwi    r11, 0x300
	ldx       r12, r12, r10
	blt       loc_358
	# POST_OUT = 0x54
	oris      r10, r3, 6
	li        r2, 0x54
	sldi      r2, r2, 56
	std       r2, 0x1010(r10)
	# WAIT 100 ms
	lis       r2, 1
	mtctr     r2

loc_388:
	bdnz      loc_388
	nop
	# COPY & JUMP
	oris      r6, r3, 0xC800
	addi      r6, r6, -4
	clrldi    r2, r31, 32
	add       r6, r6, r2
	lwz       r7, 0x10(r6)
	lwz       r8, 0xC(r6)
	add       r31, r31, r7
	srdi      r7, r7, 2
	mtctr     r7

loc_3B4:
	lwzu      r2, 4(r6)
	stwu      r2, 4(r5)
	bdnz      loc_3B4
	clrlwi    r8, r8, 16
	addis     r8, r8, 0x200
	mtlr      r8
	blr

# ENTRY POINT - RELOCATE
sub_3D0:
	li        r3, 0x200
	oris      r3, r3, 0x8000
	sldi      r3, r3, 32
	oris      r4, r3, 1
	addi      r5, r4, -4
	ori       r6, r4, 0xC000
	li        r2, 0x7F
	mtctr     r2

loc_3F0:
	ldu       r2, 8(r4)
	stdu      r2, 8(r6)
	bdnz      loc_3F0
	b         0xC350
9:

#============================================================================
	.end
#============================================================================
