
# ============================================================================
#	Disable panic on failed to resolve import
# ============================================================================
	MAKEPATCH 0x0002ACE8
0:
	nop
	nop
	nop
	nop
9:

	MAKEPATCH 0x00000002
0:
	.short KRNL_VER
	.short 0
9:

	MAKEPATCH 0x00001B98
0:
	lis     %r11, 0x0760
	lis     %r10, KRNL_VER
9:

	MAKEPATCH 0x00000010
0:
	.short 0x0760
	.short 0
9:

	KMAKEPATCH 0x80040460
0:
	.short KRNL_VER
	.short 0
9:

	KMAKEPATCH 0x80040468
0:                                      
	.short 0x0760
	.short 0
9:

	MAKEPATCH 0x0002ADB0
0:
	nop
9:

	MAKEPATCH 0x0002ADC0
0:
	nop
9:

	MAKEPATCH 0x0002AE18
0:
	nop
9:

# ============================================================================
#	Fill unresolved ordinals with li r3, 0 ; blr
# ============================================================================
	MAKEPATCH 0x0002AE7C
0:
	bla       0xB208
9:

	MAKEPATCH 0x0000B208
0:
	lwz       %r9, 0x20C(%r1)
	lwz       %r10, 0x74(%r1)
	cmplw     cr6, %r10, %r9
	blt       cr6, 0x18
	lwz       %r10, 0x78(%r1)
	lwz       %r9, 0x208(%r1)
	cmplw     cr6, %r9, %r10
	bge       cr6, 0x8
	lis       %r11, 0x3860
	stw       %r11, 0(%r30)   #;//do what we patched..
	blr
9:

	MAKEPATCH 0x0002AEEC
0:
	bla       0xB2F8
9:

	MAKEPATCH 0x0000B2F8
0:
	clrlwi    %r10, %r29, 16
	cmplwi    cr6, %r10, 0
	bne       cr6, 0xC
	lis       %r29, 0x4E80
	ori       %r29, %r29, 0x20
	stw       %r29, 0(%r11)   #;//do what we patched..
	blr
9:










