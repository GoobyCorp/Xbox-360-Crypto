
# ============================================================================
#	Disable fcrt.bin
#      (fcrt.bin is neccesary for some slim drives though)
# ============================================================================

	MAKEPATCH 0x0002E020
0:
	li   %r11,  0
9:

	MAKEPATCH 0x0002DE28
0:
	li   %r10,  0
9:

	KMAKEPATCH 0x800816E0
0:
	nop
9:




