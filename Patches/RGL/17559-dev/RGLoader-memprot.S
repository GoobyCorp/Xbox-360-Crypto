
# ============================================================================
#	Disable memory protection on devkits
# ============================================================================
	MAKEPATCH 0x000011BC
0:
	ba  0x15F0
9:

	MAKEPATCH 0x000015F0
0:
	li  %r4, 7
	.long 0x7C212078
	.long 0x7C35EBA6
	ba 0x11C0
9:

	MAKEPATCH 0x00030090
0:
	ori       %r4, %r4, 0x1B0
9:




