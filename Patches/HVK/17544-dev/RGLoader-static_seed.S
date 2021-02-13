
# ============================================================================
#	Set memory encryption seed to static
# ============================================================================
MAKEPATCH 0x00010100
0:
	.quad    0x5555555555555555
	.quad    0xAAAAAAAAAAAAAAAA
	.quad    0x0101010101010101
	.quad    0x0101010101010101
#	.quad    0xDEADBEEFFEEFDAED
#	.quad    0xDEADBEEFFDDFDAED
	.quad    0x0000000000000000
	.quad    0x0000000000000000
9:


MAKEPATCH 0x00001EB0
0:
	nop
9:


MAKEPATCH 0x00001EA4
0:
	nop
9:

MAKEPATCH 0x00001FF8
0:
	nop
9:
