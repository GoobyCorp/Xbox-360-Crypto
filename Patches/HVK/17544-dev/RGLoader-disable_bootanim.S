
# ============================================================================
#	Disable stock bootanimation
#      (used for custom boot animations)
# ============================================================================

	KMAKEPATCH 0x80081858
0:
	nop  # nop out AniStartBootAnimation
9:




