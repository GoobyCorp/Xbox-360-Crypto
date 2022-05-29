# ============================================================================
#	UART POST
# ============================================================================
	KMAKEPATCH 0x80002068
0:
	li        %r7, 0x0200
	oris      %r7, %r7, 0x8000
	sldi      %r7, %r7, 32
	oris      %r7, %r7, 0xEA00
    mr %r8, %r3
	slwi %r8, %r8, 24
	stw %r8, 0x1014(%r7)        # send the character
	sync
	isync
loop:
	lwz %r8, 0x1018(%r7)        # wait until character is sent
	rlwinm. %r8, %r8, 0, 6, 6
	beq loop
	blr
9:

	KMAKEPATCH 0x801B8200
0:
	li %r3, 1
	blr
9: