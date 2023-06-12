.include "macros.S"

	.globl _start
_start:

# Print LR in MachineCheck
    MAKEPATCH 0x00000264
0:
    mflr    r3
    bl      PrintLR-PatchAddr
9:

    MAKEPATCH  0x00031FBC
    .set UartOut, PatchAddr
    .set PrintLR, (PatchAddr + (1f - 0f)-4)
#;##########################################################
0: #; UART out
;###########################################################
	lis     r4, 0x8000
	ori     r4, r4, 0x0200
	rldicr  r4, r4, 32, 31
	oris    r4, r4, 0xea00
	slwi    r3, r3, 24
	stw     r3, 0x1014(r4)
uartwaitloop:
	lwz     r3, 0x1018(r4)
	rlwinm. r3, r3, 0, 6, 6
	beq     uartwaitloop
	blr
#;##########################################################
1: #; Print LR
;###########################################################
    xor     r10, r10, r10
    li      r10, 4
    mtctr   r10
    mr      r11, r3
uartprintlrloop:
    mr      r3, r11
    bl      UartOut-((.-0b)+PatchAddr)
    slwi    r11, r11, 8
    bdnz    uartprintlrloop
    blr
9:

#============================================================================
		.long 0xFFFFFFFF
		.end
#============================================================================
