# A patch to remap the bootanim from flash to the HDD

.include "macros.S"

.set HvxPostOutput, 0x80061000
.set AniStartBootAnimation, 0x80061730
.set SataDiskInitialize, 0x8015DB18
.set SataCdRomInitialize, 0x8015D678

# set new bootanim path
    KMAKEPATCH 0x80166C00
0:
    .string "\\Device\\Harddisk0\\Partition1\\bootanim.xex\0"
    .align 2
9:

# initialize SATA driver before bootanim
    KMAKEPATCH 0x80061298
0:
	# output POST code 0x73
    li r3, 0x73
    KMAKEBRANCHL HvxPostOutput
    # init HDD before bootanim
    KMAKEBRANCHL SataDiskInitialize
    # init DVD after bootanim
    KMAKEBRANCHL SataCdRomInitialize
    # output POST code 0x72
    li r3, 0x72
    KMAKEBRANCHL HvxPostOutput
    # start the boot animation
    li r3, 0
    KMAKEBRANCHL AniStartBootAnimation
9:

# remove bound path limit, set new bootanim path, and remove the minimum bootanim version
    KMAKEPATCH 0x80061754
0:
    lis r11, -0x7FEA  # r11 = 0x80160000
    addi r3, r11, 0x6C00  # r3 = r11 + 0x6C00
    addi r6, r1, 0x50  # unmodified
    li r5, 0  # minimum version
    li r4, 9  # flags
9:

# ============================================================================
	.long 0xFFFFFFFF
# ============================================================================
