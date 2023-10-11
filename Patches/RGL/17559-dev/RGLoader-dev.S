# RGLoader patches file
# Patches follow same format as XeBuild, but with RGLP at start
# When used with RGLoader patch engine, refer to the ini for patches offset in NAND
# [4byte offset] [4byte patch count] [4byte patch]...

# Devkit 17489 patches

.include "macros.S"
.include "settings.S"

	.globl _start
_start:

# ============================================================================
#       Optional patches
# ============================================================================

.if VFUSES == 1
.print "  --- Adding vfuses ---"
.include "RGLoader-vfuses.S"
.endif

.if SYSROOT == 1
.print "  --- SYSTEM ROOT MAPPED TO HDD ---"
.include "RGLoader-sysroot.S"
.endif

.print "  --- KD retries patched to 1 ---"
.include "RGLoader-kd_1retry.S"

.print "  --- Removing FCRT restriction ---"
.include "RGLoader-nofcrt.S"

.print "  --- Disabling Mem Protection ---"
.include "RGLoader-memprot.S"

.print "  --- Using spoofed dash ---"
.include "RGLoader-spoof.S"

.print "  --- Ignoring heap errors ---"
.include "RGLoader-ignoreHeapErr.S"

# ============================================================================
#       Retail XEX2 AES key
# note: should be static
# ============================================================================
	MAKEPATCH 0x000000F0
0:
	.long 0x20B185A5
	.long 0x9D28FDC3
	.long 0x40583FBB
	.long 0x0896BF91
9:

# ============================================================================
# 	Enable retail xex decryption
# ============================================================================
	MAKEPATCH 0x00029C4C
0:
	b       0x10   #;//skip signature check for retail consoles. (allow patched xex)
9:
	MAKEPATCH 0x00029C70
0:
	li      %r4,  0xF0   #;//patch XexAes key to retail one at 0xF0
9:

# ============================================================================
#	HV jump to flag fixer
# ============================================================================
	MAKEPATCH 0x000018B8
0:
	ba  0xB2B8      #(CHANGE THE ADDR TO FLAG FIXING FUNCTIONS ADDR) ^
9:

# ============================================================================
#	HV Flag fixing function
# note: store at empty space
# ============================================================================
	MAKEPATCH 0x0000B2B8
0:
	lhz     %r3, 0x6(%r0)  # load flag byte into r3
	li      %r4, 0x21
	andc    %r3, %r3, %r4 # clear bit
	sth     %r3, 0x6(%r0)      # store new flag
	cmpldi   %r21,  0    # do what we patched
	ba      0x18BC  #CHANGE THIS ADDR TO JUMP BACK
9:

# ============================================================================
#       HvxSecuity Functions  (sets machine acct flags)
# ============================================================================
	MAKEPATCH 0x00006C58  #;// HvxSecurityGetActivated
0:
	li     %r3, 0
	blr
9:
	MAKEPATCH 0x00006B98  #;// HvxSecurityGetDetected
0:
	li     %r3, 0
	blr
9:
	MAKEPATCH 0x00006BE8  #;// HvxSecuritySetActivated
0:
	li     %r3, 0
	blr
9:
	MAKEPATCH 0x00006B00  #;// HvxSecuritySetDetected
0:
	li     %r3, 0
	blr
9:
	MAKEPATCH 0x00006CA8  #;// HvxSecuritySetStat
0:
	li     %r3, 0
	blr
9:
	MAKEPATCH 0x00006D08
0:
	li  %r3, 0
	blr
9:
	MAKEPATCH 0x00006C48  #;// HvxSecuritySetActivated
0:
	li  %r3, 0
	blr
9:

# ============================================================================
#	HV Patch Console Seq check
# ============================================================================
	MAKEPATCH 0x00007214
0:
	nop  
9:

#============================================================================
#	HV patch jump
# ============================================================================
	MAKEPATCH 0x000071B8
0:
	li %r3, 0 
9:

	MAKEPATCH 0x0000723C
0:
	nop
9:

# ============================================================================
#   Patch XEX flag
# ============================================================================
	MAKEPATCH 0x000072F0
0:
	li %r3, 0
9:
	MAKEPATCH 0x000076A0
0:
	li %r4, 0x8
	li %r3, 0
9:

# ============================================================================
#	HV Patch blow fuses              
# ============================================================================
	MAKEPATCH 0x0000A1C8
0:
	li %r3, 1 
	blr
9:

# ============================================================================
#	Remove fcrt.bin hash check
# ============================================================================
	MAKEPATCH 0x000264F0
0:
	li    %r3, 1
9:

# ============================================================================
#   DVDAuth2 retail key
#     note: should stay constant
# ============================================================================
	MAKEPATCH 0x00010D08
0:
	.long 0xD1E3B33A
	.long 0x6C1EF770
	.long 0x5F6DE93B
	.long 0xB6C0DC71
9:

# ============================================================================
#	HvxDvdAuthRecordXControl  Remove signature check
# ============================================================================
	MAKEPATCH 0x00026C04
0:
	li  %r3, 1
9:

# ============================================================================
#   HV DAE
# ============================================================================
	MAKEPATCH 0x00029018
0:
	li    %r3, 0
9:

# ============================================================================
#	HvxSetImagePageTableEntry memory addr check
# ============================================================================
	MAKEPATCH 0x00029E28
0:
	nop
9:

# ============================================================================
#	HvxCreateImageMapping hash check
# ============================================================================
	MAKEPATCH 0x0002C82C
0:
	b  0x10
9:

# ============================================================================
#	HvxCreateImageMapping HV XEX region check 
# ============================================================================
	MAKEPATCH 0x0002C924
0:
	nop
9:

# ============================================================================
#	HvxExpansionInstall sig check
# ============================================================================
    MAKEPATCH 0x00030BAC
0:
    nop
9:

#------------
#=============================================================================
# Kernel patches
#=============================================================================
#------------

# ============================================================================
#       Fix controller desync bug that still exists..  
# ============================================================================
	KMAKEPATCH 0x801287F4
0:
	ori		%r9, %r9, 8
	stb		%r9, 0x6F(%r31)
9:

# ============================================================================
#	Patch XEX Restrictions check
# ============================================================================
	KMAKEPATCH 0x800A2F48
0:
	li     %r3,  1
9:
	KMAKEPATCH 0x800A0FAC
0:
	b   0x18
9:

# ============================================================================
#	XexpVerifyXexHeaders
# ============================================================================
	KMAKEPATCH 0x800A0994
0:
	li   %r3,  1 
9:
	KMAKEPATCH 0x800A09F0
0:
	nop
9:

# ============================================================================
#	XexpVerifyMinimumVersion
# ============================================================================
	KMAKEPATCH 0x800A17B0
0:
	li   %r3,  0
9:

# ============================================================================
#	XexpLoadFile
# ============================================================================
	KMAKEPATCH 0x8009EE78
0:
	li   %r3,  1
9:

# ============================================================================
#	SataCdRomActivateHCDFRuntimePatch  
#       patch out blacklisted drives for XGD3 discs (zero ExpUpdateModule)
# ============================================================================
	KMAKEPATCH 0x800C51E8
0:
	li   %r11, 0
9:
	KMAKEPATCH 0x800C5210
0:
	li   %r11, 0
9:

# ============================================================================
#   SataCdRomAuthenticationExSequence
# ============================================================================
	KMAKEPATCH 0x800C57D8
0:
	b   0x38
9:

# ============================================================================
#	SataCdRomVerifyDVDX2AuthoringSignature
# ============================================================================
	KMAKEPATCH 0x800C3788
0:
	li   %r3, 1
9:

# ============================================================================
#	SataDiskAuthenticateDevice
# ============================================================================
	KMAKEPATCH 0x801B0C98 
0:
	li   %r3, 1
9:

# ============================================================================
#	XeKeysVerifyRSASignature
# ============================================================================
	KMAKEPATCH 0x8014A128
0:
	nop
9:
	KMAKEPATCH 0x8014A028
0:
	li    %r3, 1
	blr
9:
	KMAKEPATCH 0x8014A15C
0:
	li   %r3, 1
9:

# ============================================================================
#	XeKeysVerifyPIRSSignature
# ============================================================================
	KMAKEPATCH 0x8014A1FC
0:
	li    %r3, 1
9:

# ============================================================================
#	XeKeysConsoleSignatureVerification
#       patch flag check  & always return 1
# ============================================================================
	KMAKEPATCH 0x8014C35C
0:
	li   %r3, 1
9:
	KMAKEPATCH 0x8014C344
0:
	li   %r3, 1
9:
	KMAKEPATCH 0x8014C364
0:
	li   %r3, 1
9:

# ============================================================================
#	XexDeltaDecompressHeaders
#       remove hash check
# ============================================================================
	KMAKEPATCH 0x800A6494
0:
	li   %r3, 0x14
9:

# ============================================================================
#	XexpLoadCompressedImage
#       remove hash check
# ============================================================================
	KMAKEPATCH 0x800A5BDC
0:
	li   %r3, 0x14
9:

# ============================================================================
#	XexpLoadDeltaCompressedImage
#       remove hash check
# ============================================================================
	KMAKEPATCH 0x800A628C
0:
	li   %r3, 0x14
9:

# ============================================================================
#	XexpVerifyMediaType
# ============================================================================
	KMAKEPATCH 0x8009EEDC
0:
	li   %r3,  1
9:

# ============================================================================
#	VdpDelayExecution
# ============================================================================
	KMAKEPATCH 0x800F4B2C
0:
	nop
9:
	KMAKEPATCH 0x800F4B38
0:
	nop
9:

# ============================================================================
#	XexpVerifyDeviceId 
#       always return 0
# ============================================================================
	KMAKEPATCH 0x800A0DB8
0:
	li   %r3, 0
9:
	KMAKEPATCH 0x800A0FC4
0:
	li   %r3, 0
9:

# ============================================================================
#	StfsMapNewBlock hash mismatch
# ============================================================================
	KMAKEPATCH 0x800E22CC
0:
	b    0x34  #patch to unconditional branch
9:

# ============================================================================
#	StfsNonCachedRead
#       remove hash check (nop out bne)
# ============================================================================
	KMAKEPATCH 0x800E45E0
0:
	nop
9:

# ============================================================================
#	SvodMapNewBlock hash mismatch 
# ============================================================================
	KMAKEPATCH 0x80193BE8
0:
	b 0x30  #patch to unconditional branch
9:

# ============================================================================
#	SvodPartiallyCachedRead hash mismatch
# ============================================================================
	KMAKEPATCH 0x80193FFC
0:
	nop
9:

# ============================================================================
#	XeKeysSecurityLoadSettings - ignore
# ============================================================================
	KMAKEPATCH 0x800816C0
0:
	nop
9:

# ============================================================================
#	XexpScanImageCodeSection - ignore
# ============================================================================
	KMAKEPATCH 0x8009FD90
0:
	b 0x5C
9:

# ============================================================================
#	Load RGLoader.xex after XAM
# ============================================================================

.set ldBranchAddr, 0x80081AC8
.set loaderFuncAddr, 0x801C1774 #;//empty space
.set XexLoadImage, 0x800A3F08

	KMAKEPATCH loaderFuncAddr
0:
	.set strPath, (loaderFuncAddr + 0x20)
	
	lis   %r11, strPath@h
	ori  %r3, %r11, strPath@l
	li %r4, 8
	li %r5, 0
	li %r6, 0
	KMAKEBRANCHL XexLoadImage

	li  %r3, 0
	KMAKEBRANCH (ldBranchAddr+4)
1:
.if HDD == 1
    .string "\\Device\\Harddisk0\\Partition1\\RGLoader.xex\0"
.elseif FLASH == 1
    .string "\\Device\\Flash\\RGLoader.xex\0"
.endif
2:
	.align 2
9:

	KMAKEPATCH ldBranchAddr
0:
	KMAKEBRANCHL loaderFuncAddr
9:


# ============================================================================
	.long 0xFFFFFFFF
	.end
# ============================================================================
