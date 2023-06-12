#; u32 at header *0xC(-0x670) of CD must be < 0xF990
#; 9452 is 0x4F20 size, free space at end is 0xB0E0

#;============================================================================
#; CD patches for 9452 trinity BL
#;============================================================================
.include "macros.S"

	.globl _start
_start:

.set PWR_REAS_PWRBTN, 	0x11 		#;power button pushed
.set PWR_REAS_EJECT, 	0x12 		#;eject button pushed
.set PWR_REAS_ALARM, 	0x15 		#;guess ~ should be the wake alarm ~
.set PWR_REAS_REMOPWR, 	0x20 		#;power button on 3rd party remote/ xbox universal remote
.set PWR_REAS_REMOX, 	0x22 		#;xbox universal media remote X button
.set PWR_REAS_WINBTN, 	0x24 		#;windows button pushed IR remote
.set PWR_REAS_RESET, 	0x30 		#;HalReturnToFirmware(1 or 2 or 3) = hard reset by smc
.set PWR_REAS_KIOSK,	0x41		#;kiosk debug pin turned the console on
.set PWR_REAS_WIRELESS, 0x55 		#;wireless controller middle button/start button pushed to power on controller and console
.set PWR_REAS_WIRED, 	0x5A 		#;wired controller guide button pushed (attached to back usb port)
.set PWR_REAS_56, 0x56 		#;xss7
.set PWR_REAS_57, 0x57 		#;xss8
.set PWR_REAS_58, 0x58 		#;xss9
.set PWR_REAS_5A, 0x59 		#;xss10

.set SPR_HRMOR, 0x139
.set CD_ORIG_SIZE, 0x00004F20
.set FLASH_BASE, 0xC8000000
.set XELL_OFFSET, 0x00070000
.set PATCH_OFFSET, 0x000dc010		#; raw offset of patches in logical NAND
.set PATCHES, (FLASH_BASE+PATCH_OFFSET)
.set XELL, (FLASH_BASE+XELL_OFFSET)

#;============================================================================
#;	Zephyr patches
#;============================================================================
    MAKEPATCH 0x00000830
0:
    nop
9:

	MAKEPATCH 0x00000864
0:
	nop
9:

	MAKEPATCH 0x000006DC
0:
	nop
9:

	MAKEPATCH 0x000006EC
0:
	nop
9:

	MAKEPATCH 0x00000704
0:
	nop
9:

	MAKEPATCH 0x000007F0
0:
	nop
9:

	MAKEPATCH 0x000007F8
0:
	nop
9:

#;============================================================================
#;	check for poweron reason and start xell if needed - lis %r3, 0x300        
#;============================================================================
	MAKEPATCH 0x0000028C 
0:
	bl      CheckXell-PatchAddr
9:

#;============================================================================
#;  replace rfid with call to do kernel/hv patching                           
#;============================================================================
	MAKEPATCH 0x000005B4
0:
	b		CopyPatches-PatchAddr
9:

#;============================================================================
#;  remove pairing check         bne cr6, check_update_pairing                
#;============================================================================
	MAKEPATCH 0x00000830
0:
	nop
9:

#;============================================================================
#;  kernel/hv patch engine                                                    
#;============================================================================
	MAKEPATCH CD_ORIG_SIZE
	.set AddonSize, (9f-0f)
	.set CheckXell, PatchAddr
	.set PciTable, ((PatchAddr + (1f - 0f))-4)
	.set DotOut, (PatchAddr + (2f - 0f))
	.set CopyPatches, (PatchAddr + (3f - 0f))
	.set fixflagsA, (PatchAddr + (4f - 0f))
	.set fixflagsB, (PatchAddr + (5f - 0f))

#;##########################################################
0: #; CheckXell                                             
#;##########################################################
#; r1 r3 r4 r5 r6 r7 r11 r23 r22 r29
#; 		0x80000200EA00101C/0x7fea101c = 0xae010000; cygnos speed
#; 		0x80000200EA00101C/0x7fea101c = 0xe6010000; 115k
	li		%r5, 0x200
	oris	%r5, %r5, 0x8000
	sldi	%r5, %r5, 32
	oris	%r5, %r5, FLASH_BASE@h			
	# ori		%r5, %r5, FLASH_BASE@l		#; %r12 = 80000200_c8000000 flash address
	lbz		%r4, 0x4d(%r5)			#; header opts
	isync
	cmplwi	%r4, 0
	beq		nocygnos
	lis		%r3, 0xae01 #; 0xae01 0xE601
	lis     %r4, 0x8000
	ori     %r4, %r4, 0x0200
	rldicr  %r4, %r4, 32, 31
	oris    %r4, %r4, 0xEA00
	stw     %r3, 0x101c(%r4)
nocygnos:
	mflr	%r12
 	bl		DotOut - ((.-0b)+PatchAddr)
	mtlr	%r12
	li		%r8, 0x200
	oris	%r8, %r8, 0x8000
	sldi	%r8, %r8, 32
	oris	%r8, %r8, 0xEA00		#;  %r8 = 80000000_EA000000
	lis		%r9, 0x400
	lis		%r10, 0x100
	li		%r11, 0
	#; send SMC query for powerup reason, originally found in kkhack payload
	stw		%r9, 0x1084(%r8)		#; 00000004 (byteswapped)
	stw		%r10, 0x1080(%r8)		#; 01000000
	stw		%r11, 0x1080(%r8)		#; 00000000
	stw		%r11, 0x1080(%r8)		#; 00000000
	stw		%r11, 0x1080(%r8)		#; 00000000
	stw		%r11, 0x1084(%r8)		#; 00000000

	#; wait for SMC answer
queryloop:	
	lwz		%r12, 0x1094(%r8)
	and.	%r12, %r12, %r9			#; check for 04 (swapped)
	beq		queryloop
	stw		%r9, 0x1094(%r8)		#; 00000004 (byteswapped)
	lwz		%r12, 0x1090(%r8)
	lwz		%r3, 0x1090(%r8)
	lwz		%r3, 0x1090(%r8)
	lwz		%r3, 0x1090(%r8)
	stw		%r11, 0x1094(%r8)		#; 00000000
	rlwinm	%r3, %r12, 8, 24, 31
	cmpwi	%r3, 0x1
	bne		queryloop

	rlwinm	%r3, %r12, 16, 24, 31
	cmpwi	%r3, 0
	beq		noxell
	lbz		%r4, 0x4f(%r5)			#; header opts
	# isync
	cmplw 	%r3, %r4
#	cmpwi	%r3, PWR_REAS_EJECT		#; poweron cause as listed above
	beq		flash_loader
	lbz		%r4, 0x4e(%r5)			#; header opts
	# isync
	cmplw 	%r3, %r4
#	cmpwi	%r3, PWR_REAS_KIOSK		#; poweron cause as listed above
	beq		flash_loader
noxell:
	lis 	%r3, 0x300				#; original instruction
	blr

flash_loader:
	li		%r7, 0x200
	oris	%r7, %r7, 0x8000
	sldi	%r7, %r7, 32
	oris	%r7, %r7, 6
	ori		%r7, %r7, 0x1010		#; r7= 80000200_00061010 POST

	li		%r3, 0x10				#; POST out 0x10
	sldi	%r3, %r3, 56
	std		%r3, 0(%r7)
	bl		pci_init

	li		%r5, 0x200
	oris	%r5, %r5, 0x8000
	sldi	%r5, %r5, 32
	oris	%r5, %r5, XELL@h			
	ori		%r5, %r5, XELL@l		#; %r5 = 80000200_c8****** source address
	lis		%r6, 0x8000
	sldi	%r6, %r6, 32
	oris	%r6, %r6, 0x1C00		#; %r6 = 80000000_1c000000 dest address
	mr		%r9, %r6				#; %r9 = rfid address

	mtspr	SPR_HRMOR, %r11			#; zero hrmor
	
	li		%r3, 0x11				#; POST out 0x11
	sldi	%r3, %r3, 56
	std		%r3, 0(%r7)

	lis		%r4, 1					#; copy 0x10000*32bit = 256k
	mtctr	%r4

xellcopy:
	lwz		%r8, 0(%r5)
	stw		%r8, 0(%r6)
	dcbst	%r0, %r6
	icbi	%r0, %r6
	sync
	isync
	addi	%r6, %r6, 4
	addi	%r5, %r5, 4
	bdnz	xellcopy
	li		%r3, 0x12				#; POST out 0x12
	sldi	%r3, %r3, 56
	std		%r3, 0(%r7)
	li		%r4, 0x30				#; Clear IR/DR and jump to Xell
	mfmsr	%r3
	andc	%r3, %r3, %r4
	mtsrr1	%r3
	mtsrr0	%r9
	rfid

pci_init:
	lis		%r3, 0x8000
	ori		%r3, %r3, 0x17C 
	sldi	%r3, %r3, 32
	oris	%r3, %r3, 0x400			#; 0x8000017C_04000000 CD base address
#;	oris	%r3, %r3, PciTable@h	#; only needed if offset > 0xFFFF which is too big anyway
	ori		%r3, %r3, PciTable@l	#; table offset -4
	li		%r30, 0x200
	oris	%r30, %r30, 0x8000
	sldi	%r30, %r30, 32
pciloop:
	lwzu	%r4, 4(%r3)		#; load first val
	cmplwi	%r4, 0
	beqlr
	lwzu	%r31, 4(%r3)	#; load second val
	stwbrx	%r31, %r30, %r4 #; 0x80000200_00000000+first value = byte reversed second value
	li		%r31, 0xFF
	andc	%r4, %r4, %r31	#; first value = first value &~0xFF
	ori		%r4, %r4, 4		#; first value = (first value &~0xFF)|0x4
	lwbrx	%r31, %r30, %r4
	lwzu	%r29, 4(%r3)	#; load third val
	or		%r31, %r31, %r29#;
	stwbrx	%r31, %r30, %r4	#; 0x80000200_00000000+new first value = byte reversed load and or of third value
	b		pciloop
#;##########################################################
1: #; PciTable - gligli's PCI init table                    
#;##########################################################

#;	pci-pci bridge
	.long 0xD0000010, 0xEA000000, 0x00000156	#; *0x80000200_D0000010 = 0xEA000000; *0x80000200_D0000004 |= 0x00000156;
#;	host bridge
	.long 0xD0008010, 0xE0000000, 0x00000002
#;	GPU
	.long 0xD0010010, 0xEC800000, 0x00000002
#;	1414:5801
	.long 0xD0100010, 0xEA001800, 0x00000002
#;	SATA
	.long 0xD0108010, 0xEA001200, 0x00000006
	.long 0xD0108014, 0xEA001220, 0x00000006
	.long 0xD0110010, 0xEA001300, 0x00000006
	.long 0xD0110014, 0xEA001320, 0x00000006
#;	USB
	.long 0xD0120010, 0xEA002000, 0x00000156
	.long 0xD0121010, 0xEA003000, 0x00000106
	.long 0xD0128010, 0xEA004000, 0x00000156
	.long 0xD0129010, 0xEA005000, 0x00000106
#;	Ethernet
	.long 0xD0138010, 0xEA001400, 0x00000006
#;	System flash controller
	.long 0xD0140010, 0xEA00C000, 0x00000006	#; *0x80000200_D0140010 = 0xEA00C000; *0x80000200_D0140004 |= 0x00000006;
	.long 0xD0140014, 0xC8000000, 0x00000006	#; *0x80000200_D0140014 = 0xC8000000; *0x80000200_D0140004 |= 0x00000006;
#;	Audio
	.long 0xD0148010, 0xEA001600, 0x00000006
#;	SMC
	.long 0xD0150010, 0xEA001000, 0x00000002
	.long 0x00000000				#; -1 to tell the pci init engine to stop

#;##########################################################
2: #; DotOut                                                
#;##########################################################
	li      %r3, '.'
	lis     %r4, 0x8000
	ori     %r4, %r4, 0x0200
	rldicr  %r4, %r4, 32, 31
	oris    %r4, %r4, 0xea00
	slwi    %r3, %r3, 24
	stw     %r3, 0x1014(%r4)
uartwaitloop:
	lwz     %r3, 0x1018(%r4)
	rlwinm. %r3, %r3, 0, 6, 6
	beq     uartwaitloop
	blr
#;##########################################################
3: #; CopyPatches                                           
#;##########################################################
	mfmsr	%r7
	li		%r8, 0x10
	andc	%r8, %r7, %r8
	mtmsrd	%r8, 0
	#; flash address
	# mflr	%r5
 	bl		DotOut-((.-0b)+PatchAddr)
	# mtlr	%r5

	li		%r5, 0x200
	oris	%r5, %r5, 0x8000
	sldi	%r5, %r5, 32
	oris	%r5, %r5, FLASH_BASE@h			
	ori		%r5, %r5, FLASH_BASE@l		#; %r12 = 80000200_c8000000 flash address
	lwz		%r6, 0x70(%r5)			#; patch slot size
	lwz		%r4, 0x64(%r5)			#; patch slot offset
	cmplwi	%r6, 0
	bne		sz_nonzero
	lis		%r6, 0x1				#; default size of 0x10000
sz_nonzero:
	add		%r4, %r4, %r6
	addi	%r4, %r4, 0x5C			#; to the start of patches -4
	or		%r3, %r5, %r4			#; or into the flash base
	isync							#; make sure this all executed before carrying on
	# oris	%r3, %r3, PATCHES@h		#; %r3 = 80000200_PATCHES (0xc8xxxxxx)
	# ori		%r3, %r3, PATCHES@l
	# addi	%r3, %r3, -4
iterLoop:
	mtmsrd	%r8, 0
	isync
	lwzu	%r4, 4(%r3)				#; load patch offset
	cmpwi	%r4, -1					#; check for end of patches
	beq		exit					#; exit if done
	addi	%r4, %r4, -4
	lwzu	%r6, 4(%r3)				#; load patch size
	mtctr	%r6						#; set size to counter
patchLoop:
	mtmsrd	%r8, 0
	isync
	lwzu	%r6, 4(%r3)				#; load patch data
	mtmsrd	%r7, 0
	isync
	stwu	%r6, 4(%r4)				#; store patch data
	dcbst	%r0, %r4
	icbi	%r0, %r4
	bdnz	patchLoop				#; loop until counter is done
	b		iterLoop				#; proceed to next patch

exit:
	sync
	isync
	mtmsrd	%r7, 0
	rfid
#;##########################################################
4: #; fixflagsA    or        r11, r11, r10
#;##########################################################
	ori		r10, r10, 0x1E
	or		r11, r11, r10
	blr
#;##########################################################
5: #; fixflagsB    or        r11, r11, r28
#;##########################################################
	ori		r28, r28, 0x1E
	or		r11, r11, r28
	blr
9:

.set XeCryptCopyQwVec,		0xE90	# XeCryptCopyQwVec(VOID *dest, VOID *src, DWORD len) ; len is in number of 64bit reads
.set SbFlashAddrOff,		0x18000000
.set SbFlashAddrOff,		0x18000000
.set qwSbFlashAddrOff,		0x258
.set dwSysUpdateAddr,		0x64
.set dwSysUpdateSlotSize,	0x70
.set fusesSize,				0xC

#;============================================================================
#;  patch fuse load
#;  patch1 920	fuses to r10, 10 instructions, r3, r4, r5 ok
#;============================================================================
	MAKEPATCH 0x920
0:
	lis		%r3, SbFlashAddrOff@h
	ori		%r3, %r3, SbFlashAddrOff@l
	lwz		%r4, dwSysUpdateAddr(%r3)
	lwz		%r5, dwSysUpdateSlotSize(%r3)
	add		%r3, %r3, %r4
	add		%r4, %r3, %r5
	mr		%r3, %r10
#;	addi	%r4, 0x10
	li		%r5, fusesSize
	MAKEBRANCHL	XeCryptCopyQwVec
	nop
9:

# skip a check on a bit set in SB
	MAKEPATCH 0x990
0:
	nop
9:

# E54         or        r11, r11, r10
	MAKEPATCH 0xE54
0:
	bl		fixflagsA-PatchAddr
9:
         
# 8C4         or        r11, r11, r28
	MAKEPATCH 0x8C4
0:
	bl		fixflagsB-PatchAddr
9:

#;============================================================================
	.long 0xFFFFFFFF
	.end
#;============================================================================
