#; u32 at header *0xC(-0x670) of CD must be < 0xF990
#; 17489 is 0x4F30 size

#;============================================================================
#; CD patches for 17489 Jasper SD
#;============================================================================
.include "macros.S"

	.globl _start
_start:

.set SPR_HRMOR, 0x139
.set CD_ORIG_SIZE, 0x4F30
.set FLASH_BASE, 0xC8000000
.set XELL_OFFSET, 0xB80000
.set XELL, (FLASH_BASE + XELL_OFFSET)

#;============================================================================
#;	check for poweron reason and start xell if needed - lis %r3, 0x300
#;============================================================================
#	MAKEPATCH 0x00000310
#0:
#	bl		CheckXell
#9:

#;============================================================================
#;  remove pairing check         bne cr6, check_update_pairing
#;============================================================================
	MAKEPATCH 0x000009EC
0:
	nop
9:

#;============================================================================
#;  fix boot flags         or r11, r11, r10
#;============================================================================
	MAKEPATCH 0x00000AB4
0:
	li		%r11, -0x27E2  		# remove mfg mode 0xd81e C01E|1000 or C01E|2000 0xD01E(slot1) 0xE01E(slot2)
9:

#;============================================================================
#;  XeLL
#;============================================================================
	MAKEPATCH CD_ORIG_SIZE
        .set AddonSize, (9f-0f)
        .set CheckXell, PatchAddr
        .set PciTable, ((PatchAddr + (1f - 0f))-4)

#;============================================================================
0: #; CheckXell
#;============================================================================
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
 	# bl		DotOut - ((.-0b)+PatchAddr)
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
	lwzu	%r4, 4(%r3)
	cmplwi	%r4, 0
	beqlr
	lwzu	%r31, 4(%r3)
	stwbrx	%r31, %r30, %r4
	li		%r31, 0xFF
	andc	%r4, %r4, %r31
	ori		%r4, %r4, 4
	lwbrx	%r31, %r30, %r4
	lwzu	%r29, 4(%r3)
	or		%r31, %r31, %r29
	stwbrx	%r31, %r30, %r4
	b		pciloop
#;============================================================================
1: #; PciTable - gligli's PCI init table                    
#;============================================================================

#;	pci-pci bridge
	.long 0xD0000010, 0xEA000000, 0x00000156
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
	.long 0xD0140010, 0xEA00C000, 0x00000006
	.long 0xD0140014, 0xC8000000, 0x00000006
#;	Audio
	.long 0xD0148010, 0xEA001600, 0x00000006
#;	SMC
	.long 0xD0150010, 0xEA001000, 0x00000002
	.long 0x00000000				#; -1 to tell the pci init engine to stop
9:

#;============================================================================
	.long 0xFFFFFFFF
	.end
#;============================================================================
