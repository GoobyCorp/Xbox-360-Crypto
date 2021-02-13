.set TLB_RPN,       0x3b5
.set SPR_HRMOR,     0x139
.set hrmor,         313
.set rmor,          312
.set ctr,           9
.set lr,            8
.set ppe_tlb_rpn, 	0x3B4
.set PIR,          1023

.set KBASE, 0x80000000

#;Arg0 is address, Arg1 is label used for handler
.macro MAKEPATCH PAddress 
.if(\PAddress)
	#;Patch structure
	.set 	PatchAddr, \PAddress
	.long	PatchAddr
	.long (9f - 0f) / 4  					#;Length of patch in dwords
.endif
.endm

#;Arg0 is address, Arg1 is label used for handler
.macro KMAKEPATCH PKAddress 
.if(\PKAddress)
	#;Patch structure
	.set 	PatchAddr, (\PKAddress-KBASE)
	.set 	RealAddr, (\PKAddress)
	.long	PatchAddr
	.long (9f - 0f) / 4  					#;Length of patch in dwords
.endif
.endm

#;Arg0 is hook address, Arg1 is destination
.macro MAKEHOOKL PKAddress PKDest
.if(\PKAddress)
	#;Patch structure
	.set 	PatchAddr, (\PKAddress)
	.set 	RealAddr, (\PKAddress)
	.long	PatchAddr
	.long (9f - 0f) / 4  					#;Length of patch in dwords
0:
	MAKEBRANCHL (\PKDest)
9:
.endif
.endm

#;Arg0 is hook address, Arg1 is destination
.macro KMAKEHOOKL PKAddress PKDest
.if(\PKAddress)
	#;Patch structure
	.set 	PatchAddr, (\PKAddress-KBASE)
	.set 	RealAddr, (\PKAddress)
	.long	PatchAddr
	.long (9f - 0f) / 4  					#;Length of patch in dwords
0:
	MAKEBRANCHL (\PKDest-KBASE)
9:
.endif
.endm

#;Arg0 is hook address, Arg1 is destination
.macro KMAKEHOOK PKAddress PKDest
.if(\PKAddress)
	#;Patch structure
	.set 	PatchAddr, (\PKAddress-KBASE)
	.set 	RealAddr, (\PKAddress)
	.long	PatchAddr
	.long (9f - 0f) / 4  					#;Length of patch in dwords
0:
	MAKEBRANCH (\PKDest-KBASE)
9:
.endif
.endm

#;Arg0 is destination address
.macro MAKEBRANCH DAddress
.if(\DAddress)
		#;Patch structure
 	b	\DAddress - ((.-0b)+PatchAddr)
.endif
.endm

#;Arg0 is destination address
.macro MAKEBRANCHL DAddress 
.if(\DAddress)
		#;Patch structure
 	bl	\DAddress - ((.-0b)+PatchAddr)
.endif
.endm

#;Arg0 is destination address
.macro KMAKEBRANCH DAddress
.if(\DAddress)
		#;Patch structure
 	b	(\DAddress-KBASE) - ((.-0b)+PatchAddr)
.endif
.endm

#;Arg0 is destination address
.macro KMAKEBRANCHL DAddress 
.if(\DAddress)
		#;Patch structure
 	bl	(\DAddress-KBASE) - ((.-0b)+PatchAddr)
.endif
.endm

#;Arg0 is destination address
.macro BLMAKEBRANCH DAddress
		#;Patch structure
 	b	\DAddress - ((.-0b)+PatchAddr)
.endm

#;Arg0 is destination address
.macro BLMAKEBRANCHL DAddress 
		#;Patch structure
 	bl	\DAddress - ((.-0b)+PatchAddr)
.endm
