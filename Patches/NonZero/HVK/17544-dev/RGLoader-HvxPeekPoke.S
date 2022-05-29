# ============================================================================
#	Hypervisor Peek Poking on RGL  (freeboot type access using syscall 0)
#      
# ============================================================================

#;//Set these to the addresses of functions in the HV
.set oldHvxGetVer, 0x1B98
.set memcpy, 0xA4E0
.set sysCallTable, 0x15EC0
#;//Set this to empty space (usually zero space after jump codes (ex: B4F0 XeCryptUidEccEncode_0 from 16537))
.set newHvxGetVer, 0xBE00  


	MAKEPATCH sysCallTable  
0:
	.long   newHvxGetVer
9:


#;// HvxExecute  Params( 0x72627472, 4, (QWORD)srcAddr, (QWORD)destAddr, (QWORD) lenInBytes)  will jump to destAddr after memcpy
#;// MemCpy      Params( 0x72627472, 5, (QWORD)srcAddr, (QWORD)destAddr, (QWORD) lenInBytes)
	MAKEPATCH newHvxGetVer  
0:
 
	#;//check if secret key is right..
	lis       %r11, 0x7262 #;// 0x72627472
	ori       %r11, %r11, 0x7472 #;// 0x72627472 
	cmplw     cr6, %r3, %r11
	beq       cr6, checkOpType 
	ba        oldHvxGetVer

checkOpType:                             
	cmplwi    cr6, %r4, 4    
	bgt       cr6, doMemCpy 
	beq       cr6, hvxExecuteCode 
	li        %r5, 0x154C
	lis       %r6, 0x3880 #;//0x38800007
	cmplwi    cr6, %r4, 2
	bne       cr6, loc_B5C0
	ori       %r6, %r6, 7 #;//0x38800007
	b         loc_B5C8

loc_B5C0:
	cmplwi    cr6, %r4, 3
	bne       cr6, loc_B5E0

loc_B5C8:
	li        %r0, 0
	stw       %r6, 0(%r5)
	dcbst     %r0, %r5
	icbi      %r0, %r5
	sync
	isync

loc_B5E0:
	li        %r3, 1
	blr

hvxExecuteCode:                              
	mfspr   %r12, lr
	std     %r12, -8(%r1) 
	stdu    %r1, -0x10(%r1)
	mtspr   lr, %r5          
	mtspr   ctr, %r7

cpyLoop:                              
	lwz       %r4, 0(%r6)     
	stw       %r4, 0(%r5)
	dcbst     %r0, %r5        
	icbi      %r0, %r5
	sync                    
	isync
	addi      %r5, %r5, 4     
	addi      %r6, %r6, 4
	bdnz      cpyLoop      
	blr
	addi      %r1, %r1, 0x10  
	ld        %r12, -8(%r1)
	mtspr   lr, %r12         
	blr

doMemCpy:                             
	cmplwi    cr6, %r4, 5    
	bne       cr6, loc_B610 
	mr        %r3, %r6        
	mr        %r4, %r5        
	mr        %r5, %r7    
	ba        memcpy

loc_B610:                             
	li        %r3, 2         
	blr
9:

#----------------------------------------------------------

