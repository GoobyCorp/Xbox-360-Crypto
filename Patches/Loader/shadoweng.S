	.set PatchOff, ((9f - 1f) - 4)
0:
	bl		1f
1:
	mflr	%r3
	addi	%r3, %r3, PatchOff		#; patch address minus 4
iterLoop:
	lwzu	%r4, 4(%r3)				#; load patch offset
	cmpwi	%r4, -1					#; check for end of patches
	beq		exit					#; exit if done
	addi	%r4, %r4, -4
	lwzu	%r6, 4(%r3)				#; load patch size
	mtctr	%r6						#; set size to counter
patchLoop:
	lwzu	%r6, 4(%r3)				#; load patch data
	stwu	%r6, 4(%r4)				#; store patch data
	bdnz	patchLoop				#; loop until counter is done
	b		iterLoop				#; proceed to next patch

exit:
	rfid
9:

#;============================================================================
	.end
#;============================================================================
