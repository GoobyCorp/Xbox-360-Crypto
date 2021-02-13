#!/usr/bin/env python3

# https://www.ibm.com/support/knowledgecenter/en/ssw_aix_72/assembler/idalangref_inst_forms.html

from keystone import *

code = """
lwzu r4, 4(r3)
cmpwi r4, -1
addi r4, r4, -4
lwzu r6, 4(r3)
mtctr r6
lwzu r6, 4(r3)
stwu r6, 4(r4)
rfid
"""

def main() -> None:
	ks = Ks(KS_ARCH_PPC, KS_MODE_PPC32 + KS_MODE_BIG_ENDIAN)
	for single in code.splitlines():
		single = single.rstrip("\r\n")
		if single == "":
			continue

		print(single)
		(data, instructions) = ks.asm(single)
		data = bytes(data)
		print(data.hex())

if __name__ == "__main__":
	main()