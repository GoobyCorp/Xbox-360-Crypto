#!/usr/bin/env python3

from struct import unpack

# py -m pip install capstone
# sudo pip3 install capstone
from capstone import *

def main() -> None:
	# md = Cs(CS_ARCH_PPC, CS_MODE_32 + CS_MODE_BIG_ENDIAN)

	with open("Output/decompiled_patches.asm", "w", newline="\n") as fw:
		with open(r"C:\Users\John\Desktop\xeBuild_1.21_zero\17559\bin\patches_g2mjasper.bin", "rb") as fr:
			fr.seek(0, 2)
			patch_size = fr.tell()
			fr.seek(0)
			print("# Fuck if I know if this is accurate :)\n", file=fw)
			print(".include \"macros.S\"\n", file=fw)
			while fr.tell() != patch_size:
				while True:
					(addr,) = unpack(">I", fr.read(4))
					if addr == 0xFFFFFFFF:
						print("# done with patch section\n", file=fw)
						break
					# print(f"0x{addr:08X}:")
					(size,) = unpack(">I", fr.read(4))
					print(f"MAKEPATCH 0x{addr:08X}", file=fw)
					print("0:", file=fw)
					for i in range(size):
						code = fr.read(4)
						disasm = [x for x in md.disasm(code, addr + (i * 4))]
						if len(disasm) > 0:
							# print(f"\t0x{addr + (i * 4):08X} -> {code.hex()}")
							for x in disasm:
								print(f"\t{x.mnemonic} {x.op_str}".strip(" "), file=fw)
						else:
							#print(f"\t#;// 0x{addr + (i * 4):08X} -> 0x{code.hex()}", file=fw)
							print(f"\t.long 0x{code.hex()}", file=fw)
					print("9:\n", file=fw)
	print("Done!")

if __name__ == "__main__":
	main()