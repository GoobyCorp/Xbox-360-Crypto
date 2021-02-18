#!/usr/bin/env python3

import patch_compile
import se_patcher
import patch_checker

def main() -> None:
	"""
	print("Setting KDNET settings in flash header...")
	nand_path = r"Z:\Xbox 360\xeBuild_1.21_zero\zero_rgl.bin"
	with open(nand_path, "r+b") as f:
		f.seek(0x80)
		# magic
		f.write(pack(">H", 0xCA4A))
		f.seek(0x88)
		# data offset
		f.write(pack(">I", 16))
		# data size
		f.write(pack(">I", 72))
		# enabled
		f.write(pack(">I", 1))
		# target MAC
		f.seek(0x98)
		f.write(pack("6s", bytes.fromhex("0022485B4E17")))
		# host port
		f.write(pack(">H", 50010))
		# host address
		f.write(pack("4B", 192, 168, 1, 35))
		f.flush()

		f.seek(0x200)
		spare = f.read(0x10)
		f.seek(0)
		data = f.read(0x200)

		print("Correcting ECC bits...")
		(data, spare) = fix_page_ecc(data, spare)

		f.seek(0x200)
		f.write(spare)
	"""

	print("Compiling...")
	patch_compile.main()
	print("Patching...")
	se_patcher.main()
	print("Checking...")
	patch_checker.main()
	print("Done!")

if __name__ == "__main__":
	main()