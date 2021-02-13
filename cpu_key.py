#!/usr/bin/env python3

from XeCrypt import XeCryptCpuKeyGen  # , XeCryptHammingWeight, XeCryptUidEccEncode, XeCryptCpuKeyValid

def main() -> None:
	key = XeCryptCpuKeyGen()
	print(key.hex().upper())
	#print("\\x" + "\\x".join([f"{x:02X}" for x in key]))

	"""
	test = bytes.fromhex("BADA5535BADA5535BADA550007000000")
	print(hex(XeCryptHammingWeight(test)))
	test = XeCryptUidEccEncode(test)
	print(test.hex().upper())
	print(XeCryptCpuKeyValid(test))
	"""

if __name__ == "__main__":
	main()