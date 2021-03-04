#!/usr/bin/env python3

from XeCrypt import XeCryptCpuKeyGen

def main() -> None:
	key = XeCryptCpuKeyGen()
	key_bits = "".join([f"{x:0>8b}" for x in key])

	print("ECC Bits: " + key_bits[-26:])
	print("UID Bits: " + key_bits[:-26])

	print(key.hex().upper())

if __name__ == "__main__":
	main()