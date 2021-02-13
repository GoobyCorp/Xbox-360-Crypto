#!/usr/bin/env python3

from XeCrypt import XeCryptCpuKeyGen

def main() -> None:
	key = XeCryptCpuKeyGen()
	print(key.hex().upper())

if __name__ == "__main__":
	main()