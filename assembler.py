#!/usr/bin/env python3

import re

from keystone import *

REG_EXP = re.compile(r"(r\d+)")

def main() -> None:
	ks = Ks(KS_ARCH_PPC, KS_MODE_PPC32 + KS_MODE_BIG_ENDIAN)
	while True:
		line = input("ASM> ").strip()
		# commands
		if line.lower() in ["exit", "quit", "stop", "close", "end"]:
			break
		# parse as assembly
		line = REG_EXP.sub(r"%\1", line)
		try:
			(code, line_num) = ks.asm(line)
			code = bytes(code)
			print(code.hex().upper())
			code = ", ".join([f"0x{x:02X}" for x in code])
			code = f"BYTE code = {{ {code} }};"
			print(code)
		except Exception as e:
			print(e.message)

if __name__ == "__main__":
	main()