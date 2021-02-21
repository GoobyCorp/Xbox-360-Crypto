#!/usr/bin/env python3

import re

from keystone import *

REG_EXP = re.compile(r"(r\d+)")

def main() -> None:
	print("Xbox 360 Interactive Assembler")

	ks = Ks(KS_ARCH_PPC, KS_MODE_PPC32 + KS_MODE_BIG_ENDIAN)

	capturing = False
	code_lines = []
	while True:
		line = input("ASM> ").strip()
		# commands
		if line.lower() in ["exit", "quit", "stop", "close"]:
			break
		elif line.lower() == "start":
			code_lines = []
			capturing = True
			continue
		elif line.lower() == "end":
			combined_code = b""
			for (asm, code_line) in code_lines:
				combined_code += code_line
				print(code_line.hex().upper())
				code = ", ".join([f"0x{x:02X}" for x in code_line])
				code = f"BYTE code = {{ {code} }}; // {asm}"
				print(code)
			print(combined_code.hex().upper())
			capturing = False
			continue
		elif line.lower() == "back":
			code_lines.pop(-1)
			continue

		# parse as assembly
		line = REG_EXP.sub(r"%\1", line)
		try:
			(code, line_num) = ks.asm(line)
			code = bytes(code)
			if capturing:
				code_lines.append((line, code))
			else:
				print(code.hex().upper())
				code = ", ".join([f"0x{x:02X}" for x in code])
				code = f"BYTE code = {{ {code} }}; // {line}"
				print(code)
		except Exception as e:
			print(e.message)

if __name__ == "__main__":
	main()