#!/usr/bin/env python3

import re

from keystone import *

REG_EXP = re.compile(r"(r\d+)")

# 0x80066354 = li r4, 0
# 0x80066358 = addi r3, r11, 0xC00
# 0x80066360 = li r5, 0

def main() -> None:
	print("Xbox 360 Interactive Assembler")

	addr = 0
	line_split = None
	ks = Ks(KS_ARCH_PPC, KS_MODE_PPC32 + KS_MODE_BIG_ENDIAN)

	capturing = False
	code_lines = []
	while True:
		line_split = None
		line = input("ASM> ").strip()
		if ": " in line:
			line_split = line.split(": ")

		# commands
		if line.lower() in ["exit", "quit", "close"]:
			print("Done!")
			break
		elif line.lower() in ["start", "begin"]:
			code_lines = []
			capturing = True
			continue
		elif line.lower() in ["end", "stop"]:
			combined_code = b""
			for (asm, code_line) in code_lines:
				combined_code += code_line
				print(code_line.hex().upper())
				code = ", ".join([f"0x{x:02X}" for x in code_line])
				code = f"BYTE code[] = {{ {code} }}; // {asm}"
				print(code)
			print(combined_code.hex().upper())
			code = ", ".join([f"0x{x:02X}" for x in combined_code])
			code = f"BYTE code[] = {{ {code} }};"
			print(code)
			capturing = False
			continue
		elif line.lower() == "back":
			code_lines.pop(-1)
			continue

		# parse as assembly
		try:
			if len(line_split) == 2:
				line_split[1] = REG_EXP.sub(r"%\1", line_split[1])
				(code, line_num) = ks.asm(line_split[1], int(line_split[0], 16))
				code = bytes(code)
				if capturing:
					code_lines.append((line_split[1], code))
				else:
					print(code.hex().upper())
					code = ", ".join([f"0x{x:02X}" for x in code])
					code = f"BYTE code[] = {{ {code} }}; // {line_split[1]}"
					print(code)
			else:
				line = REG_EXP.sub(r"%\1", line)
				(code, line_num) = ks.asm(line)
				code = bytes(code)
				if capturing:
					code_lines.append((line, code))
				else:
					print(code.hex().upper())
					code = ", ".join([f"0x{x:02X}" for x in code])
					code = f"BYTE code[] = {{ {code} }}; // {line}"
					print(code)
		except Exception as e:
			print(e.message)

if __name__ == "__main__":
	main()