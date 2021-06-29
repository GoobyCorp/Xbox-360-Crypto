#!/usr/bin/env python3

from keystone import *

import re
from io import BytesIO
from pathlib import Path
from collections import OrderedDict

LABEL_EXP = re.compile(r"^([\w\d]+):")
PERCENT_EXP = re.compile(r"(r\d+)")
EOL_COMMENT_EXP = re.compile(r"#[\w\d\s]+$")

class CodeSection:
	addr: int = 0
	code: str = ""

	def __init__(self, addr: int, code: str):
		self.reset()
		self.addr = addr
		self.code = code

	def reset(self) -> None:
		self.addr = 0
		self.code = ""

	def __repr__(self):
		return repr({"addr": self.addr, "code": self.code})

class MacroSection:
	code: str = ""

	def __init__(self, code: str):
		self.reset()
		self.code = code

	def reset(self) -> None:
		self.code = ""

	def __repr__(self):
		return self.code

def add_percent_to_registers(code: str) -> str:
	return PERCENT_EXP.sub("%\g<1>", code)

def main() -> None:
	ks = Ks(KS_ARCH_PPC, KS_MODE_BIG_ENDIAN + KS_MODE_PPC64)

	data = Path("Patches/Spoofy.S").read_text()
	lines = data.splitlines()
	# remove empty lines, comment lines, and macro lines
	lines = [x for x in lines if x.strip() and not x.strip().startswith("#")]
	# remove EOL comments and remove whitespace
	for i in range(len(lines)):
		line = lines[i]
		if "#" in line:
			lines[i] = lines[i][:lines[i].find("#")].strip()
		else:
			lines[i] = lines[i].strip()

	symbol_name = ""
	symbols = OrderedDict()
	symbols["main_scope"] = []

	addr = 0
	for line in lines:
		line = add_percent_to_registers(line)
		matches =  LABEL_EXP.match(line)
		if matches:  # label start
			symbol_name = matches.group(1)
			symbols[symbol_name] = []
		else:
			if line.startswith("."):  # macro line
				if symbol_name == "":
					symbols["main_scope"].append(MacroSection(line))
				else:
					symbols[symbol_name].append(MacroSection(line))
			else:
				symbols[symbol_name].append(CodeSection(addr, line))
				addr += 4

	def sym_resolver(symbol: bytes, value):
		value.contents.value = symbols[symbol.decode("UTF8")][0].addr
		return True

	ks.sym_resolver = sym_resolver

	with BytesIO() as bio:
		for key in symbols.keys():
			for section in symbols[key]:
				try:
					if type(section) == MacroSection:
						(code, count) = ks.asm(section.code, as_bytes=True)
					elif type(section) == CodeSection:
						(code, count) = ks.asm(section.code, section.addr, as_bytes=True)
					if code is not None:
						bio.write(code)
					else:
						if type(section) == CodeSection:
							print(section.addr)
						print(section.code)
				except KsError as ke:
					if ke.errno == KS_ERR_ASM_SYMBOL_MISSING:
						print(f"SYMBOL MISSING @ 0x{section.addr:04X} - {section.code}")

				# addr += 4
		compiled = bio.getvalue()

	print(compiled.hex())

if __name__ == "__main__":
	main()