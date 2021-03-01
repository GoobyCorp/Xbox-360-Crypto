#!/usr/bin/env python3

from io import StringIO
from enum import IntEnum
from os.path import isfile
from argparse import ArgumentParser

lowercase = lambda s: s.lower()

class Language(IntEnum):
	PYTHON    = 0
	C         = 1
	CPLUSPLUS = 2
	CSHARP    = 3
	PHP       = 4
	PHP_NEW   = 5
	PHP_OLD   = 6

def lang_format(in_file: str, out_file: str = None, language: Language = Language.CPLUSPLUS, var_name: str = "data", byte_count: int = 16) -> str:
	with open(in_file, "rb") as fr:
		with StringIO() as sio:
			if language == Language.PYTHON:
				print(f"{var_name} = bytearray([", file=sio)
				lines = []
				while True:
					data = fr.read(byte_count)
					if not data:
						break
					lines.append("\t" + ", ".join([f"0x{x:02X}" for x in data]) + ",")
				lines[-1] = lines[-1].rstrip(",")
				[print(x, file=sio) for x in lines]
				print("])", file=sio)
			elif language in [Language.C, Language.CPLUSPLUS]:
				print("#ifndef BYTE", file=sio)
				print("typedef unsigned char BYTE", file=sio)
				print("#endif", file=sio)
				print(file=sio)
				print(f"#ifndef __{var_name}__", file=sio)
				print(f"#define __{var_name}__", file=sio)
				print(f"BYTE {var_name}[] = {{", file=sio)
				lines = []
				while True:
					data = fr.read(byte_count)
					if not data:
						break
					lines.append("\t" + ", ".join([f"0x{x:02X}" for x in data]) + ",")
				lines[-1] = lines[-1].rstrip(",")
				[print(x, file=sio) for x in lines]
				print("};", file=sio)
				print("#endif", file=sio)
			elif language == Language.CSHARP:
				print(f"#region {var_name}", file=sio)
				print(f"byte[] {var_name} = {{", file=sio)
				lines = []
				while True:
					data = fr.read(byte_count)
					if not data:
						break
					lines.append("\t" + ", ".join([f"0x{x:02X}" for x in data]) + ",")
				lines[-1] = lines[-1].rstrip(",")
				[print(x, file=sio) for x in lines]
				print("};", file=sio)
				print("#endregion", file=sio)
			elif language in [Language.PHP, Language.PHP_NEW]:  # using fast arrays
				print(f"${var_name} = [", file=sio)
				lines = []
				while True:
					data = fr.read(byte_count)
					if not data:
						break
					lines.append("\t" + ", ".join([f"0x{x:02X}" for x in data]) + ",")
				lines[-1] = lines[-1].rstrip(",")
				[print(x, file=sio) for x in lines]
				print("];", file=sio)
			elif language == Language.PHP_OLD:  # using slow arrays
				print(f"${var_name} = array(", file=sio)
				lines = []
				while True:
					data = fr.read(byte_count)
					if not data:
						break
					lines.append("\t" + ", ".join([f"0x{x:02X}" for x in data]) + ",")
				lines[-1] = lines[-1].rstrip(",")
				[print(x, file=sio) for x in lines]
				print(");", file=sio)

			data = sio.getvalue()

	if out_file is not None:
		with open(out_file, "w") as f:
			f.write(data)

	return data

def main() -> None:
	parser = ArgumentParser(description="A script to make embedding binaries in code a breeze")
	parser.add_argument("input", type=str, help="The binary to embed")
	parser.add_argument("output", type=str, help="A file to write the output to")
	parser.add_argument("-l", "--language", type=lowercase, default="python", help="The programming language to use")
	parser.add_argument("-b", "--bytes", type=int, default=16, help="The number of bytes per line")
	parser.add_argument("-v", "--variable", type=str, default="output", help="The name of the variable")
	args = parser.parse_args()

	assert isfile(args.input), "The specified input file doesn't exist"

	lang: Language = None
	if args.language in ["python", "py"]:
		lang = Language.PYTHON
	elif args.language == "c":
		lang = Language.C
	elif args.language in ["c++", "cpp", "cplusplus"]:
		lang = Language.CPLUSPLUS
	elif args.language in ["csharp", "cs", "c#"]:
		lang = Language.CSHARP
	elif args.language in ["php", "php-new"]:
		lang = Language.PHP
	elif args.language == "php-old":
		lang = Language.PHP_OLD
	else:
		raise Exception("Invalid language specified!")

	print(lang_format(args.input, args.output, lang, args.variable, args.bytes))

if __name__ == "__main__":
	main()

# exports
__all__ = ["Language", "lang_format"]