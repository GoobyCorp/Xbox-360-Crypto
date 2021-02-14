#!/usr/bin/env python3

from os.path import isfile
from argparse import ArgumentParser

lowercase = lambda s: s.lower()

def lang_format(in_file: str, out_file: str, language: str, var_name: str, byte_count: int = 16):
	with open(in_file, "rb") as fr:
		with open(out_file, "w") as fw:
			if language in ["python", "py"]:
				print(f"{var_name} = bytearray([", file=fw)
				lines = []
				while True:
					data = fr.read(byte_count)
					if not data:
						break
					lines.append("\t" + ", ".join([f"0x{x:02X}" for x in data]) + ",")
				lines[-1] = lines[-1].rstrip(",")
				[print(x, file=fw) for x in lines]
				print("])", file=fw)
			elif language in ["c", "c++", "cpp", "cplusplus"]:
				print("#ifndef BYTE", file=fw)
				print("typedef unsigned char BYTE", file=fw)
				print("#endif", file=fw)
				print(file=fw)
				print(f"#ifndef __{var_name}__", file=fw)
				print(f"#define __{var_name}__", file=fw)
				print(f"BYTE {var_name}[] = {{", file=fw)
				lines = []
				while True:
					data = fr.read(byte_count)
					if not data:
						break
					lines.append("\t" + ", ".join([f"0x{x:02X}" for x in data]) + ",")
				lines[-1] = lines[-1].rstrip(",")
				[print(x, file=fw) for x in lines]
				print("};", file=fw)
				print("#endif", file=fw)
			elif language in ["csharp", "c#"]:
				print(f"#region {var_name}", file=fw)
				print(f"byte[] {var_name} = {{", file=fw)
				lines = []
				while True:
					data = fr.read(byte_count)
					if not data:
						break
					lines.append("\t" + ", ".join([f"0x{x:02X}" for x in data]) + ",")
				lines[-1] = lines[-1].rstrip(",")
				[print(x, file=fw) for x in lines]
				print("};", file=fw)
				print("#endregion", file=fw)
			elif language in ["php-new", "php"]:  # using fast arrays
				print(f"${var_name} = [", file=fw)
				lines = []
				while True:
					data = fr.read(byte_count)
					if not data:
						break
					lines.append("\t" + ", ".join([f"0x{x:02X}" for x in data]) + ",")
				lines[-1] = lines[-1].rstrip(",")
				[print(x, file=fw) for x in lines]
				print("];", file=fw)
			elif language == "php-old":  # using slow arrays
				print(f"${var_name} = array(", file=fw)
				lines = []
				while True:
					data = fr.read(byte_count)
					if not data:
						break
					lines.append("\t" + ", ".join([f"0x{x:02X}" for x in data]) + ",")
				lines[-1] = lines[-1].rstrip(",")
				[print(x, file=fw) for x in lines]
				print(");", file=fw)

def main() -> None:
	parser = ArgumentParser(description="A script to make embedding binaries in code a breeze")
	parser.add_argument("input", type=str, help="The binary to embed")
	parser.add_argument("output", type=str, help="A file to write the output to")
	parser.add_argument("-l", "--language", type=lowercase, default="python", help="The programming language to use")
	parser.add_argument("-b", "--bytes", type=int, default=16, help="The number of bytes per line")
	parser.add_argument("-v", "--variable", type=str, default="output", help="The name of the variable")
	args = parser.parse_args()

	assert isfile(args.input), "The specified input file doesn't exist"
	assert args.language in ["python", "py", "c", "c++", "cpp", "cplusplus", "csharp", "c#", "php", "php-old", "php-new"], "Invalid programming language specified"

	lang_format(args.input, args.output, args.language, args.variable, args.bytes)

if __name__ == "__main__":
	main()