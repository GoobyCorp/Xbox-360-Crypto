#!/usr/bin/env python3

import re
import subprocess
from argparse import ArgumentParser
from os.path import join, abspath, isfile, isdir

SDK_VER = "11775.3"

SDK_DIR = "C:\\Program Files (x86)\\Microsoft Xbox 360 SDK\\bin\\win32"

HEADER_RE = re.compile(r"DLL\sname\s*:\s*([\w\W]{0,}?)\r\n")
EXPORT_RE = re.compile(r"\s+(\d+)\s+([\w\W]{0,}?)\r\n")

def dumpbin(command: str, filename: str) -> str:
	global SDK_DIR

	p = subprocess.Popen([join(SDK_DIR, "dumpbin.exe"), "/" + command.upper(), abspath(filename)], stdout=subprocess.PIPE, shell=True)
	(output, err) = p.communicate()
	if p.wait() != 0:
		print("Error!")
	return output.decode("utf8")

def fetch_version(s: str) -> (str, None):
	global HEADER_RE

	matches = HEADER_RE.search(s)
	if matches:
		return matches.group(1)

def create_def(ifile: str, ofile: str, verbose: bool = False) -> None:
	global EXPORT_RE

	assert isfile(ifile), "Input file doesn't exist!"

	res = dumpbin("headers", ifile)
	lib_ver = fetch_version(res)
	assert lib_ver, "Error locating library version!"
	res = dumpbin("exports", ifile)
	with open(ofile, "wb") as f:
		if verbose: print(f"LIBRARY {lib_ver}")
		f.write(f"LIBRARY {lib_ver}\r\n".encode("ascii"))
		if verbose: print("EXPORTS")
		f.write("EXPORTS\r\n".encode("ascii"))

		# if debug: print("Parsing dumpbin response...")
		clean = []
		for (ordinal, func) in EXPORT_RE.findall(res, re.MULTILINE):
			if not func.startswith("."):
				clean.append((int(ordinal), func))

		# if debug: print("Sorting results by ordinal...")
		clean.sort(key=lambda i: i[0])
		for (ordinal, func) in clean:
			if verbose: print(f"\t{func} @{ordinal}")
			f.write(f"\t{func} @{ordinal}\r\n".encode("ascii"))

def main() -> None:
	global SDK_DIR, SDK_VER

	parser = ArgumentParser(description="A script to create .def files from Xbox 360 libraries using dumpbin in the SDK")
	parser.add_argument("ifile", type=str, help="The library you want to dump exports from")
	parser.add_argument("ofile", type=str, help="The file you want to write the definitions to")
	parser.add_argument("-v", "--verbose", action="store_true", help="Print verbose information out")
	args = parser.parse_args()

	assert isdir(SDK_DIR), "The Xbox 360 SDK doesn't appear to be installed"
	assert isfile(args.ifile), "The input file doesn't exist"

	create_def(args.ifile, args.ofile, args.verbose)

if __name__ == "__main__":
	main()