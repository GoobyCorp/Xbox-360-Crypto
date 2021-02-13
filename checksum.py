#!/usr/bin/env python3

from os import listdir
from binascii import crc32
from argparse import ArgumentParser
from os.path import join, isfile, isdir

BUFF_SIZE = 2048

def checksum_file(filename: str) -> int:
	cksm = 0
	with open(filename, "rb") as f:
		while b := f.read(BUFF_SIZE):
			cksm = crc32(b, cksm)
	return cksm

def main() -> None:
	global BUFF_SIZE

	parser = ArgumentParser(description="A script to perform a CRC32 checksum on a file")
	parser.add_argument("-i", "--ifile", type=str, help="A file to checksum")
	parser.add_argument("-d", "--dir", type=str, help="A directory to checksum")
	args = parser.parse_args()

	if args.ifile and isfile(args.ifile):
		print(checksum_file(args.ifile))
	elif args.dir and isdir(args.dir):
		for single in listdir(args.dir):
			full_path = join(args.dir, single)
			if isfile(full_path):
				print(f"{single} -> {checksum_file(full_path)}")
	else:
		print("No file or directory specified to checksum")

if __name__ == "__main__":
	main()