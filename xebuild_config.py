#!/usr/bin/env python3

from pathlib import Path
from binascii import crc32
from io import StringIO, BytesIO
from argparse import ArgumentParser

BUFF_SIZE = 2048

def checksum(data: (bytes, bytearray)) -> int:
	cksm = 0
	with BytesIO(data) as bio:
		while b := bio.read(BUFF_SIZE):
			cksm = crc32(b, cksm)
	return cksm

def main() -> None:
	parser = ArgumentParser(description="A script to generate build configs for XeBuild")
	parser.add_argument("-d", "--dir", type=str, help="The directory to search for XeBuild files")
	args = parser.parse_args()

	root_p = Path("./")
	with StringIO() as sio:
		for single in root_p.iterdir():
			if single.is_file():
				pass

if __name__ == "__main__":
	main()