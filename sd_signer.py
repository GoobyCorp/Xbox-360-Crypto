#!/usr/bin/env python3

__description__ = "A script to sign retail CD's and devkit SD bootloaders for Xbox 360"

from pathlib import Path
from binascii import crc32
from struct import pack_into
from argparse import ArgumentParser

from XeCrypt import *
from build_lib import sign_sd_4bl
from keystore import load_and_verify_sb_prv

SB_PRV_KEY: XeCryptRsaKey = None

def valid_file(parser: ArgumentParser, filename: str) -> Path:
	if not Path(filename).is_file():
		parser.error(f"The file \"{filename}\" doesn't exist!")
	else:
		return Path(filename)

def main() -> None:
	SB_PRV_KEY = load_and_verify_sb_prv()

	parser = ArgumentParser(description=__description__)
	parser.add_argument("input", type=lambda x: valid_file(parser, x), help="The CD/SD to sign")
	parser.add_argument("-o", type=lambda x: valid_file(parser, x), help="The file to output to")
	args = parser.parse_args()

	# make sure the CD/SD exists
	assert args.input.is_file(), "The input file specified doesn't exist"
	# read the CD/SD
	bl_data = bytearray(args.input.read_bytes())
	# make sure it's a valid image
	assert bl_data[:2] == b"CD" or bl_data[:2] == b"SD", "The input file specified isn't a valid CD or SD bootloader image"
	# append padding
	bl_data += (b"\x00" * (((len(bl_data) + 0xF) & ~0xF) - len(bl_data)))
	# set SD size
	pack_into(">I", bl_data, 0xC, len(bl_data))
	# resign SD
	bl_data = sign_sd_4bl(SB_PRV_KEY, XECRYPT_SD_SALT, bl_data)
	# zero nonces
	pack_into("16s", bl_data, 0x10, b"\x00" * 0x10)
	# write the CD/SD
	out_path = args.input if args.o is None else args.o
	out_path.write_bytes(bl_data)
	# output XeBuild checksums
	print(f"{out_path.name},{crc32(bl_data):08x}")

if __name__ == "__main__":
	main()