#!/usr/bin/env python3

from os import urandom
from struct import pack
from enum import IntEnum
from os.path import isfile
from argparse import ArgumentParser

from keystore import load_and_verify_hvx_prv
from XeCrypt import *

PAYLOAD_SALT = b"XBOX_EX_01"

class PayloadMagic(IntEnum):
	DEVKIT = 0x5D4D
	RETAIL = 0x4D4D

def sign_xekeys(in_file: str, out_file: str = None, pl_magic: PayloadMagic = PayloadMagic.DEVKIT) -> None:
	hvx_prv = load_and_verify_hvx_prv()
	payload = read_file(in_file)
	hvx_key = urandom(0x10)

	# build header
	hvx_hdr = pack(">2H 3I 16s 256x", pl_magic, 0xDEAD, 0, 0x120, 0x120 + len(payload), hvx_key)

	# prepend header to payload
	payload = bytearray(hvx_hdr + payload)

	b_hash = XeCryptRotSumSha(payload[:0x10] + payload[0x120:])[:0x14]
	sig = hvx_prv.sig_create(b_hash, PAYLOAD_SALT)
	payload[0x20:0x20 + len(sig)] = sig
	rc4_key = XeCryptHmacSha(XECRYPT_1BL_KEY, hvx_key)[:0x10]
	enc_payload = XeCryptRc4.new(rc4_key).encrypt(payload[0x20:])
	payload[0x20:0x20 + len(enc_payload)] = enc_payload

	# write the signed payload to disk
	write_file(out_file if out_file else in_file, payload)

def main() -> int:
	parser = ArgumentParser(description="A script to sign XeKeysExecute payloads")
	parser.add_argument("input", type=str, help="The payload executable to sign")
	parser.add_argument("output", type=str, help="The signed payload file")
	args = parser.parse_args()

	assert isfile(args.input), "The specified input file doesn't exist"

	sign_xekeys(args.input, args.output)

	print("Done!")

	return 0

if __name__ == "__main__":
	exit(main())

__all__ = [
	"PayloadMagic",
	"sign_xekeys"
]