#!/usr/bin/env python3

from os import urandom
from os.path import isfile
from struct import pack, pack_into
from argparse import ArgumentParser

from XeCrypt import *

PAYLOAD_MAGIC = 0x5D4D
PAYLOAD_SALT = b"XBOX_EX_01"

def main() -> None:
	global PAYLOAD_MAGIC, PAYLOAD_SALT

	parser = ArgumentParser(description="A script to sign XeKeysExecute payloads")
	parser.add_argument("input", type=str, help="The payload executable to sign")
	parser.add_argument("output", type=str, help="The signed payload file")
	args = parser.parse_args()

	assert isfile(args.input), "The specified input file doesn't exist"

	hvx_prv = read_file("Keys/HVX_prv.bin")
	payload = read_file(args.input)
	hvx_key = urandom(0x10)

	# build header
	hvx_hdr = pack(">4H 2I 16s 256x", PAYLOAD_MAGIC, 0xDEAD, 0, 0x120, len(payload), hvx_key)

	# prepend header to payload
	payload = bytearray(hvx_hdr + payload)

	b_hash = XeCryptRotSumSha(payload[:0x10] + payload[0x120:])[:0x14]
	sig = XeCryptBnQwBeSigCreate(b_hash, PAYLOAD_SALT, hvx_prv)
	sig = XeCryptBnQwNeRsaPrvCrypt(sig, hvx_prv)
	pack_into("<%ss" % (len(sig)), payload, 0x20, sig)
	rc4_key = XeCryptHmacSha(XECRYPT_1BL_KEY, hvx_key)[:0x10]
	enc_payload = XeCryptRc4Ecb(rc4_key, payload[0x20:])
	pack_into("<%ss" % (len(enc_payload)), payload, 0x20, enc_payload)

	# write the signed payload to disk
	write_file(args.output, payload)

if __name__ == "__main__":
	main()