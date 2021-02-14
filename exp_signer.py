#!/usr/bin/env python3

from os import urandom
from enum import IntEnum
from argparse import ArgumentParser
from os.path import isfile, basename

from bin2lang import lang_format

from XeCrypt import *

EXPANSION_SIZE = 0x1000

class ExpansionMagic(IntEnum):
	HXPR = 0x48585052
	HXPC = 0x48585043
	SIGM = 0x5349474D
	SIGC = 0x53494743

def main() -> None:
	global EXPANSION_SIZE

	parser = ArgumentParser(description="A script to sign HvxExpansionInstall payloads")
	parser.add_argument("input", type=str, help="The payload executable to sign")
	parser.add_argument("-o", "--ofile", type=str, help="The signed payload file")
	parser.add_argument("-i", "--expansion-id", type=str, default="0x48565050", help="The expansion ID to use")
	parser.add_argument("--no-encrypt", action="store_true", help="Disable expansion encryption")
	args = parser.parse_args()

	assert isfile(args.input), "The specified input file doesn't exist"
	args.expansion_id = int(args.expansion_id, 16)

	print(f"Signing \"{basename(args.input)}\"...")

	cpu_key = b""
	hvx_prv = read_file("Keys/HVX_prv.bin")
	payload = read_file(args.input)
	exp_id = args.expansion_id
	exp_typ = ExpansionMagic.HXPR

	# pad payload
	payload += (b"\x00" * (len(payload) % 16))

	# allocate 0x1000 bytes for the expansion
	exp_final = bytearray(EXPANSION_SIZE)

	# expansion header
	exp_hdr = pack(">3I", exp_typ, 0, EXPANSION_SIZE)
	exp_hdr += (b"\x00" * 0x14)  # SHA hash
	exp_hdr += (b"\x00" * 0x10)  # exp_iv  # AES feed
	exp_hdr += (b"\x00" * 0x100)  # RSA sig of above

	# expansion info
	exp_hdr += pack(">4I 2Q 4I", exp_id, 0, 0, 0, 0, 0, 0, 0, 0x160, len(payload) + 0x10)

	# expansion section info
	exp_hdr += pack(">3I 4x", 0x10, 0x10, len(payload))

	# write the header into the expansion
	pack_into(f"<{len(exp_hdr)}s", exp_final, 0, exp_hdr)
	# write the payload into the expansion
	pack_into(f"<{len(payload)}s", exp_final, len(exp_hdr), payload)

	# write the expansion hash
	b_hash = XeCryptSha(exp_final[0x130:])
	pack_into("<20s", exp_final, 0xC, b_hash)

	# write the expansion signature
	if exp_typ in [ExpansionMagic.HXPR, ExpansionMagic.SIGM]:
		b_hash = XeCryptRotSumSha(exp_final[:0x30])
	elif exp_typ in [ExpansionMagic.HXPC, ExpansionMagic.SIGC]:
		assert XeCryptCpuKeyValid(cpu_key), "A valid CPU is required for everything but SIGM/HXPR"
		b_hash = XeCryptHmacSha(cpu_key, exp_final[:0x30])
	sig = XeKeysPkcs1Create(b_hash, hvx_prv)
	pack_into(f"<{len(sig)}s", exp_final, 0x30, sig)

	# strip padding
	exp_final = exp_final[:len(exp_hdr) + len(payload)]

	# write the encrypted expansion
	if exp_typ in [ExpansionMagic.HXPR, ExpansionMagic.HXPC]:
		exp_iv = urandom(0x10)
		pack_into("16s", exp_final, 0xC + 0x14, exp_iv)
		if not args.no_encrypt:
			enc_exp = XeCryptAesCbc(XECRYPT_1BL_KEY, exp_iv, exp_final[0x30:])
			pack_into(f"<{len(enc_exp)}s", exp_final, 0x30, enc_exp)

	# write it to a file
	out_file = args.ofile if args.ofile else args.input
	print(f"Outputting to \"{basename(out_file)}\"...")
	write_file(out_file, exp_final)

	print("Done!")

if __name__ == "__main__":
	main()