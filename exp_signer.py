#!/usr/bin/env python3

from os import urandom
from enum import IntEnum
from os.path import isfile
from struct import pack, pack_into
from argparse import ArgumentParser

from XeCrypt import *

EXP_SALT = b"XBOX360EXP"
EXP_SIZE = 0x1000

class ExpansionMagic(IntEnum):
	HXPR = 0x48585052
	HXPC = 0x48585043
	SIGM = 0x5349474D
	SIGC = 0x53494743

def sign_exp(in_file: str, out_file: str = None, key_file: str = "Keys/HVX_prv.bin", exp_magic: ExpansionMagic = ExpansionMagic.HXPR, exp_id: int = 0x48565050, encrypt: bool = True):
	cpu_key = b""
	prv_key = read_file(key_file)
	payload = read_file(in_file)
	exp_id = exp_id
	exp_typ = int(exp_magic)

	# pad payload to the 16 byte boundary
	payload_len_nopad = len(payload)
	payload += (b"\x00" * (((payload_len_nopad + 0xF) & ~0xF) - payload_len_nopad))
	payload_len_pad = len(payload)

	# allocate 0x1000 bytes for the expansion
	exp_final = bytearray(EXP_SIZE)

	# 0x0 -> expansion header
	exp_hdr = pack(">3I", exp_typ, 0, 0x170 + payload_len_pad)  # type, flags, padded size
	# 0xC
	exp_hdr += (b"\x00" * 0x14)  # SHA hash
	# 0x20
	exp_hdr += (b"\x00" * 0x10)  # exp_iv
	# 0x30
	exp_hdr += (b"\x00" * 0x100)  # RSA sig of above
	# 0x130 -> expansion info
	exp_hdr += pack(">4I 2Q 4I", exp_id, 0, 0, 0, 0, 0, 0, 0, 0x160, payload_len_pad + 0x10)
	# 0x160 -> expansion section info
	exp_hdr += pack(">3I 4x", 0x10, 0x10, payload_len_pad)
	# 0x170

	# write the header into the expansion
	pack_into(f"<{len(exp_hdr)}s", exp_final, 0, exp_hdr)
	# write the payload into the expansion
	pack_into(f"<{payload_len_pad}s", exp_final, len(exp_hdr), payload)

	# write the expansion hash
	b_hash = XeCryptSha(exp_final[0x130:0x170 + payload_len_pad])
	pack_into("<20s", exp_final, 0xC, b_hash)

	# write the expansion signature
	if exp_typ in [ExpansionMagic.HXPR, ExpansionMagic.SIGM]:
		b_hash = XeCryptRotSumSha(exp_final[:0x30])
		sig = XeCryptBnQwBeSigCreate(b_hash, EXP_SALT, prv_key)
		sig = XeCryptBnQwNeRsaPrvCrypt(sig, prv_key)
	elif exp_typ in [ExpansionMagic.HXPC, ExpansionMagic.SIGC]:
		assert XeCryptCpuKeyValid(cpu_key), "A valid CPU is required for HXPC/SIGC"
		b_hash = XeCryptHmacSha(cpu_key, exp_final[:0x30])
		# sig = XeKeysPkcs1Create(b_hash, prv_key)
		sig = XeCryptBnQwBeSigCreate(b_hash, EXP_SALT, prv_key)
		sig = XeCryptBnQwNeRsaPrvCrypt(sig, prv_key)
	else:
		raise Exception("Invalid expansion magic")

	# write the expansion signature
	pack_into(f"<{len(sig)}s", exp_final, 0x30, sig)

	# strip padding
	exp_final = exp_final[:0x170 + payload_len_pad]

	# write the encrypted expansion
	if exp_typ in [ExpansionMagic.HXPR, ExpansionMagic.HXPC]:
		if encrypt:  # encrypt everything after the signature
			exp_iv = urandom(0x10)
			pack_into("16s", exp_final, 0x20, exp_iv)
			enc_exp = XeCryptAesCbc(XECRYPT_1BL_KEY, exp_iv, exp_final[0x130:])
			pack_into(f"<{len(enc_exp)}s", exp_final, 0x130, enc_exp)

	# write it to a file
	write_file(out_file if out_file else in_file, exp_final)

def main() -> None:
	global EXP_SIZE

	parser = ArgumentParser(description="A script to sign HvxExpansionInstall payloads")
	parser.add_argument("input", type=str, help="The payload executable to sign")
	parser.add_argument("-o", "--ofile", type=str, help="The signed payload file")
	parser.add_argument("-i", "--expansion-id", type=str, default="0x48565050", help="The expansion ID to use")
	parser.add_argument("-k", "--keyfile", type=str, default="Keys/HVX_prv.bin", help="The private key to sign with")
	parser.add_argument("--encrypt", action="store_true", help="Encrypt the expansion")
	args = parser.parse_args()

	assert isfile(args.input), "The specified input file doesn't exist"
	args.expansion_id = int(args.expansion_id, 16)

	sign_exp(args.input, args.ofile, args.keyfile, exp_id=args.expansion_id, encrypt=args.encrypt)

if __name__ == "__main__":
	main()

__all__ = [
	"ExpansionMagic",
	"sign_exp"
]