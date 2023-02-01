#!/usr/bin/env python3

from pathlib import Path
from binascii import crc32
from struct import pack_into

from XeCrypt import *
from build_lib import *
from keystore import load_and_verify_sb_prv

SB_PRV_KEY: PY_XECRYPT_RSA_KEY = None

def patch_rehash_sign_se(sd_data: bytes | bytearray, se_data: bytes | bytearray, se_patch_data: bytes | bytearray = None) -> tuple[tuple[int, bytearray], tuple[int, bytearray]]:
	if isinstance(sd_data, bytes):
		sd_data = bytearray(sd_data)

	if isinstance(se_data, bytes):
		se_data = bytearray(se_data)

	# apply patches to SE
	if se_patch_data is not None:
		se_data = apply_patches(se_data, se_patch_data)

	# compress SE
	se_data = bytearray(compress_se(se_data))
	se_data = bytearray(0x20) + se_data
	# magic, build, QFE, flags, and entry point
	pack_into(">2s 3H I", se_data, 0, b"SE", 17559, 0x8000, 0, 0)
	# get length of SE without padding
	se_len_nopad = len(se_data)
	# set SE size
	pack_into(">I", se_data, 0xC, se_len_nopad)
	# append padding
	se_data += (b"\x00" * calc_pad_size(se_len_nopad))
	# compute SE hash
	se_hash = XeCryptRotSumSha(se_data[:0x10] + se_data[0x20:])
	# patch SE hash into SD
	pack_into("20s", sd_data, 0x24C, se_hash)

	# get length of SD without padding
	sd_len_nopad = len(sd_data)

	# xell!
	# xell_data = Path("Output/Zero/xell.bin").read_bytes()
	# patch_size = calc_patch_size(xell_data, sd_len_nopad)
	# sd_data += (b"\x00" * patch_size)
	# sd_data = apply_patches(sd_data, xell_data)
	# sd_data = apply_jump_sd_4bl(sd_data, sd_len_nopad)
	# sd_len_nopad += patch_size
	# apply padding BEFORE
	# sd_data += (b"\x00" * calc_pad_size(sd_len_nopad))

	# set SD size
	pack_into(">I", sd_data, 0xC, sd_len_nopad)
	# apply padding AFTER
	sd_data += (b"\x00" * calc_pad_size(sd_len_nopad))
	# resign SD
	sd_data = sign_sd_4bl(SB_PRV_KEY, XECRYPT_SD_SALT, sd_data)

	return ((sd_len_nopad, sd_data), (se_len_nopad, se_data))

def main() -> int:
	global SB_PRV_KEY

	SB_PRV_KEY = load_and_verify_sb_prv()

	con_rev = "Jasper"

	base_dir = Path(f"Output/Extracted/{con_rev}/")

	sd_data = (base_dir / "sd_17489.bin").read_bytes()
	se_data = (base_dir / "hypervisor.bin").read_bytes() + (base_dir / "kernel.exe").read_bytes()
	se_patch_data = Path("Output/Zero/VRGL.bin").read_bytes()

	((sd_len_nopad, sd_data), (se_len_nopad, se_data)) = patch_rehash_sign_se(sd_data, se_data, se_patch_data)

	# zero nonces
	pack_into("16x", sd_data, 0x10)
	pack_into("16x", se_data, 0x10)

	# write the SD and SE
	Path(f"xeBuild_1.21/Builds/17559 - RGL/bootloaders/rgl/{con_rev.lower()}bl/sd_17489.bin").write_bytes(sd_data)
	Path(f"xeBuild_1.21/Builds/17559 - RGL/bootloaders/rgl/{con_rev.lower()}bl/se_17559.bin").write_bytes(se_data)
	# output XeBuild checksums
	print(f"[{con_rev.lower()}bl]")
	print(f"bootloaders/rgl/{con_rev.lower()}bl/sd_17489.bin,{crc32(sd_data[:sd_len_nopad]):08x}")
	print(f"bootloaders/rgl/{con_rev.lower()}bl/se_17559.bin,{crc32(se_data[:se_len_nopad]):08x}")

	return 0

if __name__ == "__main__":
	exit(main())