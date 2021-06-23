#!/usr/bin/env python3

from pathlib import Path
from binascii import crc32
from struct import pack_into

from XeCrypt import *
from build_lib import *

def main() -> None:
	SD_PRV_KEY = Path("Keys/SB_prv.bin").read_bytes()

	sd_data = bytearray(Path("Output/Winchester/sd_17489.bin").read_bytes())
	se_data = bytearray(Path("Output/Winchester/hypervisor.bin").read_bytes() + Path("Output/Winchester/kernel.exe").read_bytes())

	# apply patches
	se_data = apply_patches(se_data, Path("Output/Zero/HVK.bin").read_bytes())
	# compress SE
	se_data = bytearray(compress_se(se_data))
	# magic, build, QFE, flags, and entry point
	pack_into(">2s 3H I", se_data, 0, b"SE", 17559, 0x8000, 0, 0)
	# get length of SE without padding
	se_len_nopad = len(se_data)
	# apply padding BEFORE
	# se_data += (b"\x00" * calc_pad_size(se_len_nopad))
	# set SE size
	pack_into(">I", se_data, 0xC, se_len_nopad)
	# append padding AFTER
	se_data += (b"\x00" * calc_pad_size(se_len_nopad))
	# compute SE hash
	se_hash = XeCryptRotSumSha(se_data[:0x10] + se_data[0x20:])
	# patch SE hash into SD
	pack_into("<20s", sd_data, 0x24C, se_hash)

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
	sd_data = sign_sd_4bl(SD_PRV_KEY, XECRYPT_SD_SALT, sd_data)
	# zero nonces
	pack_into("16x", sd_data, 0x10)
	pack_into("16x", se_data, 0x10)
	# write the SD and SE
	Path("Output/Zero/sd_17489.bin").write_bytes(sd_data)
	Path("Output/Zero/se_17559.bin").write_bytes(se_data)
	# output XeBuild checksums
	print(f"winchesterbl_rgl/sd_17489.bin,{crc32(sd_data[:sd_len_nopad]):08x}")
	print(f"winchesterbl_rgl/se_17559.bin,{crc32(se_data[:se_len_nopad]):08x}")

if __name__ == "__main__":
	main()