#!/usr/bin/env python3

from ctypes import *
from pathlib import Path
from binascii import crc32
from struct import unpack_from, pack_into

from StreamIO import *
from XeCrypt import XECRYPT_SD_SALT, XeCryptRotSumSha, XeCryptBnQwBeSigCreate, XeCryptBnQwNeRsaPrvCrypt

# C DLL's
libcedll = CDLL(str(Path("lib/x64/libcedll.dll").absolute()))

# C prototypes
# decompression
libcedll.ceDecompress.argtypes = [POINTER(c_ubyte), c_uint32]
libcedll.ceDecompress.restype = c_uint32
# compression
libcedll.ceCompress.argtypes = [POINTER(c_ubyte), c_uint32]
libcedll.ceCompress.restype = c_uint32

# C functions
def decompress_se(data: (bytes, bytearray)) -> bytearray:
	(u_size,) = unpack_from(">I", data, 0x28)
	c_buf = (c_ubyte * u_size).from_buffer_copy(data)
	assert libcedll.ceDecompress(c_buf, len(data)) == u_size, "SE decompression failed"
	return bytearray(c_buf)

def compress_se(data: (bytes, bytearray)) -> bytearray:
	c_buf = (c_ubyte * len(data)).from_buffer_copy(data)
	new_size = libcedll.ceCompress(c_buf, len(data))
	return bytearray(c_buf)[:new_size]

def sign_sd_4bl(key: (bytes, bytearray), salt: (bytes, bytearray), data: (bytes, bytearray)) -> bytearray:
	if type(data) == bytes:
		data = bytearray(data)

	h = XeCryptRotSumSha(data[:0x10] + data[0x120:])
	sig = XeCryptBnQwBeSigCreate(h, salt, key)
	sig = XeCryptBnQwNeRsaPrvCrypt(sig, key)
	pack_into("<256s", data, 0x20, sig)
	return data

# def verify_sd_4bl(key: (bytes, bytearray), salt: (bytes, bytearray), data: (bytes, bytearray)) -> bool:
#	sig = data[0x20:0x20 + 256]
#	h = XeCryptRotSumSha(data[:0x10] + data[0x120:])
#	return XeCryptBnQwBeSigVerify(sig, h, salt, key)

def apply_patches(bl_data: (bytes, bytearray), patch_data: (bytes, bytearray)) -> bytearray:
	with StreamIO(bl_data, Endian.BIG) as blsio:
		with StreamIO(patch_data, Endian.BIG) as psio:
			while True:
				addr = psio.read_uint32()
				if addr == 0xFFFFFFFF:
					break
				size = psio.read_uint32()
				patch = psio.read_ubytes(size * 4)
				blsio.write_ubytes_at(addr, patch)
		bl_data = blsio.getvalue()
	return bytearray(bl_data)

def main() -> None:
	SD_PRV_KEY = Path("Keys/SD_prv.bin").read_bytes()

	sd_data = bytearray(Path("Build/Mine/SD.bin").read_bytes())
	se_data = bytearray(Path("Build/Mine/hypervisor.bin").read_bytes() + Path("Build/Mine/kernel.exe").read_bytes())

	# pack_into(f"{0x4000}s", se_data, 0x162E0, Path("KV/banned.bin").read_bytes())

	# apply patches
	se_data = apply_patches(se_data, Path("Output/Zero/HVK.bin").read_bytes())
	# compress SE
	se_data = bytearray(compress_se(se_data))
	# magic, build, QFE, flags, and entry point
	pack_into(">2s 3H I", se_data, 0, b"SE", 17559, 0x8000, 0, 0)
	# get length of SE without padding
	se_len_nopad = len(se_data)
	# set SE size
	pack_into(">I", se_data, 0xC, len(se_data))
	# append padding AFTER
	se_data += (b"\x00" * (((se_len_nopad + 0xF) & ~0xF) - se_len_nopad))
	# compute SE hash
	se_hash = XeCryptRotSumSha(se_data[:0x10] + se_data[0x20:])
	# patch SE hash into SD
	pack_into("<20s", sd_data, 0x24C, se_hash)

	# add SD patches here
	# sd_data += b"\x00" * 0x400  # should be enough room for the loader
	# sd_data = apply_patches(sd_data, Path("Output/Zero/xell.bin").read_bytes())

	# get length of SD without padding
	sd_len_nopad = len(sd_data)
	# set SD size
	pack_into(">I", sd_data, 0xC, len(sd_data))
	# append padding AFTER
	sd_data += (b"\x00" * (((sd_len_nopad + 0xF) & ~0xF) - sd_len_nopad))
	# resign SD
	sd_data = sign_sd_4bl(SD_PRV_KEY, XECRYPT_SD_SALT, sd_data)
	# print(verify_sd_4bl(SD_PRV_KEY[:XECRYPT_RSAPUB_2048_SIZE], XECRYPT_SD_SALT, sd_data))
	# zero nonces
	pack_into("16s", sd_data, 0x10, b"\x00" * 0x10)
	pack_into("16s", se_data, 0x10, b"\x00" * 0x10)
	# write the SD and SE
	Path("Output/Zero/sd_17489.bin").write_bytes(sd_data)
	Path("Output/Zero/se_17559.bin").write_bytes(se_data)
	# output XeBuild checksums
	print(f"rgl_jasperbl/sd_17489.bin,{crc32(sd_data[:sd_len_nopad]):08x}")
	print(f"rgl_jasperbl/se_17559.bin,{crc32(se_data[:se_len_nopad]):08x}")

if __name__ == "__main__":
	main()