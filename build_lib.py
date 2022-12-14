#!/usr/bin/env python3

import subprocess
from io import BytesIO
from typing import Union
from pathlib import Path
from os.path import abspath
from struct import pack_into, unpack_from
from ctypes import CDLL, POINTER, c_ubyte, c_uint32

from XeCrypt import *
from StreamIO import *

BIN_DIR = "bin"

# C DLL's
libcedll = CDLL(abspath("lib/x64/libcedll.dll"))

# C prototypes
# decompression
libcedll.ceDecompress.argtypes = [POINTER(c_ubyte), c_uint32]
libcedll.ceDecompress.restype = c_uint32
# compression
libcedll.ceCompress.argtypes = [POINTER(c_ubyte), c_uint32]
libcedll.ceCompress.restype = c_uint32

def assemble_patch(asm_filename: str, bin_filename: str, *includes) -> None:
	args = [str(Path(BIN_DIR) / "xenon-as.exe"), "-be", "-many", "-mregnames", asm_filename, "-o", "temp.elf"]
	args.extend(["-I", str(Path(asm_filename).parent.absolute())])
	[args.extend(["-I", str(Path(x).absolute())]) for x in includes]
	result = subprocess.run(args, shell=True, stdout=subprocess.DEVNULL)
	assert result.returncode == 0, f"Patch assembly failed with error code {result.returncode}"

	args = [str(Path(BIN_DIR) / "xenon-objcopy.exe"), "temp.elf", "-O", "binary", bin_filename]
	result = subprocess.run(args, shell=True, stdout=subprocess.DEVNULL)
	assert result.returncode == 0, f"ELF conversion failed with error code {result.returncode}"

	Path("temp.elf").unlink()

# C functions
def decompress_se(data: Union[bytes, bytearray]) -> bytearray:
	(u_size,) = unpack_from(">I", data, 0x28)
	c_buf = (c_ubyte * u_size)(*data)
	assert libcedll.ceDecompress(c_buf, len(data)) == u_size, "SE decompression failed"
	return bytearray(c_buf)

def compress_se(data: Union[bytes, bytearray]) -> bytearray:
	c_buf = (c_ubyte * len(data))(*data)
	new_size = libcedll.ceCompress(c_buf, len(data))
	return bytearray(c_buf)[:new_size]

def sign_sd_4bl(key: Union[PY_XECRYPT_RSA_KEY, bytes, bytearray], salt: Union[bytes, bytearray], data: Union[bytes, bytearray]) -> bytearray:
	if type(key) in [bytes, bytearray]:
		key = PY_XECRYPT_RSA_KEY(key)
	if type(data) == bytes:
		data = bytearray(data)

	h = XeCryptRotSumSha(data[:0x10] + data[0x120:])
	sig = key.sig_create(h, salt)
	pack_into(f"<{len(sig)}s", data, 0x20, sig)
	return data

def verify_sd_4bl(key: Union[PY_XECRYPT_RSA_KEY, bytes, bytearray], salt: Union[bytes, bytearray], data: Union[bytes, bytearray]) -> bool:
	if type(key) in [bytes, bytearray]:
		key = PY_XECRYPT_RSA_KEY(key)

	sig = data[0x20:0x20 + 256]
	h = XeCryptRotSumSha(data[:0x10] + data[0x120:])
	return key.sig_verify(sig, h, salt)

def encrypt_bl(key: Union[bytes, bytearray], data: Union[bytes, bytearray]) -> bytearray:
	with BytesIO(data) as bio:
		bio.seek(0x20)  # skip header and nonce
		bl_data_enc = XeCryptRc4.new(key).encrypt(bio.read())  # read all of the remaining data and encrypt it
		bio.seek(0x20)  # write the encrypted data back
		bio.write(bl_data_enc)
		data = bio.getvalue()
	return bytearray(data)

def apply_jump_sd_4bl(data: Union[bytes, bytearray], size: int) -> bytearray:
	with StreamIO(data, Endian.BIG) as sio:
		while True:
			if sio.read_uint32() == 0x4C000024:
				sio.offset -= 4
				dist = (size & ~0x80000000) - (sio.offset & ~0x80000000)
				ret = 0x48000000 | (dist & 0x3FFFFFC)
				sio.write_uint32(ret)
				break
		data = sio.getvalue()
	return bytearray(data)

def apply_patches(bl_data: Union[bytes, bytearray], patch_data: Union[str, bytes, bytearray]) -> bytearray:
	with StreamIO(bl_data, Endian.BIG) as blsio, StreamIO(patch_data, Endian.BIG) as psio:
		while True:
			addr = psio.read_uint32()
			if addr == 0xFFFFFFFF:
				break
			size = psio.read_uint32()
			patch = psio.read_ubytes(size * 4)
			blsio.write_ubytes_at(addr, patch)
		bl_data = blsio.getvalue()
	return bytearray(bl_data)

def calc_patch_size(patch_data: Union[bytes, bytearray], size: int) -> int:
	patch_size = 0
	with StreamIO(patch_data, Endian.BIG) as psio:
		while True:
			addr = psio.read_uint32()
			if addr == 0xFFFFFFFF:
				break
			ps = psio.read_uint32()
			psio.seek(ps * 4, SEEK_CUR)
			if addr >= size:
				patch_size += (ps * 4)
	return patch_size

def calc_pad_size(size: int, bounds: int = 16) -> int:
	return (bounds - (size % bounds)) % bounds

def calc_bldr_pad_size(size: int) -> int:
	return (size + 0xF & 0xFFFFFFF0) - size

__all__ = [
	"assemble_patch",
	"decompress_se",
	"compress_se",
	"sign_sd_4bl",
	"verify_sd_4bl",
	"encrypt_bl",
	"apply_jump_sd_4bl",
	"apply_patches",
	"calc_patch_size",
	"calc_pad_size",
	"calc_bldr_pad_size"
]