#!/usr/bin/env python3

import subprocess
from io import BytesIO
from enum import IntEnum
from pathlib import Path
from typing import Union, TypeVar, BinaryIO
from struct import pack, pack_into, unpack_from
from ctypes import BigEndianStructure, c_char, c_ubyte, c_uint16, c_uint32, c_uint64

from XeCrypt import *
from StreamIO import *
from LZX import *

BinLike = TypeVar("BinLike", bytes, bytearray, memoryview)

BIN_DIR = "bin"
INCLUDE_DIR = "Patches/include"

# types
BYTE  = c_ubyte
WORD  = c_uint16
DWORD = c_uint32
QWORD = c_uint64

class BLMagic(IntEnum):
	CA_1BL = 0x0342
	CB_2BL = 0x4342
	CC_3BL = 0x4343
	CD_4BL = 0x4344
	CE_5BL = 0x4345
	CF_6BL = 0x4346
	CG_7BL = 0x4347
	SB_2BL = 0x5342
	SC_3BL = 0x5343
	SD_4BL = 0x5344
	SE_5BL = 0x5345
	SF_6BL = 0x5346
	SG_7BL = 0x5347

# structures
class FLASH_HEADER(BigEndianStructure):
	_fields_ = [
		("magic", WORD),
		("build", WORD),
		("qfe", WORD),
		("flags", WORD),
		("entry", DWORD),
		("size", DWORD),
		("copyright", (c_char * 0x40)),
		("padding", (BYTE * 0x10)),
		("kv_length", DWORD),
		("sys_upd_addr", DWORD),
		("patch_slots", WORD),
		("kv_version", WORD),
		("kv_offset", DWORD),
		("patch_slot_size", DWORD),
		("smc_config_offset", DWORD),
		("smc_length", DWORD),
		("smc_offset", DWORD)
	]

class BLDR_HEADER(BigEndianStructure):
	_fields_ = [
		("magic", (BYTE * 2)),
		("build", WORD),
		("qfe", WORD),
		("flags", WORD),
		("entry", DWORD),
		("size", DWORD)
	]

class SB_2BL_HEADER(BigEndianStructure):
	_fields_ = [
		("header", BLDR_HEADER),
		("nonce", (BYTE * 0x10))
	]

SC_3BL_HEADER = SB_2BL_HEADER
SD_4BL_HEADER = SB_2BL_HEADER
SE_5BL_HEADER = SB_2BL_HEADER
SF_6BL_HEADER = SB_2BL_HEADER

HV_HEADER = BLDR_HEADER

class BLHeader:
	include_nonce = True

	magic = None
	build = None
	qfe = None
	flags = None
	entry_point = None
	size = None

	nonce = None

	def __init__(self, include_nonce: bool = True):
		self.reset()
		self.include_nonce = include_nonce
		# self.parse(data)

	def __bytes__(self) -> BinLike:
		data = pack(">2s 3H 2I", self.magic, self.build, self.qfe, self.flags, self.entry_point, self.size)
		if self.include_nonce:
			data += self.nonce
		return data

	def __dict__(self) -> dict:
		dct = {"magic": self.magic, "build": self.build, "qfe": self.qfe, "flags": self.flags, "entry_point": self.entry_point, "size": self.size}
		if self.include_nonce:
			dct["nonce"] = self.nonce
		return dct

	def __getitem__(self, item: str) -> Union[BinLike, int, bool]:
		item = item.lower()
		value = getattr(self, item, None)
		if value is not None:
			return value

	def __setitem__(self, key: str, value):
		key = key.lower()
		if getattr(self, key, None) is not None:
			setattr(self, key, value)

	@property
	def header_size(self) -> int:
		if self.include_nonce:
			return 0x20
		return 0x10

	@property
	def padded_size(self) -> int:
		return (self.size + 0xF) & ~0xF

	@property
	def requires_padding(self) -> bool:
		return self.padded_size > 0

	@staticmethod
	def parse(data: BinLike, include_nonce: bool = True):
		hdr = BLHeader(include_nonce)
		(hdr.magic, hdr.build, hdr.qfe, hdr.flags, hdr.entry_point, hdr.size) = unpack_from(">2s 3H 2I", data, 0)
		if hdr.include_nonce:
			(hdr.nonce,) = unpack_from("16s", data, 0x10)
		return hdr

	def reset(self) -> None:
		self.include_nonce = True
		self.magic = None
		self.build = None
		self.qfe = None
		self.flags = None
		self.size = None
		self.nonce = None

def assemble_patch(asm_filename: str, bin_filename: str, *defines) -> None:
	args = [str(Path(BIN_DIR) / "xenon-as.exe"), "-be", "-many", "-mregnames", asm_filename, "-o", "temp.elf"]
	args.extend(["-I", str(Path(asm_filename).parent.absolute())])
	args.extend(["-I", str(Path(INCLUDE_DIR).absolute())])
	[args.extend(["--defsym", f"{x}=1"]) for x in defines]
	result = subprocess.run(args, shell=True, stdout=subprocess.DEVNULL)
	assert result.returncode == 0, f"Patch assembly failed with error code {result.returncode}"

	args = [str(Path(BIN_DIR) / "xenon-objcopy.exe"), "temp.elf", "-O", "binary", bin_filename]
	result = subprocess.run(args, shell=True, stdout=subprocess.DEVNULL)
	assert result.returncode == 0, f"ELF conversion failed with error code {result.returncode}"

	Path("temp.elf").unlink()

def assemble_devkit_patch(asm_filename: str, bin_filename: str, *defines) -> None:
	assemble_patch(asm_filename, bin_filename, "DEVKIT", *defines)

def assemble_retail_patch(asm_filename: str, bin_filename: str, *defines) -> None:
	assemble_patch(asm_filename, bin_filename, "RETAIL", *defines)

def assemble_rgl_flash(asm_filename: str, bin_filename: str, *defines) -> None:
	assemble_patch(asm_filename, bin_filename, "FLASH", *defines)

def assemble_rgl_vfuses_flash(asm_filename: str, bin_filename: str, *defines) -> None:
	assemble_patch(asm_filename, bin_filename, "VFUSES", "FLASH", *defines)

def assemble_rgl_hdd(asm_filename: str, bin_filename: str, *defines) -> None:
	assemble_patch(asm_filename, bin_filename, "HDD", *defines)

def assemble_rgl_vfuses_hdd(asm_filename: str, bin_filename: str, *defines) -> None:
	assemble_patch(asm_filename, bin_filename, "VFUSES", "HDD", *defines)

def run_command(path: Union[Path, str], *args: str) -> tuple[int, str]:
	ep = Path(path)  # executable path
	a = [str(ep.absolute())]
	a.extend(args)
	result = subprocess.run(a, shell=True, stdout=subprocess.PIPE)
	return result.returncode, result.stdout.decode("UTF8", errors="ignore")

def get_bldr_size_in_place(stream: BinaryIO, offset: int) -> int:
	stream.seek(offset)
	magic = stream.read(2)
	assert magic in [b"SB", b"SC", b"SD", b"SE"], "Invalid bootloader magic!"
	stream.seek(10, SEEK_CUR)
	size = int.from_bytes(stream.read(4), "big", signed=False)
	size -= 0x20
	size += calc_bldr_pad_size(size)
	return size

def patch_in_place(stream: BinaryIO, patches: BinLike) -> int:
	c = 0
	loc = stream.tell()
	# stream.seek(0, SEEK_END)
	# bldr_size = stream.tell()
	with StreamIO(patches, Endian.BIG) as pio:
		while True:
			addr = pio.read_uint32()
			if addr == 0xFFFFFFFF:
				break
			size = pio.read_uint32()
			size *= 4
			data = pio.read(size)
			stream.seek(addr)
			test = stream.read(size)
			if test == data:
				continue
			stream.seek(addr)
			stream.write(data)
			c += 1
	stream.seek(loc)
	return c

def encrypt_bldr_in_place(key: BinLike, stream: BinaryIO, offset: int) -> None:
	loc = stream.tell()
	size = get_bldr_size_in_place(stream, offset)

	# skip nonce
	stream.seek(16, SEEK_CUR)
	# read data
	data = stream.read(size)
	# encrypt data and padding
	data = encrypt_bl(key, data, False)
	# write the data back
	stream.seek(offset + 0x20)
	stream.write(data)
	stream.seek(loc)

def calc_se_hash_in_place(stream: BinaryIO, offset: int) -> bytes:
	loc = stream.tell()
	size = get_bldr_size_in_place(stream, offset)

	# create hash
	with BytesIO() as bio:
		stream.seek(offset)
		bio.write(stream.read(0x10))
		stream.seek(offset + 0x20)
		bio.write(stream.read(size))
		h_data = bio.getvalue()
	h = XeCryptRotSumSha(h_data)

	stream.seek(loc)
	return h

def sign_bldr_in_place(stream: BinaryIO, offset: int, key: XeCryptRsaKey) -> None:
	loc = stream.tell()
	size = get_bldr_size_in_place(stream, offset)

	# create hash
	with BytesIO() as bio:
		stream.seek(offset)
		bio.write(stream.read(0x10))
		stream.seek(offset + 0x120)
		bio.write(stream.read(size - 0x100))
		h_data = bio.getvalue()
	h = XeCryptRotSumSha(h_data)

	# create signature
	sig = key.sig_create(h, XECRYPT_SD_SALT)

	# write the signature
	stream.seek(offset + 0x20)
	stream.write(sig)

	stream.seek(loc)

# C functions
def decompress_se(data: Union[bytes, bytearray], skip_header: bool = True) -> bytes:
	if skip_header:
		data = data[0x30:]
	with LZXDecompression() as lzxd:
		return lzxd.decompress_continuous(data)

def compress_se(data: Union[bytes, bytearray], include_header: bool = True) -> bytes:
	with LZXCompression() as lzxc:
		data = lzxc.compress_continuous(data)
		if include_header:
			data = bytearray(0x30) + data
			pack_into(">I", data, 0xC, len(data))
			pack_into(">I", data, 0x28, 0x280000)
		return data

def sign_sd_4bl(key: Union[XeCryptRsaKey, bytes, bytearray], salt: Union[bytes, bytearray], data: Union[bytes, bytearray]) -> bytearray:
	if type(key) in [bytes, bytearray]:
		key = XeCryptRsaKey(key)
	if type(data) == bytes:
		data = bytearray(data)

	h = XeCryptRotSumSha(data[:0x10] + data[0x120:])
	sig = key.sig_create(h, salt)
	data[0x20:0x20 + len(sig)] = sig
	return data

def verify_sd_4bl(key: Union[XeCryptRsaKey, bytes, bytearray], salt: Union[bytes, bytearray], data: Union[bytes, bytearray]) -> bool:
	if type(key) in [bytes, bytearray]:
		key = XeCryptRsaKey(key)

	sig = data[0x20:0x20 + 256]
	h = XeCryptRotSumSha(data[:0x10] + data[0x120:])
	return key.sig_verify(sig, h, salt)

def encrypt_bl(key: Union[bytes, bytearray], data: BinLike, skip_header: bool = True) -> bytearray:
	with BytesIO(data) as bio:
		if skip_header:
			bio.seek(0x20)  # skip header and nonce
		bl_data_enc = XeCryptRc4.new(key).encrypt(bio.read())  # read all of the remaining data and encrypt it
		if skip_header:
			bio.seek(0x20)  # write the encrypted data back
		else:
			bio.seek(0)
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
	return ((size + 0xF) & ~0xF) - size

__all__ = [
	# enums
	"BLMagic",

	# classes
	"BLHeader",

	# structures
	"FLASH_HEADER",
	"BLDR_HEADER",
	"SB_2BL_HEADER",
	"SC_3BL_HEADER",
	"SD_4BL_HEADER",
	"SE_5BL_HEADER",
	"HV_HEADER",

	# functions
	"assemble_patch",
	"assemble_devkit_patch",
	"assemble_retail_patch",
	"assemble_rgl_flash",
	"assemble_rgl_vfuses_flash",
	"assemble_rgl_hdd",
	"assemble_rgl_vfuses_hdd",
	"run_command",

	"get_bldr_size_in_place",
	"patch_in_place",
	"encrypt_bldr_in_place",
	"calc_se_hash_in_place",
	"sign_bldr_in_place",

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