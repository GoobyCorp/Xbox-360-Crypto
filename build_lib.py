#!/usr/bin/env python3

import subprocess
from io import BytesIO
from enum import IntEnum
from pathlib import Path
from typing import Union, TypeVar
from struct import pack, pack_into, unpack_from
from ctypes import BigEndianStructure, c_ubyte, c_uint16, c_uint32, c_uint64

from XeCrypt import *
from StreamIO import *
from LZX import *

BinType = TypeVar("BinType", bytes, bytearray, memoryview)

BIN_DIR = "bin"
INCLUDE_DIR = "includes"

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
class NAND_HEADER(BigEndianStructure):
	_fields_ = [
		("magic", WORD),
		("build", WORD),
		("qfe", WORD),
		("flags", WORD),
		("entry", DWORD),
		("size", DWORD),
		("copyright", (BYTE * 0x40)),
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

class BL_HEADER(BigEndianStructure):
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
		("header", BL_HEADER),
		("nonce", (BYTE * 0x10))
	]

SC_3BL_HEADER = SB_2BL_HEADER
SD_4BL_HEADER = SB_2BL_HEADER
SE_5BL_HEADER = SB_2BL_HEADER
SF_6BL_HEADER = SB_2BL_HEADER

HV_HEADER = BL_HEADER

class BLHeader:
	include_nonce = True

	magic = None
	build = None
	qfe = None
	flags = None
	entry_point = None
	size = None

	nonce = None

	def __init__(self, data: BinType, include_nonce: bool = True):
		self.include_nonce = include_nonce
		self.reset()
		self.parse(data)

	def __bytes__(self) -> BinType:
		data = pack(">2s 3H 2I", self.magic, self.build, self.qfe, self.flags, self.entry_point, self.size)
		if self.include_nonce:
			data += self.nonce
		return data

	def __dict__(self) -> dict:
		dct = {"magic": self.magic, "build": self.build, "qfe": self.qfe, "flags": self.flags, "entry_point": self.entry_point, "size": self.size}
		if self.include_nonce:
			dct["nonce"] = self.nonce
		return dct

	def __getitem__(self, item: str) -> Union[BinType, int, bool]:
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

	def parse(self, data: BinType):
		(self.magic, self.build, self.qfe, self.flags, self.entry_point, self.size) = unpack_from(">2s 3H 2I", data, 0)
		if self.include_nonce:
			(self.nonce,) = unpack_from("16s", data, 0x10)

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

def run_command(path: Union[Path, str], *args: str) -> tuple[int, str]:
	ep = Path(path)  # executable path
	a = [str(ep.absolute())]
	a.extend(args)
	result = subprocess.run(a, shell=True, stdout=subprocess.PIPE)
	return result.returncode, result.stdout.decode("UTF8", errors="ignore")

# C functions
def decompress_se(data: Union[bytes, bytearray]) -> bytes:
	data = data[0x30:]  # skip header
	with LZXDecompression() as lzxd:
		return lzxd.decompress_continuous(data)

def compress_se(data: Union[bytes, bytearray]) -> bytes:
	with LZXCompression() as lzxc:
		data = lzxc.compress_continuous(data)
		data = bytearray(0x30) + data
		pack_into(">I", data, 0xC, len(data))
		pack_into(">I", data, 0x28, 0x280000)
		return data

def sign_sd_4bl(key: Union[PY_XECRYPT_RSA_KEY, bytes, bytearray], salt: Union[bytes, bytearray], data: Union[bytes, bytearray]) -> bytearray:
	if type(key) in [bytes, bytearray]:
		key = PY_XECRYPT_RSA_KEY(key)
	if type(data) == bytes:
		data = bytearray(data)

	h = XeCryptRotSumSha(data[:0x10] + data[0x120:])
	sig = key.sig_create(h, salt)
	data[0x20:0x20 + len(sig)] = sig
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
	return ((size + 0xF) & ~0xF) - size

__all__ = [
	# classes
	"BLHeader",

	# structures
	"NAND_HEADER",
	"BL_HEADER",
	"SB_2BL_HEADER",
	"SC_3BL_HEADER",
	"SD_4BL_HEADER",
	"SE_5BL_HEADER",
	"HV_HEADER",

	# functions
	"assemble_patch",
	"assemble_devkit_patch",
	"assemble_retail_patch",
	"run_command",
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