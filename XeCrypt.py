#!/usr/bin/env python3

"""
Gigantic shout out to cOz for all the help in porting this, without him this wouldn't have been possible!
"""

__author__ = "Visual Studio"
__maintainer__ = "Visual Studio"
__credits__ = ["Visual Studio", "cOz", "TEIR1plus2", "ED9"]
__version__ = "1.0.0.0"
__license__ = "GPL"
__status__ = "Development"

from math import gcd
from os import urandom
from array import array
from enum import IntEnum
from pathlib import Path
from typing import Union, Tuple
from io import BytesIO, StringIO
from struct import pack, unpack, pack_into, unpack_from, calcsize
from ctypes import BigEndianStructure, c_ubyte, c_uint16, c_uint32, c_uint64

# pip install pycryptodome
from Crypto.PublicKey import RSA
from Crypto.Hash import MD5, SHA1, HMAC
from Crypto.Cipher import ARC4, DES, DES3, AES

# globals
# ciphers
RC4_CIPHER: ARC4  = None
AES_CIPHER: AES   = None
DES_CIPHER: DES   = None
DES3_CIPHER: DES3 = None

# constants
XECRYPT_SMC_KEY  = bytes.fromhex("42754E79")
XECRYPT_1BL_KEY  = bytes.fromhex("DD88AD0C9ED669E7B56794FB68563EFA")
XECRYPT_1BL_SALT = b"XBOX_ROM_B"
XECRYPT_SC_SALT  = b"XBOX_ROM_3"
XECRYPT_SD_SALT  = b"XBOX_ROM_4"
BUFFER_SIZE      = 4096

UINT8_MASK   = 0xFF
UINT16_MASK  = 0xFFFF
UINT32_MASK  = 0xFFFFFFFF
UINT64_MASK  = 0xFFFFFFFFFFFFFFFF
UINT128_MASK = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF

# public key sizes
XECRYPT_RSAPUB_1024_SIZE = 0x90
XECRYPT_RSAPUB_1536_SIZE = 0xD0
XECRYPT_RSAPUB_2048_SIZE = 0x110
XECRYPT_RSAPUB_4096_SIZE = 0x210

# private key sizes
XECRYPT_RSAPRV_1024_SIZE = 0x1D0 + 0x10
XECRYPT_RSAPRV_1536_SIZE = 0x280 + 0x10
XECRYPT_RSAPRV_2048_SIZE = 0x380 + 0x10
XECRYPT_RSAPRV_4096_SIZE = 0x710 + 0x10

XECRYPT_SHA_DIGEST_SIZE       = 0x14
XECRYPT_HMAC_SHA_MAX_KEY_SIZE = 0x40

XECRYPT_DES_BLOCK_SIZE = 0x8
XECRYPT_DES_KEY_SIZE   = 0x8

XECRYPT_DES3_BLOCK_SIZE = 0x8
XECRYPT_DES3_KEY_SIZE   = 0x18

XECRYPT_MD5_DIGEST_SIZE = 0x10

XECRYPT_AES_BLOCK_SIZE = 0x10
XECRYPT_AES_KEY_SIZE   = 0x10
XECRYPT_AES_FEED_SIZE  = 0x10

XECRYPT_ROTSUM_DIGEST_SIZE = 0x20

# types
BYTE  = c_ubyte
WORD  = c_uint16
DWORD = c_uint32
QWORD = c_uint64

# enumerations
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
	   ("cb_offset", DWORD),
	   ("sf1_offset", DWORD),
	   ("copyright", (BYTE * 0x40)),
	   ("padding", (BYTE * 0x10)),
	   ("kv_length", DWORD),
	   ("sf2_offset", DWORD),
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
		("entry_point", DWORD),
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

class XECRYPT_SIG(BigEndianStructure):
	_fields_ = [
		("aqwPad", (QWORD * 28)),
		("bOne", BYTE),
		("abSalt", (BYTE * 0xA)),
		("abHash", (BYTE * 0x14)),
		("bEnd", BYTE)
	]

class XECRYPT_RSA(BigEndianStructure):
	_fields_ = [
		("cqw", DWORD),
		("e", DWORD),
		("qwReserved", QWORD)
	]

class XECRYPT_RSAPUB_1024(BigEndianStructure):
	_fields_ = [
		("rsa", XECRYPT_RSA),
		("n", (BYTE * 128))
	]

class XECRYPT_RSAPUB_1536(BigEndianStructure):
	_fields_ = [
		("rsa", XECRYPT_RSA),
		("n", (BYTE * 192))
	]

class XECRYPT_RSAPUB_2048(BigEndianStructure):
	_fields_ = [
		("rsa", XECRYPT_RSA),
		("n", (BYTE * 256))
	]

class XECRYPT_RSAPUB_4096(BigEndianStructure):
	_fields_ = [
		("rsa", XECRYPT_RSA),
		("n", (BYTE * 512))
	]


class XECRYPT_RSAPRV_1024(BigEndianStructure):
	_fields_ = [
		("rsa", XECRYPT_RSA),
		("n", (BYTE * 128)),
		("p", (BYTE * 64)),
		("q", (BYTE * 64)),
		("dp", (BYTE * 64)),
		("dq", (BYTE * 64)),
		("cr", (BYTE * 64)),
	]

class XECRYPT_RSAPRV_1536(BigEndianStructure):
	_fields_ = [
		("rsa", XECRYPT_RSA),
		("n", (BYTE * 192)),
		("p", (BYTE * 96)),
		("q", (BYTE * 96)),
		("dp", (BYTE * 96)),
		("dq", (BYTE * 96)),
		("cr", (BYTE * 96)),
	]

class XECRYPT_RSAPRV_2048(BigEndianStructure):
	_fields_ = [
		("rsa", XECRYPT_RSA),
		("n", (BYTE * 256)),
		("p", (BYTE * 128)),
		("q", (BYTE * 128)),
		("dp", (BYTE * 128)),
		("dq", (BYTE * 128)),
		("cr", (BYTE * 128)),
	]

class XECRYPT_RSAPRV_4096(BigEndianStructure):
	_fields_ = [
		("rsa", XECRYPT_RSA),
		("n", (BYTE * 512)),
		("p", (BYTE * 256)),
		("q", (BYTE * 256)),
		("dp", (BYTE * 256)),
		("dq", (BYTE * 256)),
		("cr", (BYTE * 256)),
	]

class SMALLBLOCK(BigEndianStructure):
	def __getattribute__(self, item):
		if item == "block_id":
			res = ((self.block_id_0 << 8) & 0xF) + (self.block_id_1 & 0xFF)
		elif item == "fs_size":
			res = ((self.fs_size_0 << 8) & 0xFF) + (self.fs_size_1 & 0xFF)
		else:
			res = super(SMALLBLOCK, self).__getattribute__(item)
		return res

	_fields_ = [
		("block_id_1", BYTE),  # lba/id = (((BlockID0<<8)&0xF)+(BlockID1&0xFF))
		("block_id_0", BYTE, 4),
		("fs_unused_0", BYTE, 4),
		("fs_sequence_0", BYTE),
		("fs_sequence_1", BYTE),
		("fs_sequence_2", BYTE),
		("bad_block", BYTE),
		("fs_sequence_3", BYTE),
		("fs_size_1", BYTE),  # (((FsSize0<<8)&0xFF)+(FsSize1&0xFF)) = cert size
		("fs_size_0", BYTE),
		("fs_page_count", BYTE),  # free pages left in block (ie: if 3 pages are used by cert then this would be 29:0x1d)
		("fs_unused_1", BYTE * 2),
		("fs_block_type", BYTE, 6),
		("ecc_3", BYTE, 2),  # 26 bit ECD
		("ecc_2", BYTE),
		("ecc_1", BYTE),
		("ecc_0", BYTE)
	]

class BIGONSMALL(BigEndianStructure):
	def __getattribute__(self, item):
		if item == "block_id":
			res = ((self.block_id_0 << 8) & 0xF) + (self.block_id_1 & 0xFF)
		elif item == "fs_size":
			res = ((self.fs_size_0 << 8) & 0xFF) + (self.fs_size_1 & 0xFF)
		else:
			res = super(BIGONSMALL, self).__getattribute__(item)
		return res
		
	_fields_ = [
		("fs_sequence_0", BYTE),
		("block_id_1", BYTE),  # lba/id = (((BlockID0<<8)&0xF)+(BlockID1&0xFF))
		("block_id_0", BYTE, 4),
		("fs_unused_0", BYTE, 4),
		("fs_sequence_1", BYTE),
		("fs_sequence_2", BYTE),
		("bad_block", BYTE),
		("fs_sequence_3", BYTE),
		("fs_size_1", BYTE),  # (((FsSize0<<8)&0xFF)+(FsSize1&0xFF)) = cert size
		("fs_size_0", BYTE),
		("fs_page_count", BYTE),  # free pages left in block (ie: if 3 pages are used by cert then this would be 29:0x1d)
		("fs_unused_1", BYTE * 2),
		("fs_block_type", BYTE, 6),
		("ecc_3", BYTE, 2),  # 26 bit ECD
		("ecc_2", BYTE),
		("ecc_1", BYTE),
		("ecc_0", BYTE)
	]

class BIGBLOCK(BigEndianStructure):
	def __getattribute__(self, item):
		if item == "block_id":
			res = ((self.block_id_0 << 8) & 0xF) + (self.block_id_1 & 0xFF)
		elif item == "fs_size":
			res = ((self.fs_size_0 << 8) & 0xFF) + (self.fs_size_1 & 0xFF)
		else:
			res = super(BIGBLOCK, self).__getattribute__(item)
		return res
	
	def __setattr__(self, key, value):
		if key == "block_id":
			raise NotImplementedError("block_id can't be set yet!")
		elif key == "fs_size":
			raise NotImplementedError("fs_size can't be set yet!")
		else:
			res = super(BIGBLOCK, self).__setattr__(key, value)
		return res

	_fields_ = [
		("bad_block", BYTE),
		("block_id_1", BYTE),  # lba/id = (((BlockID0<<8)&0xF)+(BlockID1&0xFF))
		("block_id_0", BYTE, 4),
		("fs_unused_0", BYTE, 4),
		("fs_sequence_1", BYTE),
		("fs_sequence_2", BYTE),
		("fs_sequence_0", BYTE),
		("fs_sequence_3", BYTE),
		("fs_size_1", BYTE),  # FS: 06 (system reserve block number) else (((FsSize0<<8)&0xFF)+(FsSize1&0xFF)) = cert size
		("fs_size_0", BYTE),  # FS: 20 (size of flash filesys in smallblocks >>5)
		("fs_page_count", BYTE),  # FS: 04 (system config reserve) free pages left in block (multiples of 4 pages, ie if 3f then 3f*4 pages are free after)
		("fs_unused_1", BYTE * 2),
		("fs_block_type", BYTE, 6),
		("ecc_3", BYTE, 2),  # 26 bit ECD
		("ecc_2", BYTE),
		("ecc_1", BYTE),
		("ecc_0", BYTE)
	]

# utilities
def read_file(filename: str, text: bool = False) -> Union[bytes, str]:
	p = Path(filename)
	if text:
		return p.read_text()
	else:
		return p.read_bytes()

def write_file(filename: str, data: (str, bytes, bytearray)) -> None:
	p = Path(filename)
	if type(data) == str:
		p.write_text(data)
	else:
		p.write_bytes(data)

def reverse(b: Union[bytes, bytearray]) -> Union[bytes, bytearray]:
	return bytes(reversed(b))

def print_c_array(data: Union[bytes, bytearray], fmt: str = "B", endian: str = "<", name: str = "output", bpr: int = 16) -> str:
	word_lut = ["BYTE", "WORD", "DWORD", 0, "QWORD"]
	bytes_per_item = calcsize(fmt)
	words_per_item = bytes_per_item // 2
	num_row_items = bpr // bytes_per_item
	num_rows = len(data) // bpr
	with BytesIO(data) as bio:
		with StringIO() as sio:
			sio.write(f"{word_lut[words_per_item]} {name}[] = {{\n")
			for row_num in range(num_rows):
				row_items = unpack(f"{endian}{num_row_items}{fmt}", bio.read(bytes_per_item * num_row_items))
				sio.write("\t")
				for item in row_items:
					sio.write("0x" + hex(item)[2:].zfill(bytes_per_item * 2).upper())
					if row_num != (num_rows - 1) or item != row_items[-1]:
						sio.write(", ")
				sio.write("\n")
			sio.write("};")
			output = sio.getvalue()
	print(output)
	return output

def bswap(data: Union[bytes, bytearray], fmt: str) -> bytes:
	size = calcsize(fmt)
	assert len(data) % size == 0, "data isn't evenly divisible by size!"
	out_data = b""
	for i in range(0, len(data), size):
		tmp = b""
		for j in range(0, size):
			tmp += pack("<B", data[i + j])
		out_data += reverse(tmp)
	return out_data

def bswap16(data: Union[bytes, bytearray]) -> bytes:
	return bswap(data, "H")

def bswap32(data: Union[bytes, bytearray]) -> bytes:
	return bswap(data, "I")

def bswap64(data: Union[bytes, bytearray]) -> bytes:
	return bswap(data, "Q")

def XeCryptBnQw_SwapDwQwLeBe(b: Union[bytes, bytearray]) -> bytes:
	return bswap64(b)

def lcm(p: int, q: int) -> int:
	return p * q // gcd(p, q)

def egcd(e: int, phi: int) -> Tuple[int, int, int]:
	if e == 0:
		return (phi, 0, 1)
	else:
		(g, y, x) = egcd(phi % e, e)
		return (g, x - (phi // e) * y, y)

def modinv(e: int, phi: int) -> int:
	(g, x, y) = egcd(e, phi)
	return x % phi

def memcmp(b0: Union[bytes, bytearray], b1: Union[bytes, bytearray], size: int) -> bool:
	return all([(b0[i] == b1[i]) for i in range(size)])

def rsa_calc_d(e: int, p: int, q: int) -> int:
	return modinv(e, lcm(p - 1, q - 1))

def XeCryptRandom(cb: int) -> bytes:
	return urandom(cb)

# hashing
def XeCryptMd5(*args: Union[bytes, bytearray]) -> bytes:
	hasher = MD5.new()
	[hasher.update(x) for x in args]
	return hasher.digest()

def XeCryptSha(*args: Union[bytes, bytearray]) -> bytes:
	hasher = SHA1.new()
	[hasher.update(x) for x in args]
	return hasher.digest()

# MAC
def XeCryptHmacMd5(key: Union[bytes, bytearray], *args: Union[bytes, bytearray]) -> bytes:
	hasher = HMAC.new(key, digestmod=MD5)
	[hasher.update(x) for x in args]
	return hasher.digest()

def XeCryptHmacSha(key: Union[bytes, bytearray], *args: Union[bytes, bytearray]) -> bytes:
	hasher = HMAC.new(key, digestmod=SHA1)
	[hasher.update(x) for x in args]
	return hasher.digest()

# RC4
def XeCryptRc4EcbKey(key: Union[bytes, bytearray]) -> None:
	global RC4_CIPHER

	RC4_CIPHER = ARC4.new(key)

def XeCryptRc4(data: Union[bytes, bytearray]) -> bytes:
	global RC4_CIPHER

	assert RC4_CIPHER is not None, "AES cipher isn't initialized, use XeCryptRc4Key"

	return RC4_CIPHER.encrypt(data)

def XeCryptRc4Ecb(key: Union[bytes, bytearray], data: Union[bytes, bytearray]) -> bytes:
	XeCryptRc4EcbKey(key)
	return XeCryptRc4(data)

# AES
def XeCryptAesEcbKey(key: (bytes, bytearray)) -> None:
	global AES_CIPHER

	AES_CIPHER = AES.new(key, AES.MODE_ECB)

def XeCryptAesCbcKey(key: Union[bytes, bytearray], iv: Union[bytes, bytearray]) -> None:
	global AES_CIPHER

	AES_CIPHER = AES.new(key, AES.MODE_CBC, iv)

def XeCryptAes(data: Union[bytes, bytearray], encrypt: bool = True) -> bytes:
	global AES_CIPHER

	assert AES_CIPHER is not None, "AES cipher isn't initialized, use XeCryptAesEcbKey or XeCryptAesCbcKey"

	if encrypt:
		data = AES_CIPHER.encrypt(data)
	else:
		data = AES_CIPHER.decrypt(data)
	return data

def XeCryptAesEcb(key: Union[bytes, bytearray], data: Union[bytes, bytearray], encrypt: bool = True) -> bytes:
	XeCryptAesEcbKey(key)
	return XeCryptAes(data, encrypt)

def XeCryptAesCbc(key: Union[bytes, bytearray], iv: Union[bytes, bytearray], data: Union[bytes, bytearray], encrypt: bool = True) -> bytes:
	XeCryptAesCbcKey(key, iv)
	return XeCryptAes(data, encrypt)

# DES
def XeCryptDesEcbKey(key: (bytes, bytearray)) -> None:
	global DES_CIPHER

	DES_CIPHER = DES.new(key, DES.MODE_ECB)

def XeCryptDesCbcKey(key: Union[bytes, bytearray], iv: Union[bytes, bytearray]) -> None:
	global DES_CIPHER

	DES_CIPHER = DES.new(key, DES.MODE_CBC, iv)

def XeCryptDes(data: Union[bytes, bytearray], encrypt: bool = True) -> bytes:
	global DES_CIPHER

	assert DES_CIPHER is not None, "DES cipher isn't initialized, use XeCryptDesEcbKey or XeCryptDesCbcKey"

	if encrypt:
		data = DES_CIPHER.encrypt(data)
	else:
		data = DES_CIPHER.decrypt(data)
	return data

def XeCryptDesEcb(key: Union[bytes, bytearray], data: Union[bytes, bytearray], encrypt: bool = True) -> bytes:
	XeCryptDesEcbKey(key)
	return XeCryptDes(data, encrypt)

def XeCryptDesCbc(key: Union[bytes, bytearray], iv: Union[bytes, bytearray], data: Union[bytes, bytearray], encrypt: bool = True) -> bytes:
	XeCryptDesCbcKey(key, iv)
	return XeCryptDes(data, encrypt)

# DES3
def XeCryptDes3EcbKey(key: (bytes, bytearray)) -> None:
	global DES3_CIPHER

	DES3_CIPHER = DES3.new(key, DES3.MODE_ECB)

def XeCryptDes3CbcKey(key: (bytes, bytearray), iv: (bytes, bytearray)) -> None:
	global DES3_CIPHER

	DES3_CIPHER = DES3.new(key, DES3.MODE_CBC, iv)

def XeCryptDes3(data: Union[bytes, bytearray], encrypt: bool = True) -> bytes:
	global DES3_CIPHER

	assert DES3_CIPHER is not None, "DES3 cipher isn't initialized, use XeCryptDes3EcbKey or XeCryptDes3CbcKey"

	if encrypt:
		data = DES3_CIPHER.encrypt(data)
	else:
		data = DES3_CIPHER.decrypt(data)
	return data

def XeCryptDes3Ecb(key: Union[bytes, bytearray], data: Union[bytes, bytearray], encrypt: bool = True) -> bytes:
	XeCryptDes3EcbKey(key)
	return XeCryptDes3(data, encrypt)

def XeCryptDes3Cbc(key: Union[bytes, bytearray], iv: Union[bytes, bytearray], data: Union[bytes, bytearray], encrypt: bool = True) -> bytes:
	XeCryptDes3CbcKey(key, iv)
	return XeCryptDes3(data, encrypt)

# conversions
def XeCryptRsaBinToStruct(data: Union[bytes, bytearray]) -> Union[XECRYPT_RSAPUB_1024, XECRYPT_RSAPUB_2048, XECRYPT_RSAPUB_4096, XECRYPT_RSAPRV_1024, XECRYPT_RSAPRV_2048, XECRYPT_RSAPRV_4096]:
	size = len(data)

	# public keys
	if size == XECRYPT_RSAPUB_1024_SIZE:
		return XECRYPT_RSAPUB_1024.from_buffer_copy(data)
	elif size == XECRYPT_RSAPUB_2048_SIZE:
		return XECRYPT_RSAPUB_2048.from_buffer_copy(data)
	elif size == XECRYPT_RSAPUB_4096_SIZE:
		return XECRYPT_RSAPUB_4096.from_buffer_copy(data)

	# private keys
	elif size == XECRYPT_RSAPRV_1024_SIZE:
		return XECRYPT_RSAPRV_1024.from_buffer_copy(data)
	elif size == XECRYPT_RSAPRV_2048_SIZE:
		return XECRYPT_RSAPRV_2048.from_buffer_copy(data)
	elif size == XECRYPT_RSAPRV_4096_SIZE:
		return XECRYPT_RSAPRV_4096.from_buffer_copy(data)

def XeCryptRsaStructToBin(struct: Union[XECRYPT_RSAPUB_1024, XECRYPT_RSAPUB_2048, XECRYPT_RSAPUB_4096, XECRYPT_RSAPRV_1024, XECRYPT_RSAPRV_2048, XECRYPT_RSAPRV_4096]) -> bytes:
	return bytes(struct)

def XeCryptPrintRsa(key: Union[bytes, bytearray, XECRYPT_RSAPUB_1024, XECRYPT_RSAPUB_2048, XECRYPT_RSAPUB_4096, XECRYPT_RSAPRV_1024, XECRYPT_RSAPRV_2048, XECRYPT_RSAPRV_4096]) -> None:
	if type(key) in [bytes, bytearray]:
		key = XeCryptRsaBinToStruct(key)

	#print(f"Modulus: {key.n:%04X}")
	print("u32 dwPubExp = " + "0x" + hex(key.rsa.e)[2:].zfill(8).upper() + ";")
	print_c_array(key.n, "Q", ">", "aqwM")
	if type(key) in [XECRYPT_RSAPRV_1024, XECRYPT_RSAPRV_2048, XECRYPT_RSAPRV_4096]:
		print_c_array(key.p, "Q", ">", "aqwP")
		print_c_array(key.q, "Q", ">", "aqwQ")
		print_c_array(key.dp, "Q", ">", "aqwDP")
		print_c_array(key.dq, "Q", ">", "aqwDQ")
		print_c_array(key.cr, "Q", ">", "aqwCR")

# checksums
def XeCryptRotSum(data: Union[bytes, bytearray]) -> bytes:
	cqwInp = len(data) // 8
	if cqwInp != 0:
		qw1 = 0
		qw2 = 0
		qw3 = 0
		qw4 = 0
		for i in range(cqwInp):
			tqw = int.from_bytes(data[(i * 8):(i * 8) + 8], "big")

			qw2 += tqw
			qw2 &= UINT64_MASK
			qw4 -= tqw
			qw4 &= UINT64_MASK

			qw1 += (qw2 < tqw)
			qw2 = (qw2 * 0x20000000) | (qw2 >> 0x23)
			qw2 &= UINT64_MASK

			qw3 -= (tqw < qw4)
			qw3 &= UINT64_MASK
			qw4 = (qw4 * 0x80000000) | (qw4 >> 0x21)
			qw4 &= UINT64_MASK
		return pack(">4Q", qw1, qw2, qw3, qw4)

def XeCryptRotSumSha(data: Union[bytes, bytearray]) -> bytes:
	hasher = SHA1.new()
	rot_sum = bytearray(XeCryptRotSum(data))
	hasher.update(rot_sum + rot_sum + data)
	for i in range(0x20):
		rot_sum[i] = (~rot_sum[i] & 0xFF)
	hasher.update(rot_sum + rot_sum)
	return hasher.digest()

# RSA
def XeCryptMulHdu(val1: int, val2: int) -> Tuple[int, int]:
	val1 &= UINT64_MASK
	val2 &= UINT64_MASK
	a = val1 * val2
	a &= UINT128_MASK
	hi_val = (a >> 64) & UINT64_MASK
	lo_val = a & UINT64_MASK
	return (hi_val, lo_val)

def XeCryptBnQwNeModMul(qw_a: Union[bytes, bytearray], qw_b: Union[bytes, bytearray], qw_mi: int, qw_m: Union[bytes, bytearray], cqw: int) -> bytes:
	a_arr = array("Q", unpack(f">{cqw}Q", qw_a))
	b_arr = array("Q", unpack(f">{cqw}Q", qw_b))
	m_arr = array("Q", unpack(f">{cqw}Q", qw_m))
	c_arr = array("Q", [0] * cqw)
	acc_arr_1 = array("Q", [0] * 0x21)
	acc_arr_2 = array("Q", [0] * 0x21)

	mmi_stat = qw_mi * a_arr[0]
	mmi_stat &= UINT64_MASK
	for i in range(cqw):
		mmi = (mmi_stat * b_arr[i]) + (qw_mi * (acc_arr_1[1] - acc_arr_2[1]))
		acc_1 = 0
		acc_2 = 0
		for j in range(cqw):
			(hi_val, lo_val) = XeCryptMulHdu(b_arr[i], a_arr[j])
			lo_val += acc_arr_1[j + 1]
			lo_val &= UINT64_MASK
			hi_val += (lo_val < acc_arr_1[j + 1])
			lo_val += acc_1
			lo_val &= UINT64_MASK
			hi_val += (lo_val < acc_1)
			acc_1 = hi_val
			lo_val &= UINT64_MASK
			acc_arr_1[j] = lo_val

			(hi_val, lo_val) = XeCryptMulHdu(mmi, m_arr[j])
			lo_val += acc_arr_2[j + 1]
			lo_val &= UINT64_MASK
			hi_val += (lo_val < acc_arr_2[j + 1])
			lo_val += acc_2
			lo_val &= UINT64_MASK
			hi_val += (lo_val < acc_2)
			acc_2 = hi_val
			lo_val &= UINT64_MASK
			acc_arr_2[j] = lo_val
		acc_arr_1[cqw] = acc_1
		acc_arr_2[cqw] = acc_2
	for i in range(cqw):
		if acc_arr_1[cqw - i] > acc_arr_2[cqw - i]:
			car = 0
			for j in range(cqw):
				val = (acc_arr_1[j + 1] - acc_arr_2[j + 1]) - car
				val &= UINT64_MASK
				c_arr[j] = val
				val = (val ^ acc_arr_1[j + 1]) | (acc_arr_2[j + 1] ^ acc_arr_1[j + 1])
				car = (acc_arr_1[j + 1] ^ val) >> 63
			return bswap64(bytes(c_arr))
		if acc_arr_1[cqw - i] < acc_arr_2[cqw - i]:
			car1 = 0
			car2 = 0
			for j in range(cqw):
				val1 = m_arr[j]
				val2 = (acc_arr_1[j + 1] + val1) + car1
				val3 = (val2 - acc_arr_2[j + 1]) - car2
				val3 &= UINT64_MASK
				c_arr[j] = val3
				val1 ^= val2
				val3 ^= val2
				car1 = (((acc_arr_1[j + 1] ^ val2) | val1) ^ val2) >> 63
				car2 = (((acc_arr_2[j + 1] ^ val2) | val3) ^ val2) >> 63
			return bswap64(bytes(c_arr))

def XeCryptBnQwNeModInv(val: int) -> int:
	t1 = val * 3
	t2 = t1 ^ 2
	t1 = t2 * val
	t1 = (~t1) + 2
	i = 5
	while i < 0x20:
		t3 = t1 + 1
		t2 *= t3
		t2 &= UINT64_MASK
		t1 *= t1
		t1 &= UINT64_MASK
		i <<= 1
	t1 = t1 + 1
	return t1 * t2

def XeCryptBnQwNeModExpRoot(data: int, p: int, q: int, dp: int, dq: int, cr: int) -> int:
	c = data % p  # XeCryptBnQwNeMod
	m1 = pow(c, dp, p)  # XeCryptBnQwNeModExp
	c = data % q  # XeCryptBnQwNeMod
	m2 = pow(c, dq, q)  # XeCryptBnQwNeModExp

	h = (cr * (m1 - m2)) % p
	m = (m2 + (h * q)) % (p * q)
	return m

def BnQwBeBufSwap(data: Union[bytes, bytearray], cqw: int) -> bytes:
	data = bytearray(data)
	pstart = 0
	pend = (cqw - 1) * 8
	for i in range(cqw // 2):
		val1 = unpack(">Q", data[pstart:pstart + 8])[0]
		val2 = unpack(">Q", data[pend:pend + 8])[0]
		pack_into(">Q", data, pend, val1)
		pack_into(">Q", data, pstart, val2)
		pend -= 8
		pstart += 8
	return data

def XeCryptBnQwNeRsaKeyToRsaProv(rsa_key: Union[bytes, bytearray]) -> RSA:
	(cqw,) = unpack(">I", rsa_key[:calcsize("I")])
	assert cqw in [0x10, 0x18, 0x20, 0x40], "Unsupported key size"
	try:
		mod_size = cqw * 8
		param_size = mod_size // 2
		(cqw, dwPubExp, qwReserved, aqwM, aqwP, aqwQ, aqwDP, aqwDQ, aqwCR) = unpack(f">2IQ {mod_size}s {param_size}s {param_size}s {param_size}s {param_size}s {param_size}s", rsa_key)

		n = int.from_bytes(bswap64(aqwM), "little")
		p = int.from_bytes(bswap64(aqwP), "little")
		q = int.from_bytes(bswap64(aqwQ), "little")
		d = rsa_calc_d(dwPubExp, p, q)

		return RSA.construct((n, dwPubExp, d, p, q))
	except:
		mod_size = cqw * 8
		(cqw, dwPubExp, qwReserved, aqwM) = unpack(f">2IQ {mod_size}s", rsa_key)

		aqwM = int.from_bytes(bswap64(aqwM), "little")

		return RSA.construct((aqwM, dwPubExp))

def XeCryptBnQwNeRsaKeyGen(cbits: int = 2048, dwPubExp: int = 0x10001) -> Tuple[bytes, bytes]:
	prv_key = RSA.generate(cbits, e=dwPubExp)
	mod_size = prv_key.size_in_bytes()
	param_size = mod_size // 2
	cqw = mod_size // 8

	n = bswap64(prv_key.n.to_bytes(mod_size, "little", signed=False))
	p = bswap64(prv_key.p.to_bytes(param_size, "little", signed=False))
	q = bswap64(prv_key.q.to_bytes(param_size, "little", signed=False))
	dp = bswap64((prv_key.d % (prv_key.p - 1)).to_bytes(param_size, "little", signed=False))
	dq = bswap64((prv_key.d % (prv_key.q - 1)).to_bytes(param_size, "little", signed=False))
	u = bswap64(modinv(prv_key.q, prv_key.p).to_bytes(param_size, "little", signed=False))

	mod_inv = XeCryptBnQwNeModInv(int.from_bytes(n[:8], "big"))
	mod_inv &= UINT64_MASK

	if cbits == 1024:
		b_prv_key = pack(">2IQ 128s 64s 64s 64s 64s 64s", cqw, dwPubExp, mod_inv, n, p, q, dp, dq, u)
		return (b_prv_key[:XECRYPT_RSAPUB_1024_SIZE], b_prv_key)
	elif cbits == 1536:
		b_prv_key = pack(">2IQ 192s 96s 96s 96s 96s 96s", cqw, dwPubExp, mod_inv, n, p, q, dp, dq, u)
		return (b_prv_key[:XECRYPT_RSAPUB_1536_SIZE], b_prv_key)
	elif cbits == 2048:
		b_prv_key = pack(">2IQ 256s 128s 128s 128s 128s 128s", cqw, dwPubExp, mod_inv, n, p, q, dp, dq, u)
		return (b_prv_key[:XECRYPT_RSAPUB_2048_SIZE], b_prv_key)
	elif cbits == 4096:
		b_prv_key = pack(">2IQ 512s 256s 256s 256s 256s 256s", cqw, dwPubExp, mod_inv, n, p, q, dp, dq, u)
		return (b_prv_key[:XECRYPT_RSAPUB_4096_SIZE], b_prv_key)

def XeCryptBnQwBeSigFormat(sig: Union[bytes, bytearray], b_hash: Union[bytes, bytearray], salt: Union[bytes, bytearray]) -> bytes:
	if type(sig) == bytes:
		sig = bytearray(sig)

	ab_hash = SHA1.new((b"\x00" * 8) + b_hash + salt).digest()
	pack_into("<B", sig, 0xE0, 1)
	pack_into("<10s", sig, 0xE1, salt)
	pack_into("<235s", sig, 0, XeCryptRc4Ecb(ab_hash, sig[:0xEB]))
	pack_into("<20s", sig, 0xEB, ab_hash)
	pack_into("<B", sig, 0xFF, 0xBC)
	sig[0] &= 0x7F
	return BnQwBeBufSwap(sig, 0x100 // 8)

def XeCryptBnQwBeSigCreate(b_hash: Union[bytes, bytearray], salt: Union[bytes, bytearray], prv_key: Union[bytes, bytearray]) -> bytes:
	(cqw,) = unpack(">I", prv_key[:calcsize("I")])
	assert cqw in [0x10, 0x18, 0x20, 0x40], "Unsupported key size"

	mod_size = cqw * 8
	param_size = mod_size // 2
	(cqw, dwPubExp, qwReserved, aqwM, aqwP, aqwQ, aqwDP, aqwDQ, aqwCR) = unpack(f">2IQ {mod_size}s {param_size}s {param_size}s {param_size}s {param_size}s {param_size}s", prv_key)

	if cqw == 0x20:  # PXECRYPT_RSAPRV_2048
		if dwPubExp == 0x3 or dwPubExp == 0x10001:
			sig = XeCryptBnQwBeSigFormat((b"\x00" * (cqw * 8)), b_hash, salt)
			if sig != aqwM:
				aqwM = int.from_bytes(bswap64(aqwM), "little", signed=False)

				x = int.from_bytes(bswap64(sig), "little", signed=False)
				r = pow(2, (((dwPubExp & 0xFFFFFFFF) - 1) << 11), aqwM)
				sig = (x * r) % aqwM  # move to Montgomery domain

				return bswap64(sig.to_bytes(cqw * 8, "little", signed=False))

def XeCryptBnQwBeSigVerify(sig: Union[bytes, bytearray], b_hash: Union[bytes, bytearray], salt: Union[bytes, bytearray], pub_key: Union[bytes, bytearray]) -> bool:
	(cqw,) = unpack(">I", pub_key[:calcsize("I")])
	assert cqw in [0x10, 0x18, 0x20, 0x40], "Unsupported key size"

	mod_size = cqw * 8
	(cqw, dwPubExp, qwReserved, aqwM) = unpack(f">2IQ {mod_size}s", pub_key)

	if qwReserved != 0:
		mod_inv = qwReserved
	else:
		mod_inv = XeCryptBnQwNeModInv(int.from_bytes(aqwM[:8], "big"))
		mod_inv &= UINT64_MASK

	sig_dec = sig
	sig_com = sig_dec

	exp = dwPubExp >> 1
	while exp > 0:
		sig_com = XeCryptBnQwNeModMul(sig_com, sig_com, mod_inv, aqwM, cqw)
		exp >>= 1
	sig_dec = XeCryptBnQwNeModMul(sig_com, sig_dec, mod_inv, aqwM, cqw)

	sig_dec = BnQwBeBufSwap(sig_dec, cqw)

	if sig_dec[0xFF] != 0xBC:
		return False

	if SHA1.new((b"\x00" * 8) + b_hash + salt).digest() != sig_dec[0xEB:-1]:
		return False

	sig_dec = XeCryptRc4Ecb(sig_dec[0xEB:-1], sig_dec[:0xEB])

	if sig_dec[0xE0] != 1:
		return False

	if not all([x == 0 for x in sig_dec[1:0xE0]]):
		return False

	if sig_dec[0xE1:0xE1 + len(salt)] != salt:
		return False

	return True

def XeCryptBnDwLePkcs1Format(b_hash: Union[bytes, bytearray], fmt_type: int, sig: Union[bytes, bytearray], cb_sig: int) -> Union[bytes, None]:
	if cb_sig < 0x27 or cb_sig > 0x200:
		return

	# sig = bytearray(0x200)
	pack_into(f"<{cb_sig}s", sig, 0, (b"\xFF" * cb_sig))
	sig[cb_sig - 1] = 0
	sig[cb_sig - 2] = 1
	pack_into("<20s", sig, 0, b_hash[::-1])
	if fmt_type == 0:
		tbuf = bytes.fromhex("140400051A02030E2B05060930213000")
		pack_into(f"<{len(tbuf)}s", sig, 0x14, tbuf)
	elif fmt_type == 1:
		tbuf = bytes.fromhex("14041A02030E2B050607301F3000")
		pack_into(f"<{len(tbuf)}s", sig, 0x14, tbuf)
	else:
		sig[0x14] = 0
	return sig

def XeCryptBnDwLePkcs1Verify(sig: Union[bytes, bytearray], b_hash: Union[bytes, bytearray], cb_sig: int) -> bool:
	if len(sig) >= 0x27 and len(sig) <= 0x200:
		buf = bytearray(0x200)
		typ = 2
		if sig[0x16] == 0:
			typ = 0
		elif sig[0x16] == 0x1A:
			typ = 1
		buf = XeCryptBnDwLePkcs1Format(b_hash, typ, buf, cb_sig)
		return memcmp(buf, sig, cb_sig)

def XeKeysPkcs1Create(b_hash: Union[bytes, bytearray], prv_key: Union[bytes, bytearray]) -> Union[bytes, None]:
	(cqw,) = unpack(">I", prv_key[:calcsize("I")])
	assert cqw in [0x10, 0x18, 0x20, 0x40], "Unsupported key size"

	mod_size = cqw * 8
	param_size = mod_size // 2
	(cqw, dwPubExp, qwReserved, aqwM, aqwP, aqwQ, aqwDP, aqwDQ, aqwCR) = unpack(f">2IQ {mod_size}s {param_size}s {param_size}s {param_size}s {param_size}s {param_size}s", prv_key)

	sig = bytearray(mod_size)
	if cqw != 0 and cqw <= 0x40:
		buf = bytearray(0x200)
		typ = 2
		if sig[0x16] == 0:
			typ = 0
		elif sig[0x16] == 0x1A:
			typ = 1
		buf = XeCryptBnDwLePkcs1Format(b_hash, typ, buf, cqw << 3)
		buf = XeCryptBnQw_SwapDwQwLeBe(buf)
		buf = XeCryptBnQwNeRsaPrvCrypt(buf, prv_key)
		return XeCryptBnQw_SwapDwQwLeBe(buf)

def XeKeysPkcs1Verify(sig: Union[bytes, bytearray], b_hash: Union[bytes, bytearray], pub_key: Union[bytes, bytearray]) -> bool:
	(cqw,) = unpack_from(">I", pub_key, 0)
	assert cqw in [0x10, 0x18, 0x20, 0x40], "Unsupported key size"

	mod_size = cqw * 8
	(cqw, dwPubExp, qwReserved, aqwM) = unpack_from(f">2IQ {mod_size}s", pub_key, 0)

	if cqw != 0 and cqw <= 0x40:
		buf = bytearray(0x200)
		pack_into(f"<{len(sig)}s", buf, 0, XeCryptBnQw_SwapDwQwLeBe(sig))
		buf = XeCryptBnQwNeRsaPubCrypt(buf, pub_key)
		buf = XeCryptBnQw_SwapDwQwLeBe(buf)
		return XeCryptBnDwLePkcs1Verify(buf, b_hash, cqw << 3)

	return False

def XeCryptBnQwNeRsaPrvCrypt(data: Union[bytes, bytearray], prv_key: Union[bytes, bytearray]) -> Union[bytes, bool]:
	(cqw,) = unpack(">I", prv_key[:calcsize("I")])
	assert cqw in [0x10, 0x18, 0x20, 0x40], "Unsupported key size"

	mod_size = cqw * 8
	param_size = mod_size // 2
	(cqw, dwPubExp, qwReserved, aqwM, aqwP, aqwQ, aqwDP, aqwDQ, aqwCR) = unpack(f">2IQ {mod_size}s {param_size}s {param_size}s {param_size}s {param_size}s {param_size}s", prv_key)

	aqwP = int.from_bytes(bswap64(aqwP), "little")
	aqwQ = int.from_bytes(bswap64(aqwQ), "little")
	aqwDP = int.from_bytes(bswap64(aqwDP), "little")
	aqwDQ = int.from_bytes(bswap64(aqwDQ), "little")
	aqwCR = int.from_bytes(bswap64(aqwCR), "little")

	data = int.from_bytes(bswap64(data), "little")

	return bswap64(XeCryptBnQwNeModExpRoot(data, aqwP, aqwQ, aqwDP, aqwDQ, aqwCR).to_bytes(cqw * 8, "little", signed=False))

def XeCryptBnQwNeRsaPubCrypt(data: Union[bytes, bytearray], pub_key: Union[bytes, bytearray]) -> Union[bytes, bool]:
	(cqw,) = unpack(">I", pub_key[:calcsize("I")])
	assert cqw in [0x10, 0x18, 0x20, 0x40], "Unsupported key size"

	mod_size = cqw * 8
	(cqw, dwPubExp, qwReserved, aqwM) = unpack(f">2IQ {mod_size}s", pub_key)

	aqwM = int.from_bytes(bswap64(aqwM), "little")
	data = int.from_bytes(bswap64(data), "little")
	data = pow(data, dwPubExp & 0xFFFFFFFF, aqwM)

	return bswap64(data.to_bytes(cqw * 8, "little", signed=False))

# Utility
def XeCryptSmcDecrypt(data: Union[bytes, bytearray]) -> Union[bytes, bytearray]:
	res = b""
	key = list(XECRYPT_SMC_KEY)
	for i in range(0, len(data)):
		j = data[i]
		mod = j * 0xFB
		res += bytes([j ^ (key[i & 3] & 0xFF)])
		key[(i + 1) & 3] += mod
		key[(i + 2) & 3] += mod >> 8
	return res

def XeCryptSmcEncrypt(data: Union[bytes, bytearray]) -> Union[bytes, bytearray]:
	res = b""
	key = list(XECRYPT_SMC_KEY)
	for i in range(0, len(data)):
		j = data[i] ^ (key[i & 3] & 0xFF)
		mod = j * 0xFB
		res += bytes([j])
		key[(i + 1) & 3] += mod
		key[(i + 2) & 3] += mod >> 8
	return res

def XeCryptHammingWeight(data: Union[bytes, bytearray]) -> int:
	wght = 0
	for i in range(len(data)):
		val = data[i]
		for j in range(8):
			wght += val & 1
			val >>= 1
	return wght

def XeCryptUidEccEncode(data: Union[bytes, bytearray]) -> bytes:
	data = bytearray(data)
	acc1 = 0
	acc2 = 0
	for cnt in range(0x80):
		acc1 >>= 1
		b_tmp = data[cnt >> 3]
		dw_tmp = (b_tmp >> (cnt & 7)) & 1
		if cnt < 0x6A:
			acc1 ^= dw_tmp
			if acc1 & 1:
				acc1 ^= 0x360325
			acc2 ^= dw_tmp
		elif cnt < 0x7F:
			if dw_tmp != (acc1 & 1):
				data[cnt >> 3] = ((1 << (cnt & 7)) ^ (b_tmp & 0xFF))
			acc2 ^= (acc1 & 1)
		elif dw_tmp != acc2:
			data[0xF] = (0x80 ^ b_tmp) & 0xFF
	return data

# additions to the XeCrypt library that didn't exist in the original
def XeCryptCpuKeyValid(cpu_key: Union[bytes, bytearray]) -> bool:
	wght_mask = bytes.fromhex("FFFFFFFFFFFFFFFFFFFFFFFFFF030000")
	key_tmp = bytearray(0x10)
	for i in range(0x10):
		key_tmp[i] = cpu_key[i] & wght_mask[i]
	wght = XeCryptHammingWeight(key_tmp)
	key_tmp = XeCryptUidEccEncode(key_tmp)
	ecc_good = (cpu_key == key_tmp)
	wght_good = (wght == 0x35)
	return ecc_good and wght_good

def XeCryptCpuKeyGen() -> Union[bytes, bytearray]:
	key = bytearray(0x10)
	for dw_unset_count in range(0x35):
		dw_rand = int.from_bytes(urandom(4), "little") % ((~dw_unset_count) + 0x6A + 1)
		bit_pos = 0
		for bit_pos in range(0x6A):
			if ((key[(bit_pos >> 3) & 0x1F] >> (bit_pos & 0x7)) & 1) == 0:
				if dw_rand == 0:
					break
				dw_rand -= 1
		if bit_pos == 0x6A or dw_rand:
			print("Error, dw_rand: %X" % (dw_rand))
		key[(bit_pos >> 3) & 0x1F] = (1 << (bit_pos & 0x7)) ^ key[(bit_pos >> 3) & 0x1F]
	return XeCryptUidEccEncode(key)

def XeCryptKeyVaultDecrypt(cpu_key: Union[bytes, bytearray], data: Union[bytes, bytearray]) -> bytes:
	assert XeCryptCpuKeyValid(cpu_key), "Invalid CPU key"
	version = bytes([0x7, 0x12])
	kv_hash = XeCryptHmacSha(cpu_key, data[:0x10])[:0x10]
	XeCryptRc4EcbKey(kv_hash)
	data = data[:0x10] + XeCryptRc4(data[0x10:])
	kv_hash = XeCryptHmacSha(cpu_key, data[0x10:], version)[:0x10]
	assert data[:0x10] == kv_hash, "Invalid KV digest"
	return data

def XeCryptKeyVaultEncrypt(cpu_key: Union[bytes, bytearray], data: Union[bytes, bytearray]) -> bytes:
	if type(data) == bytes:
		data = bytearray(data)

	assert XeCryptCpuKeyValid(cpu_key), "Invalid CPU key"
	version = bytes([0x7, 0x12])
	# random nonce
	pack_into("8s", data, 0, XeCryptRandom(0x10))
	# random obfuscation key
	pack_into("8s", data, 0x10, XeCryptRandom(8))
	pack_into("16s", data, 0, XeCryptHmacSha(cpu_key, data[0x10:], version)[:0x10])
	rc4_key = XeCryptHmacSha(cpu_key, data[:0x10])[:0x10]
	XeCryptRc4EcbKey(rc4_key)
	return bytes(data[:0x10]) + XeCryptRc4(data[0x10:])

def XeCryptKeyVaultVerify(cpu_key: Union[bytes, bytearray], data: Union[bytes, bytearray], pub_key: Union[bytes, bytearray]) -> bool:
	assert XeCryptCpuKeyValid(cpu_key), "Invalid CPU key"
	kv_data = data[0x18:]
	kv_hash = XeCryptHmacSha(cpu_key, kv_data[4:4 + 0xD4], kv_data[0xE8:0xE8 + 0x1CF8], kv_data[0x1EE0:0x1EE0 + 0x2108])
	return XeKeysPkcs1Verify(kv_data[0x1DE0:0x1DE0 + 0x100], kv_hash, pub_key)

def XeCryptPageEccEncode(data: Union[bytes, bytearray]) -> bytes:
	if type(data) == bytes:
		data = bytearray(data)

	v1 = 0
	for bit in range(0x1066):
		v2 = v1 ^ (((1 << bit % 8) & data[bit // 8]) == 0)
		if v2 & 1:
			v2 ^= 0x6954559
		v1 = v2 >> 1
	for bit in range(0x1066, 0x1080):
		if v1 & 1:
			data[bit // 8] &= ~(1 << bit % 8)
		else:
			data[bit // 8] |= 1 << bit % 8
		v1 >>= 1
	return bytes(data)

def calc_page_ecc(data: Union[bytes, bytearray], spare: Union[bytes, bytearray]) -> int:
	if type(data) == bytes:
		data = bytearray(data)

	val = 0
	v = 0
	idx = 0
	for bit in range(0x1066):
		if not (bit & 31):
			if bit == 0x1000:
				data = spare
				idx = 0
			(v,) = unpack_from("<I", data, idx)
			v = ~v
			idx += 4
		val ^= v & 1
		v >>= 1
		if val & 1:
			val ^= 0x6954559
		val >>= 1
	return ~val & 0xFFFFFFFF

def fix_page_ecc(data: Union[bytes, bytearray], spare: Union[bytes, bytearray]) -> Tuple[bytes, bytes]:
	if type(spare) == bytes:
		spare = bytearray(spare)

	val = calc_page_ecc(data, spare)
	spare[12] = (spare[12] & 0x3F) + ((val << 6) & 0xC0)
	spare[13] = (val >> 2) & 0xFF
	spare[14] = (val >> 10) & 0xFF
	spare[15] = (val >> 18) & 0xFF
	return (data, spare)

def check_page_ecc(data: Union[bytes, bytearray], spare: Union[bytes, bytearray]) -> bool:
	val = calc_page_ecc(data, spare)
	if spare[12] & 0xC0 == ((val << 6) & 0xC0) and \
		spare[13] & 0xFF == ((val >> 2) & 0xFF) and \
		spare[14] & 0xFF == ((val >> 10) & 0xFF) and \
		spare[15] & 0xFF == ((val >> 18) & 0xFF):
		return True
	return False

__all__ = [
	# constants
	"XECRYPT_1BL_KEY",
	"XECRYPT_1BL_SALT",
	"XECRYPT_AES_BLOCK_SIZE",
	"XECRYPT_AES_FEED_SIZE",
	"XECRYPT_AES_KEY_SIZE",
	"XECRYPT_DES3_BLOCK_SIZE",
	"XECRYPT_DES3_KEY_SIZE",
	"XECRYPT_DES_BLOCK_SIZE",
	"XECRYPT_DES_KEY_SIZE",
	"XECRYPT_HMAC_SHA_MAX_KEY_SIZE",
	"XECRYPT_MD5_DIGEST_SIZE",
	"XECRYPT_ROTSUM_DIGEST_SIZE",
	"XECRYPT_RSAPRV_1024_SIZE",
	"XECRYPT_RSAPRV_1536_SIZE",
	"XECRYPT_RSAPRV_2048_SIZE",
	"XECRYPT_RSAPUB_1024_SIZE",
	"XECRYPT_RSAPUB_1536_SIZE",
	"XECRYPT_RSAPUB_2048_SIZE",
	"XECRYPT_SC_SALT",
	"XECRYPT_SD_SALT",
	"XECRYPT_SHA_DIGEST_SIZE",
	"XECRYPT_SMC_KEY",

	# structures
	"NAND_HEADER",
	"BL_HEADER",
	"SB_2BL_HEADER",
	"SC_3BL_HEADER",
	"SD_4BL_HEADER",
	"SE_5BL_HEADER",
	"HV_HEADER",
	"SMALLBLOCK",
	"BIGONSMALL",
	"BIGBLOCK",
	
	"XECRYPT_RSA",
	"XECRYPT_RSAPUB_1024",
	"XECRYPT_RSAPUB_1536",
	"XECRYPT_RSAPUB_2048",
	"XECRYPT_RSAPUB_4096",
	"XECRYPT_RSAPRV_1024",
	"XECRYPT_RSAPRV_1536",
	"XECRYPT_RSAPRV_2048",
	"XECRYPT_RSAPRV_4096",
	"XECRYPT_SIG",

	# enums
	"BLMagic",

	# functions
	"XeCryptAes",
	"XeCryptAesCbc",
	"XeCryptAesCbcKey",
	"XeCryptAesEcb",
	"XeCryptAesEcbKey",
	"XeCryptBnDwLePkcs1Format",
	"XeCryptBnDwLePkcs1Verify",
	"XeCryptBnQwBeSigCreate",
	"XeCryptBnQwBeSigFormat",
	"XeCryptBnQwBeSigVerify",
	"XeCryptBnQwNeModInv",
	"XeCryptBnQwNeModMul",
	"XeCryptBnQwNeRsaKeyGen",
	"XeCryptBnQwNeRsaKeyToRsaProv",
	"XeCryptBnQwNeRsaPrvCrypt",
	"XeCryptBnQwNeRsaPubCrypt",
	"XeCryptCpuKeyGen",
	"XeCryptCpuKeyValid",
	"XeCryptDes",
	"XeCryptDes3",
	"XeCryptDes3Cbc",
	"XeCryptDes3CbcKey",
	"XeCryptDes3Ecb",
	"XeCryptDes3EcbKey",
	"XeCryptDesCbc",
	"XeCryptDesCbcKey",
	"XeCryptDesEcb",
	"XeCryptDesEcbKey",
	"XeCryptHammingWeight",
	"XeCryptHmacMd5",
	"XeCryptHmacSha",
	"XeCryptKeyVaultDecrypt",
	"XeCryptKeyVaultEncrypt",
	"XeCryptKeyVaultVerify",
	"XeCryptMd5",
	"XeCryptMulHdu",
	"XeCryptPageEccEncode",
	"XeCryptRandom",
	"XeCryptRc4",
	"XeCryptRc4Ecb",
	"XeCryptRc4EcbKey",
	"XeCryptRotSum",
	"XeCryptRotSumSha",
	"XeCryptSha",
	"XeCryptSmcDecrypt",
	"XeCryptSmcEncrypt",
	"XeCryptUidEccEncode",
	"XeKeysPkcs1Create",
	"XeKeysPkcs1Verify"
]
__all__.extend([
	"read_file",
	"write_file",
	"reverse",
	"bswap16",
	"bswap32",
	"bswap64",
	"print_c_array",
	"XeCryptBnQw_SwapDwQwLeBe",
	"XeCryptPrintRsa"
])

__all__.extend([
	"calc_page_ecc",
	"fix_page_ecc",
	"check_page_ecc"
])