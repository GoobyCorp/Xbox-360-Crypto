#!/usr/bin/env python3

"""
Gigantic shout out to cOz for all the help in porting this, without him this wouldn't have been possible!
"""

__author__ = "Visual Studio"
__maintainer__ = "Visual Studio"
__credits__ = ["Visual Studio", "cOz", "TEIR1plus2", "ED9"]
__version__ = "1.0.0.0"
__license__ = "BSD"
__status__ = "Development"

from math import gcd
from os import urandom
from array import array
from enum import IntEnum
from pathlib import Path
from io import BytesIO, StringIO
from typing import Union, Tuple, Optional
from struct import pack, unpack, pack_into, unpack_from, calcsize
from ctypes import BigEndianStructure, sizeof, c_ubyte, c_uint16, c_uint32, c_uint64

# pip install pycryptodome
from Crypto.PublicKey import RSA
from Crypto.Hash import MD5, SHA1, HMAC
from Crypto.Cipher import ARC4, DES, DES3, AES

# globals
# constants
XECRYPT_SMC_KEY  = bytes.fromhex("42754E79")
XECRYPT_1BL_KEY  = bytes.fromhex("DD88AD0C9ED669E7B56794FB68563EFA")
XECRYPT_1BL_SALT = b"XBOX_ROM_B"
XECRYPT_SC_SALT  = b"XBOX_ROM_3"
XECRYPT_SD_SALT  = b"XBOX_ROM_4"
BUFFER_SIZE      = 4096

UINT8_MASK   = int.from_bytes(b"\xFF", "little")
UINT16_MASK  = int.from_bytes(b"\xFF" * 2, "little")
UINT32_MASK  = int.from_bytes(b"\xFF" * 4, "little")
UINT64_MASK  = int.from_bytes(b"\xFF" * 8, "little")
UINT128_MASK = int.from_bytes(b"\xFF" * 16, "little")

# public key sizes
XECRYPT_RSAPUB_1024_SIZE = 0x90
XECRYPT_RSAPUB_1536_SIZE = 0xD0
XECRYPT_RSAPUB_2048_SIZE = 0x110
XECRYPT_RSAPUB_4096_SIZE = 0x210

# private key sizes
XECRYPT_RSAPRV_1024_SIZE = 0x1D0
XECRYPT_RSAPRV_1536_SIZE = 0x2B0
XECRYPT_RSAPRV_2048_SIZE = 0x390
XECRYPT_RSAPRV_4096_SIZE = 0x710

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
		("aqwPad", (QWORD * 0x1C)),
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
	_anonymous_ = ["rsa"]
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
	_anonymous_ = ["rsa"]
	_fields_ = [
		("rsa", XECRYPT_RSA),
		("n", (BYTE * 256))
	]

class XECRYPT_RSAPUB_4096(BigEndianStructure):
	_anonymous_ = ["rsa"]
	_fields_ = [
		("rsa", XECRYPT_RSA),
		("n", (BYTE * 512))
	]

class XECRYPT_RSAPRV_1024(BigEndianStructure):
	_anonymous_ = ["rsa"]
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
	_anonymous_ = ["rsa"]
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
	_anonymous_ = ["rsa"]
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
	_anonymous_ = ["rsa"]
	_fields_ = [
		("rsa", XECRYPT_RSA),
		("n", (BYTE * 512)),
		("p", (BYTE * 256)),
		("q", (BYTE * 256)),
		("dp", (BYTE * 256)),
		("dq", (BYTE * 256)),
		("cr", (BYTE * 256)),
	]

# utilities
def read_file(filename: str, text: bool = False) -> Union[bytes, str]:
	p = Path(filename)
	if text:
		return p.read_text()
	else:
		return p.read_bytes()

def write_file(filename: str, data: Union[str, bytes, bytearray]) -> None:
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
class XeCryptRc4:
	# only works in ECB mode!

	def __init__(self, key: Union[bytes, bytearray]):
		self.reset()
		self._cipher = ARC4.new(key)

	def reset(self) -> None:
		self._cipher = None

	@staticmethod
	def new(key: Union[bytes, bytearray]):
		return XeCryptRc4(key)

	# encrypt and decrypt are exactly the same for RC4
	def crypt(self, data: Union[bytes, bytearray]) -> bytes:
		return self._cipher.encrypt(data)

	def encrypt(self, data: Union[bytes, bytearray]) -> bytes:
		return self.crypt(data)

	def decrypt(self, data: Union[bytes, bytearray]) -> bytes:
		return self.crypt(data)

# DES
class XeCryptDes:
	MODE_ECB = 1
	MODE_CBC = 2

	def __init__(self, key: Union[bytes, bytearray], mode: Optional[int] = MODE_ECB, iv: Optional[Union[bytes, bytearray]] = None):
		self.reset()
		if mode == self.MODE_ECB:
			self._cipher = DES.new(key, mode)
		elif mode == self.MODE_CBC:
			assert iv is not None, "IV is required for the CBC cipher mode"
			self._cipher = DES.new(key, mode, iv)
		else:
			raise Exception("Invalid cipher mode entered")

	def reset(self) -> None:
		self._cipher = None

	@staticmethod
	def new(key: Union[bytes, bytearray], mode: Optional[int] = MODE_ECB, iv: Optional[Union[bytes, bytearray]] = None):
		return XeCryptDes(key, mode, iv)

	def encrypt(self, data: Union[bytes, bytearray]) -> bytes:
		return self._cipher.encrypt(data)

	def decrypt(self, data: Union[bytes, bytearray]) -> bytes:
		return self._cipher.decrypt(data)

# DES 3
class XeCryptDes3:
	MODE_ECB = 1
	MODE_CBC = 2

	def __init__(self, key: Union[bytes, bytearray], mode: Optional[int] = MODE_ECB, iv: Optional[Union[bytes, bytearray]] = None):
		self.reset()
		if mode == self.MODE_ECB:
			self._cipher = DES3.new(key, mode)
		elif mode == self.MODE_CBC:
			assert iv is not None, "IV is required for the CBC cipher mode"
			self._cipher = DES3.new(key, mode, iv)
		else:
			raise Exception("Invalid cipher mode entered")

	def reset(self) -> None:
		self._cipher = None

	@staticmethod
	def new(key: Union[bytes, bytearray], mode: Optional[int] = MODE_ECB, iv: Optional[Union[bytes, bytearray]] = None):
		return XeCryptDes3(key, mode, iv)

	def encrypt(self, data: Union[bytes, bytearray]) -> bytes:
		return self._cipher.encrypt(data)

	def decrypt(self, data: Union[bytes, bytearray]) -> bytes:
		return self._cipher.decrypt(data)

# AES
class XeCryptAes:
	MODE_ECB = 1
	MODE_CBC = 2

	def __init__(self, key: Union[bytes, bytearray], mode: Optional[int] = MODE_ECB, iv: Optional[Union[bytes, bytearray]] = None):
		self.reset()
		if mode == self.MODE_ECB:
			self._cipher = AES.new(key, mode)
		elif mode == self.MODE_CBC:
			assert iv is not None, "IV is required for the CBC cipher mode"
			self._cipher = AES.new(key, mode, iv)
		else:
			raise Exception("Invalid cipher mode entered")

	def reset(self) -> None:
		self._cipher = None

	@staticmethod
	def new(key: Union[bytes, bytearray], mode: int = MODE_ECB, iv: Union[bytes, bytearray] = None):
		return XeCryptAes(key, mode, iv)

	def encrypt(self, data: Union[bytes, bytearray]) -> bytes:
		return self._cipher.encrypt(data)

	def decrypt(self, data: Union[bytes, bytearray]) -> bytes:
		return self._cipher.decrypt(data)

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
		mmi &= UINT64_MASK

		acc1 = 0
		for j in range(cqw):
			(hi_val, lo_val) = XeCryptMulHdu(b_arr[i], a_arr[j])
			lo_val += acc_arr_1[j + 1]
			lo_val &= UINT64_MASK
			hi_val += (lo_val < acc_arr_1[j + 1])
			lo_val += acc1
			lo_val &= UINT64_MASK
			hi_val += (lo_val < acc1)
			acc1 = hi_val
			lo_val &= UINT64_MASK
			acc_arr_1[j] = lo_val
		acc_arr_1[cqw] = acc1

		acc2 = 0
		for j in range(cqw):
			(hi_val, lo_val) = XeCryptMulHdu(mmi, m_arr[j])
			lo_val += acc_arr_2[j + 1]
			lo_val &= UINT64_MASK
			hi_val += (lo_val < acc_arr_2[j + 1])
			lo_val += acc2
			lo_val &= UINT64_MASK
			hi_val += (lo_val < acc2)
			acc2 = hi_val
			lo_val &= UINT64_MASK
			acc_arr_2[j] = lo_val
		acc_arr_2[cqw] = acc2
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

def XeCryptBnQwNeRsaKeyGen(cbits: int = 2048, dwPubExp: int = 0x10001) -> Tuple[bytes, bytes]:
	prv_key = RSA.generate(cbits, e=dwPubExp)
	mod_size = prv_key.n_size_in_bytes
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
	pack_into("<235s", sig, 0, XeCryptRc4.new(ab_hash).encrypt(sig[:0xEB]))
	pack_into("<20s", sig, 0xEB, ab_hash)
	pack_into("<B", sig, 0xFF, 0xBC)
	sig[0] &= 0x7F
	return BnQwBeBufSwap(sig, 0x100 // 8)

def XeCryptBnQwBeSigCreate(b_hash: Union[bytes, bytearray], salt: Union[bytes, bytearray], prv_key: Union[bytes, bytearray]) -> Union[bytes, None]:
	key = PY_XECRYPT_RSA_KEY(prv_key)
	if key.cqw != 0x20:  # PXECRYPT_RSAPRV_2048
		return None

	if key.e not in [0x3, 0x10001]:
		return None

	sig = XeCryptBnQwBeSigFormat((b"\x00" * (key.cqw * 8)), b_hash, salt)
	if sig == bytes(key.key_struct.n):
		return None

	x = int.from_bytes(bswap64(sig), "little", signed=False)
	r = pow(2, (((key.e & 0xFFFFFFFF) - 1) << 11), key.n)
	sig = (x * r) % key.n  # move to Montgomery domain
	return bswap64(sig.to_bytes(key.cqw * 8, "little", signed=False))

def XeCryptBnQwBeSigVerify(sig: Union[bytes, bytearray], b_hash: Union[bytes, bytearray], salt: Union[bytes, bytearray], pub_key: Union[bytes, bytearray]) -> bool:
	key = PY_XECRYPT_RSA_KEY(pub_key)

	if key.cqw != 0x20:  # PXECRYPT_RSAPRV_2048
		return False

	mod_inv = key.mod_inv

	sig_dec = sig
	sig_com = sig_dec

	exp = key.e >> 1
	while exp > 0:
		sig_com = XeCryptBnQwNeModMul(sig_com, sig_com, mod_inv, bytes(key.key_struct.n), key.cqw)
		exp >>= 1
	sig_dec = XeCryptBnQwNeModMul(sig_com, sig_dec, mod_inv, bytes(key.key_struct.n), key.cqw)

	sig_dec = BnQwBeBufSwap(sig_dec, key.cqw)

	if sig_dec[0xFF] != 0xBC:
		return False

	if SHA1.new((b"\x00" * 8) + b_hash + salt).digest() != sig_dec[0xEB:-1]:
		return False

	sig_dec = XeCryptRc4.new(sig_dec[0xEB:-1]).decrypt(sig_dec[:0xEB])

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
	key = PY_XECRYPT_RSA_KEY(prv_key)
	sig = bytearray(key.n_size_in_bytes)
	if key.cqw != 0 and key.cqw <= 0x40:
		buf = bytearray(0x200)
		typ = 2
		if sig[0x16] == 0:
			typ = 0
		elif sig[0x16] == 0x1A:
			typ = 1
		buf = XeCryptBnDwLePkcs1Format(b_hash, typ, buf, key.cqw << 3)
		buf = XeCryptBnQw_SwapDwQwLeBe(buf)
		buf = XeCryptBnQwNeRsaPrvCrypt(buf, prv_key)
		return XeCryptBnQw_SwapDwQwLeBe(buf)

def XeKeysPkcs1Verify(sig: Union[bytes, bytearray], b_hash: Union[bytes, bytearray], pub_key: Union[bytes, bytearray]) -> bool:
	key = PY_XECRYPT_RSA_KEY(pub_key)
	if key.cqw != 0 and key.cqw <= 0x40:
		buf = bytearray(0x200)
		pack_into(f"<{len(sig)}s", buf, 0, XeCryptBnQw_SwapDwQwLeBe(sig))
		buf = XeCryptBnQwNeRsaPubCrypt(buf, pub_key)
		buf = XeCryptBnQw_SwapDwQwLeBe(buf)
		return XeCryptBnDwLePkcs1Verify(buf, b_hash, key.cqw << 3)

	return False

def XeCryptBnQwNeRsaPrvCrypt(data: Union[bytes, bytearray], prv_key: Union[bytes, bytearray]) -> Union[bytes, bool]:
	key = PY_XECRYPT_RSA_KEY(prv_key)
	data = int.from_bytes(bswap64(data), "little")
	return bswap64(XeCryptBnQwNeModExpRoot(data, key.p, key.q, key.dp, key.dq, key.u).to_bytes(key.cqw * 8, "little", signed=False))

def XeCryptBnQwNeRsaPubCrypt(data: Union[bytes, bytearray], pub_key: Union[bytes, bytearray]) -> Union[bytes, bool]:
	key = PY_XECRYPT_RSA_KEY(pub_key)
	data = int.from_bytes(bswap64(data), "little")
	data = pow(data, key.e & 0xFFFFFFFF, key.n)
	return bswap64(data.to_bytes(key.cqw * 8, "little", signed=False))

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
	data = data[:0x10] + XeCryptRc4.new(kv_hash).decrypt(data[0x10:])
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
	return bytes(data[:0x10]) + XeCryptRc4.new(rc4_key).encrypt(data[0x10:])

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

# helper classes
class BLHeader:
	include_nonce = True

	magic = None
	build = None
	qfe = None
	flags = None
	entry_point = None
	size = None

	nonce = None

	def __init__(self, data: Union[bytes, bytearray], include_nonce: bool = True):
		self.include_nonce = include_nonce
		self.reset()
		self.parse(data)

	def __bytes__(self) -> bytes:
		data = pack(">2s 3H 2I", self.magic, self.build, self.qfe, self.flags, self.entry_point, self.size)
		if self.include_nonce:
			data += self.nonce
		return data

	def __dict__(self) -> dict:
		dct = {"magic": self.magic, "build": self.build, "qfe": self.qfe, "flags": self.flags, "entry_point": self.entry_point, "size": self.size}
		if self.include_nonce:
			dct["nonce"] = self.nonce
		return dct

	def __getitem__(self, item: str) -> Union[bytes, int, bool]:
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
	def padding_size(self) -> int:
		return (16 - (self.size % 16)) % 16

	@property
	def requires_padding(self) -> bool:
		return self.padding_size > 0

	def parse(self, data: Union[bytes, bytearray]):
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

# managed public key "interfaces"
class PY_XECRYPT_RSA_KEY:
	key_bytes = None
	rsa_struct = None
	key_struct = None

	def __init__(self, data: Union[bytes, bytearray] = None):
		self.reset()

		self.key_bytes = data
		self.rsa_struct = XECRYPT_RSA.from_buffer_copy(data[:sizeof(XECRYPT_RSA)])
		try:
			self.key_struct = globals()[f"XECRYPT_RSA{'PRV' if self.is_private_key else 'PUB'}_{self.n_size_in_bits}"].from_buffer_copy(data)
		except KeyError as e:
			raise Exception("Invalid key data specified")

	def reset(self) -> None:
		self.key_bytes = None
		self.rsa_struct = None
		self.key_struct = None

	def __bytes__(self) -> bytes:
		return self.key_bytes

	def __len__(self) -> int:
		return len(self.key_bytes)

	def to_bytes(self) -> bytes:
		return self.key_bytes

	def to_pycrypto(self) -> RSA:
		if self.is_private_key:
			return RSA.construct((self.n, self.e, self.d, self.p, self.q, self.inv_q))
		else:
			return RSA.construct((self.n, self.e))

	to_pycryptodome = to_pycrypto

	@staticmethod
	def new(bits: int = 2048, exp: int = 0x10001):
		(pub_key, prv_key) = XeCryptBnQwNeRsaKeyGen(bits, exp)
		return PY_XECRYPT_RSA_KEY(prv_key)

	@property
	def public_key(self):
		try:
			return PY_XECRYPT_RSA_KEY(self.key_bytes[:globals()[f"XECRYPT_RSAPUB_{self.n_size_in_bits}_SIZE"]])
		except KeyError as e:
			raise Exception("Invalid key data specified")

	def c_struct(self):
		return self.key_struct

	@property
	def is_private_key(self) -> bool:
		return len(self.key_bytes) > (sizeof(XECRYPT_RSA) + self.n_size_in_bytes)

	@property
	def n_size_in_bytes(self) -> int:
		return self.cqw * 8

	@property
	def n_size_in_bits(self) -> int:
		return self.n_size_in_bytes * 8

	@property
	def cqw(self) -> int:
		return self.rsa_struct.cqw

	@property
	def mod_inv(self) -> int:
		v = self.key_struct.qwReserved
		if v == 0:
			v = XeCryptBnQwNeModInv(int.from_bytes(bytes(self.key_struct.n)[:8], "big"))
		v &= UINT64_MASK
		return v

	@property
	def n(self) -> int:
		return int.from_bytes(bswap64(bytes(self.key_struct.n)), "little", signed=False)

	@property
	def e(self) -> int:
		return self.key_struct.e

	@property
	def d(self) -> int:
		return rsa_calc_d(self.e, self.p, self.q)

	@property
	def p(self) -> int:
		return int.from_bytes(bswap64(bytes(self.key_struct.p)), "little", signed=False)

	@property
	def q(self) -> int:
		return int.from_bytes(bswap64(bytes(self.key_struct.q)), "little", signed=False)

	@property
	def dp(self) -> int:
		return int.from_bytes(bswap64(bytes(self.key_struct.dp)), "little", signed=False)

	@property
	def dq(self) -> int:
		return int.from_bytes(bswap64(bytes(self.key_struct.dq)), "little", signed=False)

	@property
	def u(self) -> int:
		return int.from_bytes(bswap64(bytes(self.key_struct.cr)), "little", signed=False)

	@property
	def inv_q(self) -> int:
		return modinv(self.p, self.q)

	def sig_create(self, hash: Union[bytes, bytearray], salt: Union[bytes, bytearray]) -> bytes:
		assert self.is_private_key, "Key isn't a private key!"
		sig = XeCryptBnQwBeSigCreate(hash, salt, self.key_bytes)
		return XeCryptBnQwNeRsaPrvCrypt(sig, self.key_bytes)

	def sig_verify(self, sig: Union[bytes, bytearray], hash: Union[bytes, bytearray], salt: Union[bytes, bytearray]) -> bool:
		pub_key = self.key_bytes[:(self.cqw * 8) + 0x10]
		return XeCryptBnQwBeSigVerify(sig, hash, salt, pub_key)

	def pkcs1_sig_create(self, hash: Union[bytes, bytearray]) -> bytes:
		assert self.is_private_key, "Key isn't a private key!"
		return XeKeysPkcs1Create(hash, self.key_bytes)

	def pkcs1_sig_verify(self, sig: Union[bytes, bytearray], hash: Union[bytes, bytearray]) -> bool:
		pub_key = self.key_bytes[:(self.cqw * 8) + 0x10]
		return XeKeysPkcs1Verify(sig, hash, pub_key)

# constants
__all__ = [
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
	"XECRYPT_SMC_KEY"
]

# structures
__all__.extend([
	"NAND_HEADER",
	"BL_HEADER",
	"SB_2BL_HEADER",
	"SC_3BL_HEADER",
	"SD_4BL_HEADER",
	"SE_5BL_HEADER",
	"HV_HEADER",
	# "SMALLBLOCK",
	# "BIGONSMALL",
	# "BIGBLOCK",
	
	"XECRYPT_RSA",
	"XECRYPT_RSAPUB_1024",
	"XECRYPT_RSAPUB_1536",
	"XECRYPT_RSAPUB_2048",
	"XECRYPT_RSAPUB_4096",
	"XECRYPT_RSAPRV_1024",
	"XECRYPT_RSAPRV_1536",
	"XECRYPT_RSAPRV_2048",
	"XECRYPT_RSAPRV_4096",
	"XECRYPT_SIG"
])

# helper classes
__all__.extend([
	"BLHeader"
])

# managed key class
__all__.extend([
	"PY_XECRYPT_RSA_KEY"
])

# enums
__all__.extend([
	"BLMagic"
])

# functions
__all__.extend([
	"XeCryptBnDwLePkcs1Format",
	"XeCryptBnDwLePkcs1Verify",
	"XeCryptBnQwBeSigCreate",
	"XeCryptBnQwBeSigFormat",
	"XeCryptBnQwBeSigVerify",
	"XeCryptBnQwNeModInv",
	"XeCryptBnQwNeModMul",
	"XeCryptBnQwNeRsaKeyGen",
	"XeCryptBnQwNeRsaPrvCrypt",
	"XeCryptBnQwNeRsaPubCrypt",
	"XeCryptCpuKeyGen",
	"XeCryptCpuKeyValid",
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
	"XeCryptDes",
	"XeCryptDes3",
	"XeCryptAes",
	"XeCryptRotSum",
	"XeCryptRotSumSha",
	"XeCryptSha",
	"XeCryptSmcDecrypt",
	"XeCryptSmcEncrypt",
	"XeCryptUidEccEncode",
	"XeKeysPkcs1Create",
	"XeKeysPkcs1Verify"
])

# utility functions
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
