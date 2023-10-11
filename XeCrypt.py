#!/usr/bin/env python3

"""
Gigantic shoutout to cOz for all the help in porting this, without him this wouldn't have been possible!
"""

__author__ = "Visual Studio"
__maintainer__ = "Visual Studio"
__credits__ = ["Visual Studio", "cOz", "TEIR1plus2", "ED9"]
__version__ = "1.0.0.0"
__license__ = "BSD"
__status__ = "Development"

from os import urandom
from pathlib import Path
from typing import Union, Tuple, Optional, TypeVar
from struct import pack, unpack, pack_into, unpack_from, calcsize
from ctypes import BigEndianStructure, sizeof, c_ubyte, c_uint16, c_uint32, c_uint64

# py -3 -m pip install cryptography
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.hashes import Hash
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.hashes import MD5, SHA1
from cryptography.hazmat.primitives.ciphers.modes import ECB, CBC
from cryptography.hazmat.primitives.ciphers.algorithms import ARC4, AES, TripleDES
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey, RSAPrivateKey, RSAPublicNumbers, RSAPrivateNumbers

BinLike = TypeVar("BinLike", bytes, bytearray, memoryview)

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

class XECRYPT_KEYVAULT(BigEndianStructure):
	_pack_ = 1
	_fields_ = [
		("nonce", BYTE * 0x10),
		("obfuscation", BYTE * 8),
		("manufacturing_mode", BYTE),
		("alternate_keyvault", BYTE),
		("restricted_privilege_flags", BYTE),
		("reserved_byte_3", BYTE),  # reserved
		("odd_features", WORD),
		("odd_auth_type", WORD),
		("restricted_hv_ext_loader", WORD),
		("reserved_ushort_1", WORD),  # reserved
		("policy_flash_size", DWORD),
		("policy_build_in_mu_size", DWORD),
		("reserved_dword_4", DWORD),  # reserved
		("restricted_privileges", QWORD),
		("reserved_qword_2", QWORD),  # reserved
		("reserved_qword_3", QWORD),  # reserved
		("reserved_qword_4", QWORD),  # reserved
		("reserved_key_1", BYTE * 0x10),  # reserved
		("reserved_key_2", BYTE * 0x10),  # reserved
		("reserved_key_3", BYTE * 0x10),  # reserved
		("reserved_key_4", BYTE * 0x10),  # reserved
		("reserved_random_key_1", BYTE * 0x10),  # reserved
		("reserved_random_key_2", BYTE * 0x10),  # reserved
		("console_serial", BYTE * 0xC),
		("PADDING1", BYTE * 4),  # padding
		("motherboard_serial", BYTE * 8),
		("game_region", WORD),
		("PADDING2", BYTE * 6),  # padding
		("console_obf_key", BYTE * 0x10),
		("key_obf_key", BYTE * 0x10),
		("roamable_obf_key", BYTE * 0x10),
		("odd_key", BYTE * 0x10),
		("primary_activation_key", BYTE * 0x18),
		("secondary_activation_key", BYTE * 0x10),

		# 2des
		("global_dev_2des_key_1", BYTE * 0x10),
		("global_dev_2des_key_2", BYTE * 0x10),

		("wireless_controller_2des_key_1", BYTE * 0x10),
		("wireless_controller_2des_key_2", BYTE * 0x10),

		("wired_webcam_2des_key_1", BYTE * 0x10),
		("wired_webcam_2des_key_2", BYTE * 0x10),

		("wired_controller_2des_key_1", BYTE * 0x10),
		("wired_controller_2des_key_2", BYTE * 0x10),

		("memory_unit_2des_key_1", BYTE * 0x10),
		("memory_unit_2des_key_2", BYTE * 0x10),

		("other_xsm3_dev_2des_key_1", BYTE * 0x10),
		("other_xsm3_dev_2des_key_2", BYTE * 0x10),

		# 3p2des
		("wireless_controller_3p2des_key_1", BYTE * 0x10),
		("wireless_controller_3p2des_key_2", BYTE * 0x10),

		("wired_webcam_3p2des_key_1", BYTE * 0x10),
		("wired_webcam_3p2des_key_2", BYTE * 0x10),

		("wired_controller_3p2des_key_1", BYTE * 0x10),
		("wired_controller_3p2des_key_2", BYTE * 0x10),

		("memory_unit_3p2des_key_1", BYTE * 0x10),
		("memory_unit_3p2des_key_2", BYTE * 0x10),

		("other_xsm3_dev_3p2des_key_1", BYTE * 0x10),
		("other_xsm3_dev_3p2des_key_2", BYTE * 0x10),

		("console_private_key", XECRYPT_RSAPRV_1024),
		("xeika_private_key", XECRYPT_RSAPRV_2048),
		("cardea_private_key", XECRYPT_RSAPRV_1024),

		("console_certificate_size", WORD),
		("console_id", BYTE * 5),
		("console_part_number", BYTE * 0xB),
		("console_reserved", DWORD),  # reserved
		("console_privileges", WORD),
		("console_type", DWORD),
		("manufacture_date", BYTE * 8),
		("console_public_key_exponent", DWORD),
		("console_public_key_modulus", BYTE * 0x80),
		("console_certificate_signature", XECRYPT_SIG),
		("xeika_certificate_size", WORD),
		("xeika_public_key", XECRYPT_RSAPUB_2048),
		("xeika_certificate_overlay_signature", DWORD),
		("xeika_certificate_overlay_version", WORD),
		("xeika_odd_date_version", BYTE),
		("xeika_odd_drive_phase_level", BYTE),
		("odd_version_string", BYTE * 0x28),
		("xeika_certificate_reserved", BYTE * 0x1146),  # reserved
		("special_keyvault_signature", XECRYPT_SIG),
		("cardea_certificate", BYTE * 0x2108)
	]

# utilities
def read_file(filename: str, text: bool = False) -> Union[BinLike, str]:
	p = Path(filename)
	if text:
		return p.read_text()
	else:
		return p.read_bytes()

def write_file(filename: str, data: Union[str, BinLike]) -> None:
	p = Path(filename)
	if type(data) == str:
		p.write_text(data)
	else:
		p.write_bytes(data)

def reverse(b: BinLike) -> BinLike:
	return bytes(reversed(b))

def rsa_pad(data: BinLike) -> BinLike:
	bounds = 8
	if len(data) % bounds == 0:
		return data
	ps = bounds - (len(data) % bounds)
	return data + (b"\x00" * ps)

def b2i(b: BinLike, bswap: bool = False) -> int:
	if bswap:
		b = bswap64(b)
	return int.from_bytes(b, "little", signed=False)

def i2b(i: int, size: int, bswap: bool = False) -> BinLike:
	data = i.to_bytes(size, "little", signed=False)
	data = rsa_pad(data)  # sometimes the data isn't evenly divisible by 8
	if bswap:
		data = bswap64(data)
	return data

def rotl(value: int, shift: int, bits: int = 32) -> int:
	return ((value << shift) | (value >> (bits - shift))) & ((1 << bits) - 1)

def rotr(value: int, shift: int, bits: int = 32) -> int:
	return ((value >> shift) | (value << (bits - shift))) & ((1 << bits) - 1)

def bswap(data: BinLike, fmt: str) -> BinLike:
	size = calcsize(fmt)
	assert len(data) % size == 0, "data isn't evenly divisible by size!"
	b = b""
	for i in range(0, len(data), size):
		t = b""
		for j in range(0, size):
			t += pack("B", data[i + j])
		b += reverse(t)
	return b

def bswap16(data: BinLike) -> BinLike:
	return bswap(data, "H")

def bswap32(data: BinLike) -> BinLike:
	return bswap(data, "I")

def bswap64(data: BinLike) -> BinLike:
	return bswap(data, "Q")

def XeCryptBnQw_SwapDwQwLeBe(b: BinLike) -> BinLike:
	return bswap64(b)

def memcmp(b0: BinLike, b1: BinLike, size: int) -> bool:
	return all([(b0[i] == b1[i]) for i in range(size)])

def XeCryptRandom(cb: int) -> BinLike:
	return urandom(cb)

# hashing
def XeCryptMd5(*args: BinLike) -> BinLike:
	h = Hash(MD5())
	[h.update(x) for x in args]
	return h.finalize()

def XeCryptSha(*args: BinLike) -> BinLike:
	h = Hash(SHA1())
	[h.update(x) for x in args]
	return h.finalize()

# MAC
def XeCryptHmacMd5(key: BinLike, *args: BinLike) -> BinLike:
	h = HMAC(key, MD5())
	[h.update(x) for x in args]
	return h.finalize()

def XeCryptHmacSha(key: BinLike, *args: BinLike) -> BinLike:
	h = HMAC(key, SHA1())
	[h.update(x) for x in args]
	return h.finalize()

# RC4
class XeCryptRc4:
	# only works in ECB mode!

	def __init__(self, key: BinLike):
		self.reset()

		self._cipher = Cipher(ARC4(key), None)

		self._enc = self._cipher.encryptor()
		self._dec = self._cipher.decryptor()

	def reset(self) -> None:
		self._cipher = None

	@staticmethod
	def new(key: BinLike):
		return XeCryptRc4(key)

	# encrypt and decrypt are exactly the same for RC4
	def crypt(self, data: BinLike) -> bytes:
		return self.encrypt(data)

	def encrypt(self, data: BinLike) -> bytes:
		return self._enc.update(data)

	def decrypt(self, data: BinLike) -> bytes:
		return self._dec.update(data)

# AES
class XeCryptAes:
	MODE_ECB = 1
	MODE_CBC = 2

	def __init__(self, key: BinLike, mode: Optional[int] = MODE_ECB, iv: Optional[BinLike] = None):
		self.reset()

		assert (len(key) * 8) in [128, 256], "AES key must be 128 or 256 bits"

		if mode == self.MODE_ECB:
			self._cipher = Cipher(AES(key), ECB())
		elif mode == self.MODE_CBC:
			assert iv is not None, "IV is required for the CBC cipher mode"
			self._cipher = Cipher(AES(key), CBC(iv))
		else:
			raise Exception("Invalid cipher mode entered")

		self._enc = self._cipher.encryptor()
		self._dec = self._cipher.decryptor()

	def reset(self) -> None:
		self._cipher = None

	@staticmethod
	def new(key: BinLike, mode: int = MODE_ECB, iv: BinLike = None):
		return XeCryptAes(key, mode, iv)

	def encrypt(self, data: BinLike) -> bytes:
		return self._enc.update(data)

	def decrypt(self, data: BinLike) -> bytes:
		return self._dec.update(data)

class XeCryptDes:
	MODE_ECB = 1
	MODE_CBC = 2

	def __init__(self, key: BinLike, mode: Optional[int] = MODE_ECB, iv: Optional[BinLike] = None):
		self.reset()

		assert (len(key) * 8) == 64, "DES key must be 64 bits"

		if mode == self.MODE_ECB:
			self._cipher = Cipher(TripleDES(key), ECB())
		elif mode == self.MODE_CBC:
			assert iv is not None, "IV is required for the CBC cipher mode"
			self._cipher = Cipher(TripleDES(key), CBC(iv))
		else:
			raise Exception("Invalid cipher mode entered")

		self._enc = self._cipher.encryptor()
		self._dec = self._cipher.decryptor()

	def reset(self) -> None:
		self._cipher = None

	@staticmethod
	def new(key: BinLike, mode: int = MODE_ECB, iv: BinLike = None):
		return XeCryptDes(key, mode, iv)

	def encrypt(self, data: BinLike) -> bytes:
		return self._enc.update(data)

	def decrypt(self, data: BinLike) -> bytes:
		return self._dec.update(data)

class XeCryptDes2:
	MODE_ECB = 1
	MODE_CBC = 2

	def __init__(self, key: BinLike, mode: Optional[int] = MODE_ECB, iv: Optional[BinLike] = None):
		self.reset()

		assert (len(key) * 8) == 128, "DES2 key must be 128 bits"

		if mode == self.MODE_ECB:
			self._cipher = Cipher(TripleDES(key), ECB())
		elif mode == self.MODE_CBC:
			assert iv is not None, "IV is required for the CBC cipher mode"
			self._cipher = Cipher(TripleDES(key), CBC(iv))
		else:
			raise Exception("Invalid cipher mode entered")

		self._enc = self._cipher.encryptor()
		self._dec = self._cipher.decryptor()

	def reset(self) -> None:
		self._cipher = None

	@staticmethod
	def new(key: BinLike, mode: int = MODE_ECB, iv: BinLike = None):
		return XeCryptDes2(key, mode, iv)

	def encrypt(self, data: BinLike) -> bytes:
		return self._enc.update(data)

	def decrypt(self, data: BinLike) -> bytes:
		return self._dec.update(data)

class XeCryptDes3:
	MODE_ECB = 1
	MODE_CBC = 2

	def __init__(self, key: BinLike, mode: Optional[int] = MODE_ECB, iv: Optional[BinLike] = None):
		self.reset()

		assert (len(key) * 8) == 192, "DES3 key must be 192 bits"

		if mode == self.MODE_ECB:
			self._cipher = Cipher(TripleDES(key), ECB())
		elif mode == self.MODE_CBC:
			assert iv is not None, "IV is required for the CBC cipher mode"
			self._cipher = Cipher(TripleDES(key), CBC(iv))
		else:
			raise Exception("Invalid cipher mode entered")

		self._enc = self._cipher.encryptor()
		self._dec = self._cipher.decryptor()

	def reset(self) -> None:
		self._cipher = None

	@staticmethod
	def new(key: BinLike, mode: int = MODE_ECB, iv: BinLike = None):
		return XeCryptDes3(key, mode, iv)

	def encrypt(self, data: BinLike) -> bytes:
		return self._enc.update(data)

	def decrypt(self, data: BinLike) -> bytes:
		return self._dec.update(data)

def XeCryptDesParity(data: BinLike) -> BinLike:
	output = bytearray(len(data))
	for i in range(len(data)):
		p = data[i]
		p ^= p >> 4
		p ^= p >> 2
		p ^= p >> 1
		output[i] = (data[i] & 0xFE) | (~p & 1)
	return output

def XeCryptParveEcb(key: BinLike, sbox: BinLike, data: BinLike) -> BinLike:
	block = bytearray(9)
	block[:8] = data[:8]
	block[8] = block[0]
	for i in range(8, 0, -1):
		for j in range(8):
			x = key[j] + block[j] + i
			x &= UINT8_MASK
			y = sbox[x] + block[j + 1]
			y &= UINT8_MASK
			block[j + 1] = rotl(y, 1, 8)
		block[0] = block[8]
	return block[:8]

def XeCryptParveCbcMac(key: BinLike, sbox: BinLike, iv: BinLike, data: BinLike) -> BinLike:
	block = bytearray(8)
	block[:8] = iv
	if len(data) >= 8:
		for i in range(0, len(data), 8):
			(v0,) = unpack(">Q", block)
			(v1,) = unpack_from(">Q", data, i)
			v0 ^= v1
			v0 &= UINT64_MASK
			block = pack(">Q", v0)
			block = XeCryptParveEcb(key, sbox, block)
	return block[:8]

def XeCryptChainAndSumMac(cd: BinLike, ab: BinLike, data: BinLike) -> BinLike:
	out0 = 0
	out1 = 0

	(ab0, ab1) = unpack(">2I", ab)
	ab0 %= 0x7FFFFFFF
	ab1 %= 0x7FFFFFFF

	(cd0, cd1) = unpack(">2I", cd)
	cd0 %= 0x7FFFFFFF
	cd1 %= 0x7FFFFFFF

	for i in range(0, len(data), 8):
		(v0, v1) = unpack_from(">2I", data, i)

		t = v0 * 0xE79A9C1
		t += out0
		t %= 0x7FFFFFFF
		t *= ab0
		t += ab1
		t %= 0x7FFFFFFF
		out1 += t

		t += v1
		t *= cd0
		t %= 0x7FFFFFFF
		t += cd1
		out0 = t % 0x7FFFFFFF
		out1 += out0

	return pack(">2I", (out0 + ab1) % 0x7FFFFFFF, (out1 + cd1) % 0x7FFFFFFF)

# checksums
def XeCryptRotSum(data: BinLike) -> BinLike:
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

def XeCryptRotSumSha(data: BinLike) -> BinLike:
	h = Hash(SHA1())
	rot_sum = bytearray(XeCryptRotSum(data))
	h.update(rot_sum)
	h.update(rot_sum)
	h.update(data)
	rot_sum = bytes(map(lambda b: ~b & 0xFF, rot_sum))
	h.update(rot_sum)
	h.update(rot_sum)
	return h.finalize()

# RSA
def XeCryptBnQwNeModInv(val: int) -> int:
	return pow(1 << 64, -1, val)

def XeCryptBnQwNeModExpRoot(c: int, p: int, q: int, dp: int, dq: int, u: int) -> int:
	m1 = pow(c, dp, p)
	m2 = pow(c, dq, q)
	h = (u * (m1 - m2)) % p
	m = m2 + h * q
	return m

def XeCryptBnQwBeBufSwap(data: BinLike) -> BinLike:
	assert len(data) % 8 == 0
	if isinstance(data, bytes):
		data = bytearray(data)
	cqw = len(data) // 8
	pstart = 0
	pend = (cqw - 1) * 8
	for _ in range(cqw // 2):
		(val1,) = unpack("8s", data[pstart:pstart + 8])
		(val2,) = unpack("8s", data[pend:pend + 8])
		pack_into("8s", data, pend, val1)
		pack_into("8s", data, pstart, val2)
		pend -= 8
		pstart += 8
	return data

def XeCryptBnQwNeRsaKeyGen(cbits: int = 2048, exp: int = 0x10001) -> Tuple[BinLike, BinLike]:
	assert cbits in [1024, 1536, 2048, 4096], "Invalid bit count specified!"
	prv_key = rsa.generate_private_key(exp, cbits)
	cb = prv_key.key_size // 8
	cbh = cb // 2
	cqw = cb // 8

	pub_n = prv_key.public_key().public_numbers()
	prv_n = prv_key.private_numbers()

	n = i2b(pub_n.n, cb, True)
	p = i2b(prv_n.p, cbh, True)
	q = i2b(prv_n.q, cbh, True)
	dp = i2b(prv_n.dmp1, cbh, True)
	dq = i2b(prv_n.dmq1, cbh, True)
	u = i2b(prv_n.iqmp, cbh, True)

	mod_inv = XeCryptBnQwNeModInv(pub_n.n)
	mod_inv &= UINT64_MASK

	if cbits == 1024:
		b_prv_key = pack(">2IQ 128s 64s 64s 64s 64s 64s", cqw, exp, mod_inv, n, p, q, dp, dq, u)
		return (b_prv_key[:XECRYPT_RSAPUB_1024_SIZE], b_prv_key)
	elif cbits == 1536:
		b_prv_key = pack(">2IQ 192s 96s 96s 96s 96s 96s", cqw, exp, mod_inv, n, p, q, dp, dq, u)
		return (b_prv_key[:XECRYPT_RSAPUB_1536_SIZE], b_prv_key)
	elif cbits == 2048:
		b_prv_key = pack(">2IQ 256s 128s 128s 128s 128s 128s", cqw, exp, mod_inv, n, p, q, dp, dq, u)
		return (b_prv_key[:XECRYPT_RSAPUB_2048_SIZE], b_prv_key)
	elif cbits == 4096:
		b_prv_key = pack(">2IQ 512s 256s 256s 256s 256s 256s", cqw, exp, mod_inv, n, p, q, dp, dq, u)
		return (b_prv_key[:XECRYPT_RSAPUB_4096_SIZE], b_prv_key)

def XeCryptBnQwBeSigFormat(cqw: int, b_hash: BinLike, salt: BinLike) -> BinLike:
	sig = bytearray(cqw * 8)

	h = Hash(SHA1())
	h.update(bytes(8) + b_hash + salt)
	ab_hash = h.finalize()

	pack_into("B", sig, 0xE0, 1)
	pack_into("10s", sig, 0xE1, salt)
	pack_into("235s", sig, 0, XeCryptRc4.new(ab_hash).encrypt(sig[:0xEB]))
	pack_into("20s", sig, 0xEB, ab_hash)
	pack_into("B", sig, 0xFF, 0xBC)
	sig[0] &= 0x7F
	return XeCryptBnQwBeBufSwap(sig)

def XeCryptBnQwBeSigCreate(b_hash: BinLike, salt: BinLike, prv_key: BinLike) -> Union[BinLike, None]:
	if len(salt) > 10:
		raise Exception("Salt parameter must be 10 bytes or less")

	key = PY_XECRYPT_RSA_KEY(prv_key)
	if key.cqw != 0x20:  # PXECRYPT_RSAPRV_2048
		raise Exception("Only PXECRYPT_RSAPRV_2048 can create signatures")

	if key.e not in [0x3, 0x10001]:
		raise Exception("Public exponent must be 0x3 or 0x10001")

	sig = XeCryptBnQwBeSigFormat(key.cqw, b_hash, salt)
	if sig == bytes(key.n_size_in_bytes):
		raise Exception("Output signature size overflow")

	si = b2i(sig, True)
	se = (si * key.r) % key.n  # convert out
	sb = i2b(se, key.cqw * 8, True)
	return sb

def XeCryptBnQwBeSigVerify(sig: BinLike, b_hash: BinLike, salt: BinLike, pub_key: BinLike) -> bool:
	if len(salt) > 10:
		raise Exception("Salt parameter must be 10 bytes or less")

	key = PY_XECRYPT_RSA_KEY(pub_key)

	if key.cqw != 0x20:  # PXECRYPT_RSAPUB_2048
		raise Exception("Only PXECRYPT_RSAPUB_2048 can verify signatures")

	si = b2i(sig, True)
	se = pow(si, key.e, key.n)  # reverse of pow(sig, key.d, key.n)
	sd = (se * key.inv_r) % key.n  # reverse of (si * key.r) % key.n
	sb = i2b(sd, key.cqw * 8, True)

	sd = XeCryptBnQwBeBufSwap(sb)

	if sd[0xFF] != 0xBC:
		return False

	h = Hash(SHA1())
	h.update(bytes(8) + b_hash + salt)
	if h.finalize() != sd[0xEB:-1]:
		return False

	sd = XeCryptRc4.new(sd[0xEB:-1]).decrypt(sd[:0xEB])

	if sd[0xE0] != 1:
		return False

	if not all([x == 0 for x in sd[1:0xE0]]):
		return False

	if sd[0xE1:0xE1 + len(salt)] != salt:
		return False

	return True

def XeCryptBnDwLePkcs1Format(b_hash: BinLike, fmt_type: int, cb_sig: int) -> Union[BinLike, None]:
	if cb_sig < 0x27 or cb_sig > 0x200:
		return

	sig = bytearray(0x200)
	# pack_into(f"{cb_sig}s", sig, 0, (b"\xFF" * cb_sig))
	sig[:cb_sig] = (b"\xFF" * cb_sig)
	sig[cb_sig - 1] = 0
	sig[cb_sig - 2] = 1
	sig[:20] = b_hash[::-1]
	# pack_into("20s", sig, 0, b_hash[::-1])
	if fmt_type == 0:
		tbuf = bytes.fromhex("140400051A02030E2B05060930213000")
		# pack_into(f"{len(tbuf)}s", sig, 0x14, tbuf)
		sig[0x14:0x14 + len(tbuf)] = tbuf
	elif fmt_type == 1:
		tbuf = bytes.fromhex("14041A02030E2B050607301F3000")
		# pack_into(f"{len(tbuf)}s", sig, 0x14, tbuf)
		sig[0x14:0x14 + len(tbuf)] = tbuf
	else:
		sig[0x14] = 0
	return sig

def XeCryptBnDwLePkcs1Verify(sig: BinLike, b_hash: BinLike, cb_sig: int) -> bool:
	if 0x27 <= len(sig) <= 0x200:
		typ = 2
		if sig[0x16] == 0:
			typ = 0
		elif sig[0x16] == 0x1A:
			typ = 1
		buf = XeCryptBnDwLePkcs1Format(b_hash, typ, cb_sig)
		return memcmp(buf, sig, cb_sig)

def XeKeysPkcs1Create(b_hash: BinLike, prv_key: BinLike) -> Union[BinLike, None]:
	key = PY_XECRYPT_RSA_KEY(prv_key)
	if 0 < key.cqw <= 0x40:
		# buf = bytearray(0x200)
		#typ = 2
		#if sig[0x16] == 0:
		#	typ = 0
		#elif sig[0x16] == 0x1A:
		#	typ = 1
		typ = 0
		buf = XeCryptBnDwLePkcs1Format(b_hash, typ, key.cqw << 3)
		buf = bswap64(buf)
		buf = key.prv_crypt(buf)
		return bswap64(buf)

def XeKeysPkcs1Verify(sig: BinLike, b_hash: BinLike, pub_key: BinLike) -> bool:
	key = PY_XECRYPT_RSA_KEY(pub_key)
	if 0 < key.cqw <= 0x40:
		buf = bswap64(sig)
		buf = key.pub_crypt(buf)
		buf = bswap64(buf)
		return XeCryptBnDwLePkcs1Verify(buf, b_hash, key.cqw << 3)
	return False

def XeCryptBnQwNeRsaPrvCrypt(data: BinLike, prv_key: BinLike) -> Union[BinLike, bool]:
	key = PY_XECRYPT_RSA_KEY(prv_key)
	return key.prv_crypt(data)

def XeCryptBnQwNeRsaPubCrypt(data: BinLike, pub_key: BinLike) -> Union[BinLike, bool]:
	key = PY_XECRYPT_RSA_KEY(pub_key)
	return key.pub_crypt(data)

# Utility
def XeCryptSmcDecrypt(data: BinLike) -> BinLike:
	res = b""
	key = list(XECRYPT_SMC_KEY)
	for i in range(0, len(data)):
		j = data[i]
		mod = j * 0xFB
		res += bytes([j ^ (key[i & 3] & 0xFF)])
		key[(i + 1) & 3] += mod
		key[(i + 2) & 3] += mod >> 8
	return res

def XeCryptSmcEncrypt(data: BinLike) -> BinLike:
	res = b""
	key = list(XECRYPT_SMC_KEY)
	for i in range(0, len(data)):
		j = data[i] ^ (key[i & 3] & 0xFF)
		mod = j * 0xFB
		res += bytes([j])
		key[(i + 1) & 3] += mod
		key[(i + 2) & 3] += mod >> 8
	return res

def XeCryptHammingWeight(data: BinLike) -> int:
	wght = 0
	for i in range(len(data)):
		val = data[i]
		for j in range(8):
			wght += val & 1
			val >>= 1
	return wght

def XeCryptUidEccEncode(data: BinLike) -> BinLike:
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
def XeCryptCpuKeyValid(cpu_key: BinLike) -> bool:
	if len(cpu_key) != 0x10:
		return False

	wght_mask = bytes.fromhex("FFFFFFFFFFFFFFFFFFFFFFFFFF030000")
	key_tmp = bytearray(0x10)
	for i in range(0x10):
		key_tmp[i] = cpu_key[i] & wght_mask[i]
	wght = XeCryptHammingWeight(key_tmp)
	key_tmp = XeCryptUidEccEncode(key_tmp)
	ecc_good = (cpu_key == key_tmp)
	wght_good = (wght == 0x35)
	return ecc_good and wght_good

def XeCryptCpuKeyGen() -> BinLike:
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
			print(f"Error, dw_rand: 0x{dw_rand:X}")
		key[(bit_pos >> 3) & 0x1F] = (1 << (bit_pos & 0x7)) ^ key[(bit_pos >> 3) & 0x1F]
	return XeCryptUidEccEncode(key)

def XeCryptKeyVaultDecrypt(cpu_key: BinLike, data: BinLike) -> BinLike:
	assert XeCryptCpuKeyValid(cpu_key), "Invalid CPU key"
	version = bytes.fromhex("0712")
	kv_hash = XeCryptHmacSha(cpu_key, data[:0x10])[:0x10]
	data = data[:0x10] + XeCryptRc4.new(kv_hash).decrypt(data[0x10:])
	kv_hash = XeCryptHmacSha(cpu_key, data[0x10:], version)[:0x10]
	assert data[:0x10] == kv_hash, "Invalid KV digest"
	return data

def XeCryptKeyVaultEncrypt(cpu_key: BinLike, data: BinLike) -> BinLike:
	if isinstance(data, bytes):
		data = bytearray(data)
	assert XeCryptCpuKeyValid(cpu_key), "Invalid CPU key"
	version = bytes.fromhex("0712")
	# random nonce
	pack_into("8s", data, 0, XeCryptRandom(0x10))
	# random obfuscation key
	pack_into("8s", data, 0x10, XeCryptRandom(8))
	pack_into("16s", data, 0, XeCryptHmacSha(cpu_key, data[0x10:], version)[:0x10])
	rc4_key = XeCryptHmacSha(cpu_key, data[:0x10])[:0x10]
	return bytes(data[:0x10]) + XeCryptRc4.new(rc4_key).encrypt(data[0x10:])

def XeCryptKeyVaultVerify(cpu_key: BinLike, data: BinLike, pub_key: BinLike) -> bool:
	assert XeCryptCpuKeyValid(cpu_key), "Invalid CPU key"
	kv_data = data[0x18:]
	kv_hash = XeCryptHmacSha(cpu_key, kv_data[4:4 + 0xD4], kv_data[0xE8:0xE8 + 0x1CF8], kv_data[0x1EE0:0x1EE0 + 0x2108])
	return XeKeysPkcs1Verify(kv_data[0x1DE0:0x1DE0 + 0x100], kv_hash, pub_key)

def XeCryptPageEccEncode(data: BinLike) -> BinLike:
	if isinstance(data, bytes):
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

# managed public key "interfaces"
class PY_XECRYPT_RSA_KEY:
	key_bytes = None
	rsa_struct = None
	key_struct = None

	def __init__(self, data: BinLike = None):
		self.reset()

		self.key_bytes = data
		self.rsa_struct = XECRYPT_RSA.from_buffer_copy(data[:sizeof(XECRYPT_RSA)])
		try:
			self.key_struct = globals()[self.struct_name].from_buffer_copy(data)
		except KeyError as e:
			raise Exception("Invalid key data specified")
		# verify key parameters
		assert self.verify_parameters(), "Key parameters are incorrect!"

	def reset(self) -> None:
		self.key_bytes = None
		self.rsa_struct = None
		self.key_struct = None

	def __enter__(self):
		return self

	def __exit__(self, exc_type, exc_val, exc_tb):
		pass

	def __bytes__(self) -> BinLike:
		return self.key_bytes

	def __len__(self) -> int:
		return len(self.key_bytes)

	def to_bytes(self) -> BinLike:
		return self.key_bytes

	def to_cryptography(self) -> Union[RSAPrivateKey, RSAPublicKey]:
		pn = RSAPublicNumbers(self.e, self.n)
		if self.is_private_key:
			pn = RSAPrivateNumbers(self.p, self.q, self.d, self.dp, self.dq, self.inv_q, pn)
			return pn.private_key()
		else:
			return pn.public_key()

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

	@property
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
	def struct_name(self) -> str:
		return f"XECRYPT_RSA{'PRV' if self.is_private_key else 'PUB'}_{self.n_size_in_bits}"

	@property
	def cqw(self) -> int:
		return self.rsa_struct.cqw

	@property
	def mod_inv(self) -> int:
		v = self.key_struct.qwReserved
		if v == 0:
			v = XeCryptBnQwNeModInv(self.n)
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
		return pow(self.e, -1, (self.p - 1) * (self.q - 1))

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
	def r(self) -> int:
		return pow(2, ((self.e - 1) << 11), self.n)

	@property
	def inv_r(self) -> int:
		return pow(self.r, -1, self.n)

	@property
	def inv_q(self) -> int:
		return pow(self.q, -1, self.p)

	def verify_parameters(self) -> bool:
		# public key and private
		if self.n < 3:
			return False
		if self.e < 3 or self.e >= self.n:
			return False
		if self.e & 1 == 0:
			return False

		if self.is_private_key:
			if self.dp >= self.n:
				return False
			if self.dq >= self.n:
				return False
			if self.u >= self.n:
				return False
			if self.dp & 1 == 0:
				return False
			if self.dq & 1 == 0:
				return False

			calc_n = self.p * self.q
			calc_dp = self.d % (self.p - 1)
			calc_dq = self.d % (self.q - 1)

			if self.n != calc_n:
				return False
			if self.dp != calc_dp:
				return False
			if self.dq != calc_dq:
				return False
			if self.u != self.inv_q:
				return False
		return True

	def prv_crypt(self, n: Union[int, BinLike]) -> bytes:
		assert self.is_private_key, "Key isn't a private key!"
		if isinstance(n, (bytes, bytearray)):
			n = b2i(n, True)
		return i2b(XeCryptBnQwNeModExpRoot(n, self.p, self.q, self.dp, self.dq, self.u), self.n_size_in_bytes, True)

	def pub_crypt(self, n: Union[int, BinLike]) -> bytes:
		if isinstance(n, (bytes, bytearray)):
			n = b2i(n, True)
		return i2b(pow(n, self.e, self.n), self.n_size_in_bytes, True)

	def sig_create(self, hash: BinLike, salt: BinLike) -> BinLike:
		assert self.is_private_key, "Key isn't a private key!"
		sig = XeCryptBnQwBeSigCreate(hash, salt, self.key_bytes)
		return self.prv_crypt(sig)

	def sig_verify(self, sig: BinLike, hash: BinLike, salt: BinLike) -> bool:
		return XeCryptBnQwBeSigVerify(sig, hash, salt, self.public_key.to_bytes())

	def sig_create_pkcs1(self, hash: BinLike) -> BinLike:
		assert self.is_private_key, "Key isn't a private key!"
		return XeKeysPkcs1Create(hash, self.key_bytes)

	def sig_verify_pkcs1(self, sig: BinLike, hash: BinLike) -> bool:
		return XeKeysPkcs1Verify(sig, hash, self.public_key.to_bytes())

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

	"XECRYPT_KEYVAULT"
])

# functions
__all__.extend([
	"XeCryptDesParity",
	"XeCryptParveEcb",
	"XeCryptParveCbcMac",
	"XeCryptChainAndSumMac",
	"XeCryptBnDwLePkcs1Format",
	"XeCryptBnDwLePkcs1Verify",
	"XeCryptBnQwBeSigCreate",
	"XeCryptBnQwBeSigFormat",
	"XeCryptBnQwBeSigVerify",
	"XeCryptBnQwNeModInv",
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
	"XeCryptPageEccEncode",
	"XeCryptRandom",
	"XeCryptRotSum",
	"XeCryptRotSumSha",
	"XeCryptSha",
	"XeCryptSmcDecrypt",
	"XeCryptSmcEncrypt",
	"XeCryptUidEccEncode",
	"XeKeysPkcs1Create",
	"XeKeysPkcs1Verify"
])

# classes
__all__.extend([
	"XeCryptRc4",
	"XeCryptAes",
	"XeCryptDes",
	"XeCryptDes2",
	"XeCryptDes3",
	"PY_XECRYPT_RSA_KEY"
])

# utility functions
__all__.extend([
	"read_file",
	"write_file",
	"reverse",
	"b2i",
	"i2b",
	"rotl",
	"rotr",
	"bswap16",
	"bswap32",
	"bswap64",
	"XeCryptBnQw_SwapDwQwLeBe"
])
