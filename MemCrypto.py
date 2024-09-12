#!/usr/bin/env python3

__credits__  = ["tydye81", "teir1plus2", "no-op", "juv"]

# References:
# https://github.com/CWest07/Xbox-360-Hypervisor-Manager/blob/main/Form1.cs
# https://gist.github.com/SciresM/a4b9ae50a9ae89e6119c4de9def22435#file-aes128-py

from io import BytesIO
from typing import Generator
from argparse import ArgumentParser

# py -3 -m pip install cryptography
# pip install cryptography
from cryptography.hazmat.primitives.hashes import Hash, SHA1
from cryptography.hazmat.primitives.ciphers.modes import ECB
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey, RSAPublicNumbers
from cryptography.hazmat.primitives.ciphers import Cipher, AEADEncryptionContext, AEADDecryptionContext

# constants
ALL_55_KEY = b"\x55" * 0x10
GF2_IV = 0
GF2_POLY = 0x87
HVEX_ADDR = 0x01B5
HV_17559_TABLE_ADDR = 0x10878
SRAM_CKSM_PAGE_SIZE = 0x80
_1BL_KEY = bytes.fromhex("DD88AD0C9ED669E7B56794FB68563EFA")

# rsa values
MASTER_N = int("E1322F1DE92AD64B494455CB05173F6671A964A415536E2B680C40F54FDA808F19B82CD0D7E964B2224C56DE03E2462F946F4FFFAD4588"
		"CF78CEED1CE5FD0F80533AE97043EAD1D12E39880C3CAEEBFDA5ACA3A69445E542EF269D5459952D252945B0169BEF788FB1EAE548AC1A"
		"C3C878899708DE24D1ED04D0555079199527", 16)
MASTER_E = 0x10001
MASTER_PUB = RSAPublicNumbers(MASTER_E, MASTER_N).public_key()

create_mask = lambda n: (1 << n) - 1

# runtime
GF2_TAB: list[int] = []

# masks
UINT8_MASK = create_mask(8)
UINT16_MASK = create_mask(16)
UINT32_MASK = create_mask(32)
UINT36_MASK = create_mask(36)
UINT64_MASK = create_mask(64)
UINT128_MASK = create_mask(128)

def read_file(filename: str):
	with open(filename, "rb") as f:
		return f.read()

def write_file(filename: str, data: bytes | bytearray) -> None:
	with open(filename, "wb") as f:
		f.write(data)

def rotr(n: int, d: int, b: int) -> int:
	return (n >> d) | (n << (b - d)) & eval(f"UINT{b}_MASK")

def sxor_u32(s1: bytes | bytearray, s2: bytes | bytearray) -> bytes:
	assert len(s1) == len(s2), "s1 and s2 must be the same size"

	# a1 = unpack(f"<{len(s1) // 4}I", s1)
	# a2 = unpack(f"<{len(s2) // 4}I", s2)
	a1 = list(map(lambda b: int.from_bytes(b, "little", signed=False), read_chunks(s1, 0, 4)))
	a2 = list(map(lambda b: int.from_bytes(b, "little", signed=False), read_chunks(s2, 0, 4)))
	return b"".join(list(map(lambda a, b: (a ^ b).to_bytes(4, "little", signed=False), a1, a2)))

def sand_u32(s1: bytes | bytearray, s2: bytes | bytearray) -> bytes:
	assert len(s1) == len(s2), "s1 and s2 must be the same size"

	# a1 = unpack(f"<{len(s1) // 4}I", s1)
	# a2 = unpack(f"<{len(s2) // 4}I", s2)
	a1 = list(map(lambda b: int.from_bytes(b, "little", signed=False), read_chunks(s1, 0, 4)))
	a2 = list(map(lambda b: int.from_bytes(b, "little", signed=False), read_chunks(s2, 0, 4)))
	return b"".join(list(map(lambda a, b: (a & b).to_bytes(4, "little", signed=False), a1, a2)))

def sxor_b(s1: bytes | bytearray, s2: bytes | bytearray) -> bytes:
	return bytes(list(map(lambda a, b: a ^ b, s1, s2)))

def read_chunk(data: bytes | bytearray, offset: int, size: int) -> bytes:
	return data[offset:offset + size]

def read_chunks(data: bytes | bytearray, offset: int, size: int) -> Generator[bytes, None, None]:
	assert (len(data) - offset) % size == 0, "data must be evenly divisible by size"
	for i in range(offset, len(data) - offset, size):
		yield data[i:i + size]

def rsa_encrypt(key: RSAPublicKey, data: bytes | bytearray) -> bytes:
	pn = key.public_numbers()
	return pow(int.from_bytes(data, "little"), pn.e, pn.n).to_bytes(key.key_size // 8, "big")

def generate_gf2_table(iv: int, poly: int) -> list[int]:
	tab = [0] * 256
	for i in range(256):
		crc = iv
		c = i << 8
		for j in range(8):
			if (crc ^ c) & 0x8000:
				crc = (crc << 1) ^ poly
			else:
				crc <<= 1
			c <<= 1
		tab[i] = crc & UINT16_MASK
	return tab

def some_bullshit(key: bytes | bytearray, buffer: bytes | bytearray, offset: int, length: int) -> bytes:
	cycle = 0
	while length > 0:
		h = Hash(SHA1())
		h.update(key)
		h.update(cycle.to_bytes(4, "big"))
		digest = h.finalize()

		sublen = 0x14
		if length < 0x14:
			sublen = length

		buffer[offset:offset + sublen] = sxor_b(read_chunk(buffer, offset, sublen), digest)

		offset += sublen
		length -= sublen
		cycle += 1
	return buffer

class MemoryCrypto:
	aesdec: AEADDecryptionContext = None
	aesenc: AEADEncryptionContext = None

	white_key: bytes | bytearray = b""
	aes_key: bytes | bytearray = b""
	hash_key: bytes | bytearray = b""

	def __init__(self, wkey: bytes | bytearray, akey: bytes | bytearray, hkey: bytes | bytearray):
		self.reset()

		self.white_key = wkey
		self.aes_key = akey
		self.hash_key = hkey

		c = Cipher(AES(akey), ECB())
		self.aesdec = c.decryptor()
		self.aesenc = c.encryptor()

	def __enter__(self):
		return self

	def __exit__(self, exc_type, exc_val, exc_tb):
		pass

	def reset(self) -> None:
		self.aesdec = None
		self.aesenc = None
		self.white_key = b""
		self.aes_key = b""
		self.hash_key = b""

	def sram_offset_to_hv_offset(self, sram_offset: int) -> int:
		return (sram_offset // 2) * SRAM_CKSM_PAGE_SIZE

	def sram_size_to_hv_size(self, sram_size: int) -> int:
		return self.sram_offset_to_hv_offset(sram_size)

	def get_tweak_1(self, n: int) -> int:
		of = (n >> 128) & UINT36_MASK
		n &= UINT128_MASK

		# checksum the last 36 bits and XOR them into the first 128 bits
		i = 0
		while of:
			n ^= GF2_TAB[of & 0xFF] << (i * 8)
			of >>= 8
			i += 1
		return n & UINT128_MASK

	def get_tweak_0(self, address: int) -> bytes:
		key = int.from_bytes(self.white_key, "big")
		# create space for 36 bits
		value = key << 36

		# make address 32 bits (normally 36 bits)
		address >>= 4

		# loop through all bits in the address and
		# transform the value only if the bit is 1
		for i in range(address.bit_length()):
			if (address >> i) & 1:
				value ^= (key << i)

		return self.get_tweak_1(value).to_bytes(16, "big")

	def fix_address(self, address: int) -> int:
		if 0 <= address <= 0x40000:  # in HV range
			return address | (0x200000000 * (address // 0x10000))
		else:  # outside HV range
			return address

	def encrypt_block(self, dec_data: bytes | bytearray, offset: int, size: int, address: int = None, offset_is_address: bool = False) -> bytes:
		if address is None and offset_is_address:
			address = offset

		dec_data = read_chunk(dec_data, offset, size)

		# calculate tweak key
		tweak = self.get_tweak_0(address)
		# apply tweak before
		enc_data = sxor_u32(dec_data, tweak)
		# "encrypt" memory
		enc_data = self.aesdec.update(enc_data)
		# apply tweak after
		enc_data = sxor_u32(enc_data, tweak)

		return enc_data

	def decrypt_block(self, enc_data: bytes | bytearray, offset: int, size: int, address: int = None, offset_is_address: bool = False) -> bytes:
		if address is None and offset_is_address:
			address = offset

		enc_data = read_chunk(enc_data, offset, size)

		# calculate tweak key
		tweak = self.get_tweak_0(address)
		# apply tweak before
		dec_data = sxor_u32(enc_data, tweak)
		# "decrypt" memory
		dec_data = self.aesenc.update(dec_data)
		# apply tweak after
		dec_data = sxor_u32(dec_data, tweak)

		return dec_data

	def encrypt(self, hv_data_dec: bytes | bytearray, offset: int, size: int, address: int = None, offset_is_address: bool = False) -> bytes:
		if address is None and offset_is_address:
			address = offset

		assert size % 16 == 0, "Size must be divisible by the AES block size (16 bytes)"

		hv_data_dec = read_chunk(hv_data_dec, offset, size)

		with BytesIO() as bio:
			for i in range(0, size, 16):
				bio.write(self.encrypt_block(hv_data_dec, i, 16, self.fix_address(address + i), offset_is_address))
			return bio.getvalue()

	def decrypt(self, hv_data_enc: bytes | bytearray, offset: int, size: int, address: int = None, offset_is_address: bool = False) -> bytes:
		if address is None and offset_is_address:
			address = offset

		assert size % 16 == 0, "Size must be divisible by the AES block size (16 bytes)"

		hv_data_enc = read_chunk(hv_data_enc, offset, size)

		with BytesIO() as bio:
			for i in range(0, size, 16):
				bio.write(self.decrypt_block(hv_data_enc, i, 16, self.fix_address(address + i), offset_is_address))
			return bio.getvalue()

	def encrypt_and_calc_checksums(self, hv_data_dec: bytes | bytearray, offset: int, size: int, address: int = None, offset_is_address: bool = False) -> bytes:
		if address is None and offset_is_address:
			address = offset

		hv_data_dec = read_chunk(hv_data_dec, offset, size)
		hv_data_enc = self.encrypt(hv_data_dec, 0, size, address, offset_is_address)

		return self.calc_sram_checksums(hv_data_dec, hv_data_enc, 0, size)

	def calc_sram_checksum(self, data: bytes | bytearray) -> int:
		cksm = 0
		rot_val = 1
		for i in range(len(data) // 2):
			v = int.from_bytes(data[i * 2:i * 2 + 2], "big", signed=False)
			cksm ^= rotr(v, rot_val, 16)
			rot_val = ((i + 1) // 4) + 1
		return cksm & UINT16_MASK

	def calc_sram_checksums(self, hv_data_dec: bytes | bytearray, hv_data_enc: bytes | bytearray, offset: int, size: int) -> bytes:
		assert size % SRAM_CKSM_PAGE_SIZE == 0, "Hashes require data to be evenly divisible by 0x80"

		hv_data_dec = read_chunk(hv_data_dec, offset, size)
		hv_data_enc = read_chunk(hv_data_enc, offset, size)

		mask = self.hash_key * (len(hv_data_dec) // 0x10)
		masked = sand_u32(hv_data_enc, mask)
		hv_data_dec = sxor_u32(masked, hv_data_dec)

		num_cksm_pages = size // SRAM_CKSM_PAGE_SIZE
		cksms = [self.calc_sram_checksum(hv_data_dec[(i * SRAM_CKSM_PAGE_SIZE):(i * SRAM_CKSM_PAGE_SIZE) + SRAM_CKSM_PAGE_SIZE]) for i in range(num_cksm_pages)]
		return b"".join(list(map(lambda i: i.to_bytes(2, "big", signed=False), cksms)))

	def get_checksum_chunk_by_sram_offset_and_size(self, hv_data_dec: bytes | bytearray, hv_data_enc: bytes | bytearray, sram_offset: int, sram_size: int) -> bytes:
		hv_offs = self.sram_offset_to_hv_offset(sram_offset)
		hv_size = self.sram_size_to_hv_size(sram_size)
		return self.calc_sram_checksums(hv_data_dec, hv_data_enc, hv_offs, hv_size)

	def calc_sram(self, hv_data_dec: bytes | bytearray) -> bytes:
		hv_data_enc = self.encrypt(hv_data_dec, 0, 0x40000, 0)
		return self.calc_sram_checksums(hv_data_dec, hv_data_enc, 0, 0x40000)

	def calc_hash_1_digest(self, hv_data_dec: bytes | bytearray, salt: bytes | bytearray) -> bytes:
		salt = salt[:0x10]  # ensure salt is 0x10 in length

		h = Hash(SHA1())
		h.update(salt)
		h.update(read_chunk(hv_data_dec, 0x34, 0x40))
		h.update(read_chunk(hv_data_dec, 0x78, 0xFF88))
		h.update(read_chunk(hv_data_dec, 0x100C0, 0x40))
		h.update(read_chunk(hv_data_dec, 0x10350, 0x5F70))
		h.update(read_chunk(hv_data_dec, 0x16EA0, 0x9160))
		h.update(read_chunk(hv_data_dec, 0x20000, 0xFFFF))
		h.update(read_chunk(hv_data_dec, 0x30000, 0xFFFF))
		return read_chunk(h.finalize(), 0xE, 6)

	def calc_hash_2_digest(self, hv_data_dec: bytes | bytearray, salt: bytes | bytearray, hvex_addr: int) -> bytes:
		salt = salt[:0x10]  # ensure salt is 0x10 in length

		# HVEX_ADDR = 0x1B9

		hv_salt_dec = salt * 8
		hv_hash_addr = (hvex_addr << 0x10) | 0x7C00000000 + 0x400

		h = Hash(SHA1())
		h.update(self.encrypt_and_calc_checksums(hv_salt_dec, 0, len(hv_salt_dec), hv_hash_addr))
		h.update(read_chunk(hv_data_dec, 0x34, 0xC))
		h.update(self.encrypt(hv_data_dec, 0x40, 0x30, offset_is_address=True))
		h.update(read_chunk(hv_data_dec, 0x70, 4))
		h.update(read_chunk(hv_data_dec, 0x78, 8))
		h.update(self.encrypt_and_calc_checksums(hv_data_dec, 0x80, 0xFF80, offset_is_address=True))
		h.update(self.encrypt(hv_data_dec, 0x100C0, 0x40, offset_is_address=True))
		h.update(self.encrypt(hv_data_dec, 0x10350, 0x30, offset_is_address=True))
		h.update(self.encrypt_and_calc_checksums(hv_data_dec, 0x10380, 0x5F00, offset_is_address=True))
		h.update(self.encrypt(hv_data_dec, 0x16280, 0x40, offset_is_address=True))
		h.update(self.encrypt(hv_data_dec, 0x16EA0, 0x60, offset_is_address=True))
		h.update(self.encrypt_and_calc_checksums(hv_data_dec, 0x16F00, 0x9100, offset_is_address=True))
		h.update(self.encrypt_and_calc_checksums(hv_data_dec, 0x20000, 0x10000, offset_is_address=True))
		h.update(self.encrypt_and_calc_checksums(hv_data_dec, 0x30000, 0x10000, offset_is_address=True))
		return h.finalize()

	def calc_key_blob(self, blob_nonce: bytes | bytearray) -> bytes:
		key_blob = bytearray(0x80)
		key_blob[1:1+20] = blob_nonce
		key_blob[0x15:0x15+20] = bytes.fromhex('DA39A3EE5E6B4B0D3255BFEF95601890AFD80709')
		key_blob[0x4F] = 1
		key_blob[0x50:0x50+0x10] = self.white_key
		key_blob[0x60:0x60+0x10] = self.aes_key
		key_blob[0x70:0x70+0x10] = self.hash_key
		key_blob = some_bullshit(key_blob[0x1:0x15], key_blob, 0x15, 0x6B)
		key_blob = some_bullshit(key_blob[0x15:0x15 + 0x6B], key_blob, 1, 0x14)
		return rsa_encrypt(MASTER_PUB, key_blob)

	def calc_100f0(self, hv_data_dec: bytes | bytearray, tbl_addr: int) -> bytes:
		# encrypt the clean decrypted HV
		hv_data_enc = self.encrypt(hv_data_dec, 0, 0x40000, 0)

		# create SHA1 hasher
		h = Hash(SHA1())
		for i in range(6):
			# grab unaligned addresses and sizes from the HV

			# (u_strt_addr, u_stop_addr) = unpack_from(">2I", hv_data_dec, tbl_addr + (i * 8))
			o = tbl_addr + (i * 8)
			u_strt_addr = int.from_bytes(hv_data_dec[o:o + 4], "big", signed=False)
			o += 4
			u_stop_addr = int.from_bytes(hv_data_dec[o:o + 4], "big", signed=False)

			# 0x80 align address and size
			a_strt_addr = (u_strt_addr + 0x7F) & 0xFFFFFFFFFFFFFF80
			a_stop_addr = u_stop_addr & 0xFFFFFF80

			if a_strt_addr < a_stop_addr:
				# print(f"RAM:  0x{a_strt_addr:X} - 0x{a_stop_addr:X}")

				sram_offs = (a_strt_addr // SRAM_CKSM_PAGE_SIZE) * 2
				sram_size = ((a_stop_addr - a_strt_addr) // SRAM_CKSM_PAGE_SIZE) * 2

				# print(f"SRAM: 0x{sram_offs:X} - 0x{sram_offs + sram_size:X}")

				h.update(self.get_checksum_chunk_by_sram_offset_and_size(hv_data_dec, hv_data_enc, sram_offs, sram_size))

		return h.finalize()[:0x10]

def main() -> int:
	global GF2_TAB

	GF2_TAB = generate_gf2_table(GF2_IV, GF2_POLY)

	parser = ArgumentParser(description="A script to calculate Xbox 360 challenge responses for XOSC")
	subparsers = parser.add_subparsers(dest="mode")
	calculate_parser = subparsers.add_parser("calculate")
	test_parser = subparsers.add_parser("test")

	args = parser.parse_args()

	match args.mode:
		case "calculate":
			hv_data_dec = read_file("bin/HV_17559_Cleaned.bin")

			white_key = ALL_55_KEY
			aes_key = ALL_55_KEY
			hash_key = ALL_55_KEY

			print("W:", white_key.hex().upper())
			print("A:", aes_key.hex().upper())
			print("H:", hash_key.hex().upper())
			print()

			blob_nonce = b"testtest"

			hvex_addr = 0xB00B
			hv_salt = bytes.fromhex("892BB9F952C7759392A12A3184E0358E")
			white_key = ALL_55_KEY
			aes_key = ALL_55_KEY
			hash_key = ALL_55_KEY

			# white_key = hv_data_dec[0x10100:0x10100 + 0x10]
			# aes_key = hv_data_dec[0x10110:0x10110 + 0x10]
			# hash_key = hv_data_dec[0x10120:0x10120 + 0x10]

			print("W:", white_key.hex().upper())
			print("A:", aes_key.hex().upper())
			print("H:", hash_key.hex().upper())
			print()

			with MemoryCrypto(white_key, aes_key, hash_key) as mem:
				print("Hash 1: " + mem.calc_hash_1_digest(hv_data_dec, hv_salt).hex().upper())
			print()

			with MemoryCrypto(white_key, aes_key, hash_key) as mem:
				print("Hash 2: " + mem.calc_hash_2_digest(hv_data_dec, hv_salt, hvex_addr).hex().upper())
			print()

			with MemoryCrypto(white_key, aes_key, hash_key) as mem:
				print("Key blob: " + mem.calc_key_blob(blob_nonce).hex().upper())
			print()
		case "test":
			keys = read_file("bin/keys.bin")
			white_key = keys[:0x10]
			aes_key = keys[0x10:0x10 + 0x10]
			hash_key = keys[-0x10:]

			hv_enc = read_file("bin/HV.enc.bin")
			with MemoryCrypto(white_key, aes_key, hash_key) as mem:
				write_file("HV.dec.bin", mem.decrypt(hv_enc, 0, len(hv_enc), offset_is_address=True))
		case _:
			pass

	print("Done!")

	return 0

if __name__ == "__main__":
	exit(main())
