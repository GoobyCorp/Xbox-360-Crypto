#!/usr/bin/env python3

__author__ = "Visual Studio"
__description__ = "A script to extract and build shadowboots"
__platforms__ = ["Windows"]
__thanks__ = ["tydye81", "c0z", "golden"]

import re
from io import BytesIO
from json import loads
from pathlib import Path
from os.path import isfile
from binascii import crc32
from argparse import ArgumentParser
from typing import TypeVar, Optional
from struct import pack, unpack_from
from ctypes import sizeof, create_string_buffer

from XeCrypt import *
from StreamIO import *
from build_lib import *
from keystore import load_and_verify_1bl_pub, load_and_verify_sb_prv

BinLike = TypeVar("BinLike", bytes, bytearray, memoryview)

# constants
BIN_DIR = "bin"
XELL_DIR = "XeLL"
BUILD_DIR = Path("Build")
PATCH_DIR = "Patches"
BUILD_VER = 17559
MANIFEST_FILE = "manifest.json"
BUFFER_SIZE = 4096
NOP = 0x60000000

# size defines
HYPERVISOR_SIZE = 0x40000
SMC_CONFIG_SIZE = 280
SHADOWBOOT_SIZE = 0xD4000

# keys
# the 1BL public key
ONE_BL_KEY = load_and_verify_1bl_pub()
# this used to sign the SD and it's public key is in SB
SB_PRV_KEY = load_and_verify_sb_prv()

def checksum_file(filename: str) -> int:
	cksm = 0
	with open(filename, "rb") as f:
		while b := f.read(BUFFER_SIZE):
			cksm = crc32(b, cksm)
	return cksm

def verify_checksum(filename: str, cksm: int) -> bool:
	if cksm == 0 or not isfile(filename):
		return True
	return checksum_file(filename) == cksm

def pad_hex(i: int) -> str:
	h = pack(">I", i).hex()
	while len(h) < 8:
		h = "0" + h
	return h

def path_type(parser: ArgumentParser, value: str) -> Path:
	return Path(value)

def unecc(path: str, block_size: int = 512, spare_size: int = 16) -> bytes:
	with BytesIO() as bio, open(path, "rb") as f:
		f.seek(0, 2)
		size = f.tell()
		f.seek(0)
		while f.tell() < size:
			data = f.read(block_size)
			f.seek(spare_size, 1)
			bio.write(data)
		return bio.getvalue()

class ShadowbootImage:
	# I/O stream
	_stream = None

	# bootloader header map
	img_map = {}

	# headers
	flash_header = None

	# shadowboot data (all decrypted)
	smc_data = None
	smc_config_data = None
	kv_data = None
	sb_data = None
	sc_data = None
	sd_data = None
	se_data = None
	kernel_data = None
	hypervisor_data = None
	patches = []

	# metadata
	# SB
	sb_sig = None
	sb_pub_key = None
	sc_nonce = None
	sc_salt = None
	sd_salt = None
	sd_digest = None
	# SC
	sc_sig = None
	# SD
	sd_sig = None
	sd_pub_key = None
	sf_nonce = None
	sf_salt = None
	se_digest = None
	# bootloaders
	sb_build = None
	sc_build = None
	sd_build = None
	se_build = None
	# kernel
	kernel_version = None
	# HV
	hypervisor_version = None
	# SMC
	console_type = None
	smc_version = None
	# misc.
	is_retal = False
	is_testkit = False

	def __init__(self) -> None:
		self.reset()

	@staticmethod
	def parse(data: (bytes, bytearray), perform_checks: bool = True, parse_patches: bool = True):
		img = ShadowbootImage()

		with BytesIO(data) as img._stream:
			img.flash_header = img.read_header(FLASH_HEADER)

			img.map_shadowboot()

			img.parse_smc()
			img.parse_smc_config()
			img.parse_keyvault()

			img.parse_sb_2bl()

			img.parse_sc_3bl()

			img.parse_sd_4bl()

			img.parse_se_5bl()
			img.decompress_se_5bl()

			img.parse_metadata()

			if parse_patches:
				img.parse_patches()

			if perform_checks:
				if not img.check_signature_sb_2bl():
					raise Exception("Invalid SB signature")
				if not img.check_signature_sc_3bl():
					raise Exception("Invalid SC signature")
				if not img.check_signature_sd_4bl():
					raise Exception("Invalid SD signature")
				if not img.check_hash_sd_4bl():
					raise Exception("Invalid SD digest")
				if not img.check_hash_se_5bl():
					raise Exception("Invalid SE digest")
			
		return img

	@staticmethod
	def create(sb_data: BinLike, sc_data: BinLike, sd_data: BinLike, se_data: BinLike, smc_data: Optional[BinLike] = None, kv_data: Optional[tuple[BinLike, BinLike]] = None, patches: Optional[BinLike] = None, test_kit: Optional[bool] = False, build_version: Optional[int] = BUILD_VER) -> bytes:
		# probably never going to actually implement this since I have building working already
		img = ShadowbootImage()

		new_sb_nonce = XeCryptRandom(0x10)
		new_sb_key = XeCryptHmacSha(XECRYPT_1BL_KEY, new_sb_nonce)[:0x10]

		new_sc_nonce = XeCryptRandom(0x10)
		new_sc_key = XeCryptHmacSha(bytes(0x10), new_sc_nonce)[:0x10]

		new_sd_nonce = XeCryptRandom(0x10)
		new_sd_key = XeCryptHmacSha(new_sc_key, new_sd_nonce)[:0x10]

		new_se_nonce = XeCryptRandom(0x10)
		new_se_key = XeCryptHmacSha(new_sd_key, new_se_nonce)[:0x10]

		sb_hdr = BLHeader.parse(sb_data[:0x20])
		assert sb_hdr.magic == b"SB", "Invalid SB bootloader!"
		sb_data = sb_data[0x20:]

		sc_hdr = BLHeader.parse(sc_data[:0x20])
		assert sc_hdr.magic == b"SC", "Invalid SC bootloader!"
		sc_data = sc_data[0x20:]

		sd_hdr = BLHeader.parse(sd_data[:0x20])
		assert sd_hdr.magic == b"SD", "Invalid SD bootloader!"
		sd_data = sd_data[0x20:]

		se_hdr = BLHeader.parse(se_data[:0x20])
		if se_hdr.magic == b"SE":  # compressed with header
			se_data = decompress_se(se_data)
		else:
			# create header from scratch if one wasn't provided
			se_hdr = BLHeader.parse(pack(">2s 3H I 4x 16x", b"SE", build_version, 0x8000, 0, 0))

		# error if not decompressed properly
		assert se_data[:2] == b"^N", "Invalid SE bootloader!"

		# create NAND header
		flash_header = FLASH_HEADER()
		flash_header.magic = 0xFF4F
		flash_header.build = build_version
		flash_header.qfe = 0x8000
		flash_header.flags = 0

		flash_header.copyright = bytes(create_string_buffer(b"\xA9 2005-2023 Microsoft Corporation. All rights reserved", 0x40))
		flash_header.patch_slots = 2
		flash_header.kv_version = 0x712
		flash_header.patch_slot_size = 0x10000

		sb_hdr.nonce = new_sb_nonce
		sc_hdr.nonce = new_sc_nonce
		sd_hdr.nonce = new_sd_nonce
		se_hdr.nonce = new_se_nonce

		with StreamIO(endian=Endian.BIG) as img:
			# write blank NAND header
			img.set_label("flash_hdr_offs")
			img.write(bytes(sizeof(FLASH_HEADER)))
			img.set_label("flash_hdr_end")

			if smc_data is not None:
				smc_data = XeCryptSmcEncrypt(smc_data)
				img.write(bytes(0x1000 - sizeof(FLASH_HEADER)))
				img.set_label("smc_offs")
				img.write(smc_data)
				img.set_label("smc_end")
				flash_header.smc_offset = 0x1000
				flash_header.smc_length = len(smc_data)
				flash_header.entry = 0x1000 + flash_header.smc_length
			else:
				flash_header.smc_offset = 0x1000
				flash_header.smc_length = 0
				flash_header.entry = sizeof(FLASH_HEADER)

			if kv_data is not None:
				(cpu_key, kv_data) = kv_data
				kv_data = XeCryptKeyVaultEncrypt(cpu_key, kv_data)
				flash_header.kv_offset = 0x4000
				flash_header.kv_length = 0x4000
				img.set_label("kv_offs")
				img.write(kv_data)
				img.set_label("kv_end")
				flash_header.entry += 0x4000
			else:
				flash_header.kv_offset = 0x4000
				flash_header.kv_length = 0

			img.set_label("sb_hdr_offs")
			img.write(bytes(sb_hdr))
			img.set_label("sb_data_offs")
			img.write(sb_data)
			img.set_label("sb_data_end")

			if test_kit:
				img.goto_label("sb_hdr_offs", 0x1348)
				assert img.read(4) == bytes.fromhex("419A0014"), "Original bytes mismatch!"
				img.seek(-4, SEEK_CUR)
				img.write(bytes.fromhex("48000194"))
				img.goto_label("sb_data_end")

			img.set_label("sc_hdr_offs")
			img.write(bytes(sc_hdr))
			img.set_label("sc_data_offs")
			img.write(sc_data)
			img.set_label("sc_data_end")

			img.set_label("sd_hdr_offs")
			img.write(bytes(sd_hdr))
			img.set_label("sd_data_offs")
			img.write(sd_data)
			img.set_label("sd_data_end")

			# apply patches to SE (HV/kernel)
			if patches is not None:
				with BytesIO(se_data) as bio:
					patch_in_place(bio, patches)
					se_data = bio.getvalue()

			se_data = compress_se(se_data, False)
			se_hdr.size = len(se_data) + 0x30
			img.set_label("se_hdr_offs")
			img.write(bytes(se_hdr))
			img.set_label("se_data_offs")
			img.write(pack(">8x I 4x", 0x280000))
			img.write(se_data)
			img.write(bytes(se_hdr.padded_size - se_hdr.size))
			img.set_label("se_data_end")

			se_hash = calc_se_hash_in_place(img, img.get_label("se_hdr_offs"))

			img.goto_label("sd_hdr_offs", 0x24C)
			img.write(se_hash)
			img.seek(0, SEEK_END)

			sign_bldr_in_place(img, img.get_label("sd_hdr_offs"), SB_PRV_KEY)

			encrypt_bldr_in_place(new_sb_key, img, img.get_label("sb_hdr_offs"))
			encrypt_bldr_in_place(new_sc_key, img, img.get_label("sc_hdr_offs"))
			encrypt_bldr_in_place(new_sd_key, img, img.get_label("sd_hdr_offs"))
			encrypt_bldr_in_place(new_se_key, img, img.get_label("se_hdr_offs"))

			img.set_label("size")

			img.write(bytes(calc_pad_size(img.get_label("size"), 0x1000)))

			img.set_label("size")

			# point to right after the shadowboot image (idk if this matters)
			flash_header.sys_upd_addr = img.get_label("size")

			img.seek(0)
			img.write(bytes(flash_header))

			data = img.getvalue()

			if not test_kit:
				ShadowbootImage.parse(data)
				print("Final image verified!")

			return data

	def __enter__(self):
		return self

	def __exit__(self, exc_type, exc_val, exc_tb) -> None:
		pass

	def reset(self) -> None:
		self._stream = None
		self.img_map = {}
		self.flash_header = None
		self.smc_data = None
		self.smc_config_data = None
		self.kv_data = None
		self.sb_data = None
		self.sc_data = None
		self.sd_data = None
		self.se_data = None
		self.kernel_data = None
		self.hypervisor_data = None
		self.patches = []
		self.sb_sig = None
		self.sb_pub_key = None
		self.sc_nonce = None
		self.sc_salt = None
		self.sd_salt = None
		self.sd_digest = None
		self.sc_sig = None
		self.sd_sig = None
		self.sd_pub_key = None
		self.sf_nonce = None
		self.sf_salt = None
		self.se_digest = None
		self.console_type = None
		self.smc_version = None
		self.sb_build = None
		self.sc_build = None
		self.sd_build = None
		self.se_build = None
		self.kernel_version = None
		self.hypervisor_version = None
		self.is_retail = False
		self.is_testkit = False

	def read(self, size: int) -> bytes:
		return self._stream.read(size)

	def write(self, data: BinLike) -> int:
		return self._stream.write(data)

	def seek(self, offset: int, whence: int = SEEK_SET) -> int:
		return self._stream.seek(offset, whence)

	def tell(self) -> int:
		return self._stream.tell()

	def getvalue(self) -> bytes:
		return self._stream.getvalue()

	def read_header(self, header_type):
		return header_type.from_buffer_copy(self._stream.read(sizeof(header_type)))

	def map_shadowboot(self) -> None:
		self.img_map["SMC"] = {"offset": self.flash_header.smc_offset, "size": self.flash_header.smc_length}
		self.img_map["KV"] = {"offset": self.flash_header.kv_offset, "size": self.flash_header.kv_length}
		self._stream.seek(self.flash_header.entry)
		for i in range(4):
			# all of them are the same
			hdr = BLHeader.parse(self._stream.read(0x20))
			bldr_name = hdr.magic.decode("UTF8")
			self.img_map[bldr_name] = {
				"offset": self._stream.tell() - hdr.header_size,
				"size": hdr.size,
				"pad_size": hdr.padded_size,
				"header": hdr
			}

			# derive keys
			if bldr_name == "SB":
				self.img_map[bldr_name]["key"] = XeCryptHmacSha(XECRYPT_1BL_KEY, hdr.nonce)[:0x10]
				self.img_map[bldr_name]["header"]["nonce"] = (b"\x00" * 0x10)
			elif bldr_name == "SC":
				self.img_map[bldr_name]["key"] = XeCryptHmacSha((b"\x00" * 0x10), hdr.nonce)[:0x10]
				self.img_map[bldr_name]["header"]["nonce"] = (b"\x00" * 0x10)
			elif bldr_name == "SD":
				self.img_map[bldr_name]["key"] = XeCryptHmacSha(self.img_map["SC"]["key"], hdr.nonce)[:0x10]
				self.img_map[bldr_name]["header"]["nonce"] = (b"\x00" * 0x10)
			elif bldr_name == "SE":
				self.img_map[bldr_name]["key"] = XeCryptHmacSha(self.img_map["SD"]["key"], hdr.nonce)[:0x10]
				self.img_map[bldr_name]["header"]["nonce"] = (b"\x00" * 0x10)
			# don't seek for the last entry
			if i != 3:
				self._stream.seek(hdr.size - 0x20, 1)

	def parse_smc(self) -> None:
		if self.img_map["SMC"]["offset"] > 0:
			self._stream.seek(self.img_map["SMC"]["offset"])
			self.smc_data = XeCryptSmcDecrypt(self._stream.read(self.img_map["SMC"]["size"]))

	def parse_smc_config(self) -> None:
		if self.flash_header.smc_config_offset > 0:
			self._stream.seek(self.flash_header.smc_config_offset)
			self.smc_config_data = self._stream.read(SMC_CONFIG_SIZE)

	def parse_keyvault(self) -> None:
		if self.img_map["KV"]["offset"] > 0:
			self._stream.seek(self.img_map["KV"]["offset"])
			self.kv_data = self._stream.read(self.img_map["KV"]["size"])

	def parse_sb_2bl(self) -> None:
		# seek to the CB/SB/2BL start
		self._stream.seek(self.img_map["SB"]["offset"] + 0x20)
		# read out the encrypted bytes after the header
		sb_2bl_enc = self._stream.read(self.img_map["SB"]["pad_size"] - 0x20)
		# decrypt the CB/SB/2BL
		sb_2bl_dec = XeCryptRc4.new(self.img_map["SB"]["key"]).decrypt(sb_2bl_enc)
		# prepend the header to the decrypted data
		self.sb_data = bytes(self.img_map["SB"]["header"]) + sb_2bl_dec
		# self.sb_data = self.sb_data[:self.img_map["SB"]["size"]]

	def parse_sc_3bl(self) -> None:
		# seek to the CC/SC/3BL start
		self._stream.seek(self.img_map["SC"]["offset"] + 0x20)
		# read out the encrypted bytes after the header
		sc_3bl_enc = self._stream.read(self.img_map["SC"]["pad_size"] - 0x20)
		# decrypt the CC/SC/3BL
		sc_3bl_dec = XeCryptRc4.new(self.img_map["SC"]["key"]).decrypt(sc_3bl_enc)
		# prepend the header to the decrypted data
		self.sc_data = bytes(self.img_map["SC"]["header"]) + sc_3bl_dec
		# self.sc_data = self.sc_data[:self.img_map["SC"]["size"]]

	def parse_sd_4bl(self) -> None:
		# seek to the CD/SD/4BL start
		self._stream.seek(self.img_map["SD"]["offset"] + 0x20)
		# read out the encrypted bytes after the header
		sd_4bl_enc = self._stream.read(self.img_map["SD"]["pad_size"] - 0x20)
		# decrypt the CD/SD/4BL
		sd_4bl_dec = XeCryptRc4.new(self.img_map["SD"]["key"]).decrypt(sd_4bl_enc)
		# prepend the header to the decrypted data
		self.sd_data = bytes(self.img_map["SD"]["header"]) + sd_4bl_dec
		# self.sd_data = self.sd_data[:self.img_map["SD"]["size"]]

	def parse_se_5bl(self) -> None:
		# seek to the CE/SE/5BL start
		self._stream.seek(self.img_map["SE"]["offset"] + 0x20)
		# read out the encrypted bytes after the header
		se_5bl_enc = self._stream.read(self.img_map["SE"]["size"] - 0x20)
		# decrypt the CE/SE/5BL
		se_5bl_dec = XeCryptRc4.new(self.img_map["SE"]["key"]).decrypt(se_5bl_enc)
		# prepend the header to the decrypted data
		self.se_data = bytes(self.img_map["SE"]["header"]) + se_5bl_dec
		# self.se_data = self.se_data[:self.img_map["SE"]["size"]]

	def decompress_se_5bl(self) -> None:
		# (size,) = unpack_from(">I", self.se_data, 12)
		data = decompress_se(self.se_data)
		self.hypervisor_data = data[:HYPERVISOR_SIZE]
		self.kernel_data = data[HYPERVISOR_SIZE:]

	def parse_hypervisor(self) -> None:
		with BytesIO(self.hypervisor_data) as bio:
			bio.seek(0x105B8)  # dev PIRS public key
			bio.seek(0x106C8)  # expansion public key
			bio.seek(0x10A18)  # XMACS public key
			bio.seek(0x11008)  # master public key
			bio.seek(0x11988)  # retail PIRS public key

	def parse_patches(self) -> None:
		bldr_end = bytes.fromhex("4BFFFFB0000000000000000000000000")
		end_loc = self.sd_data.find(bldr_end) + len(bldr_end)
		if end_loc == -1 or end_loc == len(self.sd_data):  # no patches
			return
		#bldr_end = bytes.fromhex("386000004E8000200000000000000000")
		#end_loc = self.sd_data.find(bldr_end) + len(bldr_end)
		#if end_loc == -1 or end_loc == len(self.sd_data):  # no patches
		#	return
		# if not self.sd_data.endswith(bytes.fromhex("FFFFFFFF")):  # patches not available
		# 	return

		# print("Patches found!")
		with StreamIO(self.sd_data, Endian.BIG) as sio:
			sio.seek(end_loc)  # not static by any means
			patch_loader = sio.read_ubytes(0x40)  # the loader code for patches
			self.patches.append({"offset": end_loc, "size_bytes": len(patch_loader), "patch_loader": patch_loader})
			while True:
				offset = sio.tell()
				address = sio.read_uint32()
				if address == 0xFFFFFFFF:  # end of patches
					break
				size_int32 = sio.read_uint32()
				size_bytes = size_int32 * 4
				patch_code = sio.read_ubytes(size_bytes)
				whole_patch = pack(">2I", address, size_int32) + patch_code
				self.patches.append({"offset": offset, "address": address, "size_int32": size_int32, "size_bytes": (size_bytes * 4), "patch_code": patch_code, "whole_patch": whole_patch})

	def parse_metadata(self) -> None:
		# SB
		self.sb_sig = self.sb_data[64:64 + 256]
		self.sb_pub_key = XeCryptRsaKey(self.sb_data[616:616 + 272])  # verifies SC and SD
		self.sc_nonce = self.sb_data[888:888 + 0x10]
		self.sc_salt = self.sb_data[904:904 + 0xA]
		self.sd_salt = self.sb_data[914:914 + 0xA]
		self.sd_digest = self.sb_data[924:924 + 0x14]
		# SC
		self.sc_sig = self.sc_data[32:32 + 256]
		# SD
		self.sd_sig = self.sd_data[32:32 + 256]
		self.sd_pub_key = XeCryptRsaKey(self.sd_data[288:288 + 272])  # verifies SE
		self.sf_nonce = self.sd_data[560:560 + 0x10]
		self.sf_salt = self.sd_data[576:576 + 0xA]
		self.se_digest = self.sd_data[588:588 + 0x14]
		# SMC and kernel
		if self.smc_data is not None and self.smc_data != b"":
			num = self.smc_data[256]
			self.console_type = [
				"Error",
				"Xenon",
				"Zephyr",
				"Falcon",
				"Jasper",
				"Trinity",
				"Corona",
				"Winchester",
				"unknown",
				"unknown"
			][num >> 4 & 15]
			self.smc_version = f"{num >> 4 & 15}.{num & 15} ({self.smc_data[257]}.{self.smc_data[258]})"
		# (self.kernel_version,) = unpack_from(">H", self.kernel_data, 0x40C)
		self.sb_build = self.img_map["SB"]["header"]["build"]
		self.sc_build = self.img_map["SC"]["header"]["build"]
		self.sd_build = self.img_map["SD"]["header"]["build"]
		self.se_build = self.img_map["SE"]["header"]["build"]
		(self.hypervisor_version,) = unpack_from(">H", self.hypervisor_data, 0x2)
		self.kernel_version = self.se_build
		self.is_retail = self.hypervisor_data[0] == 0x4E
		self.is_testkit = bytes.fromhex("5C746573746B69745C") in self.kernel_data

	def check_signature_sb_2bl(self) -> bool:
		sb_hash = XeCryptRotSumSha(self.sb_data[:0x10] + self.sb_data[0x140:])  # skips the nonce and signature
		return ONE_BL_KEY.sig_verify(self.sb_sig, sb_hash, XECRYPT_1BL_SALT)

	def check_signature_sc_3bl(self) -> bool:
		sc_hash = XeCryptRotSumSha(self.sc_data[:0x10] + self.sc_data[0x120:])  # skips the nonce and signature
		return self.sb_pub_key.sig_verify(self.sc_sig, sc_hash, self.sc_salt)

	def check_signature_sd_4bl(self) -> bool:
		sd_hash = XeCryptRotSumSha(self.sd_data[:0x10] + self.sd_data[0x120:])  # skips the nonce and signature
		return self.sb_pub_key.sig_verify(self.sd_sig, sd_hash, self.sd_salt)

	def check_hash_sd_4bl(self) -> bool:
		if self.sd_digest != bytes(len(self.sd_digest)):
			return XeCryptRotSumSha(self.sd_data[:0x10] + self.sd_data[0x20:]) == self.sd_digest
		return True

	def check_hash_se_5bl(self) -> bool:
		if self.se_digest != bytes(len(self.se_digest)):
			return XeCryptRotSumSha(self.se_data[:0x10] + self.se_data[0x20:] + bytes(calc_bldr_pad_size(len(self.se_data)))) == self.se_digest
		return True

	def print_info(self) -> None:
		print(f"Console Type:   {self.console_type}")
		print(f"SMC Version:    {self.smc_version}")
		print(f"SB Version:     {self.sb_build}")
		print(f"SC Version:     {self.sc_build}")
		print(f"SD Version:     {self.sd_build}")
		print(f"SE Version:     {self.se_build}")
		print(f"HV Version:     {self.hypervisor_version}")
		print(f"Kernel Version: {self.kernel_version}")

		if self.is_retail:
			print("Main Menu:      Dashboard")
		else:
			print("Main Menu:      XShell")

		if self.is_testkit:
			print("Hardware:       Test Kit")
		else:
			print("Hardware:       Development Kit")

def main() -> int:
	global MANIFEST_FILE, ONE_BL_KEY, SB_PRV_KEY

	parser = ArgumentParser(description=__description__)
	subparsers = parser.add_subparsers(dest="command")

	build_parser = subparsers.add_parser("build")
	# build_parser.add_argument("input", type=str, help="The input path")
	build_parser.add_argument("output", type=lambda x: path_type(build_parser, x), help="The output path")
	build_parser.add_argument("--nochecks", action="store_true", help="Perform shadowboot parsing without integrity checks")
	build_parser.add_argument("-m", "--manifest", type=lambda x: path_type(build_parser, x), help="The build manifest file")
	build_parser.add_argument("-b", "--build-dir", type=lambda x: path_type(build_parser, x), help="The build directory path")

	extract_parser = subparsers.add_parser("extract")
	extract_parser.add_argument("input", type=lambda x: path_type(extract_parser, x), help="The input path")
	extract_parser.add_argument("output", type=lambda x: path_type(extract_parser, x), help="The output path")
	# extract_parser.add_argument("--nochecks", action="store_true", help="Extract without doing sanity checks")
	# extract_parser.add_argument("--raw", action="store_true", help="No decryption performed")
	extract_parser.add_argument("--flash", action="store_true", help="Parse a flash image instead of a shadowboot")
	extract_parser.add_argument("--nochecks", action="store_true", help="Perform shadowboot parsing without integrity checks")
	extract_parser.add_argument("--all", action="store_true", help="Extract all sections")
	extract_parser.add_argument("--smc", action="store_true", help="Extract the SMC")
	extract_parser.add_argument("--keyvault", "--kv", action="store_true", help="Extract the keyvault")
	extract_parser.add_argument("--sb", action="store_true", help="Extract the SB")
	extract_parser.add_argument("--sc", action="store_true", help="Extract the SC")
	extract_parser.add_argument("--sd", action="store_true", help="Extract the SD")
	extract_parser.add_argument("--se", action="store_true", help="Extract the SE")
	extract_parser.add_argument("--kernel", action="store_true", help="Extract the kernel")
	extract_parser.add_argument("--hypervisor", "--hv", action="store_true", help="Extract the hypervisor")
	extract_parser.add_argument("--loader", action="store_true", help="Extract HV/kernel patch loader")
	extract_parser.add_argument("--patches", action="store_true", help="Extract HV/kernel patches")

	info_parser = subparsers.add_parser("info")
	info_parser.add_argument("input", type=lambda x: path_type(info_parser, x), help="The input path")
	info_parser.add_argument("--flash", action="store_true", help="Parse a flash image instead of a shadowboot")
	info_parser.add_argument("--nochecks", action="store_true", help="Perform shadowboot parsing without integrity checks")

	split_parser = subparsers.add_parser("split")
	split_parser.add_argument("input", type=lambda x: path_type(info_parser, x), help="The input path")
	split_parser.add_argument("output", type=lambda x: path_type(extract_parser, x), help="The output path")
	split_parser.add_argument("-k", "--kernel", type=int, help="The kernel version")
	split_parser.add_argument("-r", "--revision", choices=["xenon", "zephyr", "falcon", "jasper", "trinity", "corona", "winchester"], help="The console revision")
	split_parser.add_argument("-t", "--type", choices=["retail", "testkit", "devkit"], help="The console type")
	split_parser.add_argument("--nochecks", action="store_true", help="Perform shadowboot parsing without integrity checks")

	test_parser = subparsers.add_parser("test")
	test_parser.add_argument("input", type=lambda x: path_type(test_parser, x), help="The input path")
	test_parser.add_argument("output", type=lambda x: path_type(test_parser, x), help="The output path")
	test_parser.add_argument("--nochecks", action="store_true", help="Perform shadowboot parsing without integrity checks")

	args = parser.parse_args()

	if args.command == "build":
		if args.manifest.is_file():  # building with a manifest file
			# load the manifest file
			print("Loading build manifest...")
			build_manifest = loads(args.manifest.read_text())

			# remove comments
			del build_manifest["_comment"]
			del build_manifest["build"]["_comment"]
			del build_manifest["options"]["_comment"]
			del build_manifest["files"]["_comment"]

			# paths
			print("Setting up paths...")
			bd = Path(build_manifest["files"]["base_directory"])
			base_img_file = Path(build_manifest["files"]["base_image"])
			smc_bin_file = bd /  build_manifest["files"]["SMC"]
			# smc_cfg_file = bd /  build_manifest["files"]["SMC_config"]
			kv_file = bd / build_manifest["files"]["KV"]
			sb_file = bd / build_manifest["files"]["SB"]
			sc_file = bd / build_manifest["files"]["SC"]
			sd_file = bd / build_manifest["files"]["SD"]
			se_file = bd / build_manifest["files"]["SE"]
			kernel_file = bd / build_manifest["files"]["kernel"]
			hypervisor_file = bd / build_manifest["files"]["HV"]
			# sd_patches_file = bd / build_manifest["files"]["SD_patches"]
			# sd_code_file = bd / build_manifest["files"]["SD_code"]
			hvk_patches_file = bd / build_manifest["files"]["HVK_patches"]
		elif args.build_dir is not None:  # using a build directory vs a manifest
			smc_bin_file = args.build_dir / "SMC_dec.bin"
			# smc_cfg_file = args.build_dir / "SMC_config.bin"
			kv_file = args.build_dir / "KV_dec.bin"
			sb_file = args.build_dir / "sb.bin"
			sc_file = args.build_dir / "sc.bin"
			sd_file = args.build_dir / "sd.bin"
			se_file = args.build_dir / "se.bin"
			kernel_file = args.build_dir / "kernel.bin"
			hypervisor_file = args.build_dir / "hypervisor.bin"
			base_img_file = args.build_dir / "xboxrom.bin"

			# patches
			# sd_code_file = args.build_dir / "sdc.bin"  # SD code file
			# sd_patches_file = args.build_dir / "sdp.bin"  # SD patches file
			hvk_patches_file = args.build_dir / "hvk.bin"
		else:
			print("Building requires -m or -b arguments!")
			return 1

		# check for the base image and load it if it exists
		base_img = None
		base_img_available = base_img_file.is_file()
		if base_img_available:
			base_img = ShadowbootImage.parse(base_img_file.read_bytes(), not build_manifest["options"]["base_image_checks_disabled"])

		if kernel_file.is_file() and hypervisor_file.is_file():
			print("Reading raw HV/kernel...")
			kernel = kernel_file.read_bytes()
			hypervisor = hypervisor_file.read_bytes()
			se_data = hypervisor + kernel
		elif se_file.is_file():
			print("Decompressing SE...")
			se_data = decompress_se(se_file.read_bytes())
		elif base_img_available:
			print("Reading HV/kernel from base image...")
			se_data = base_img.hypervisor_data + base_img.kernel_data
		else:
			raise Exception("No HV/kernel pair, SE, or fallback image was provided!")

		data = ShadowbootImage.create(
			try_read_sources(sb_file, base_img.sb_data),
			try_read_sources(sc_file, base_img.sc_data),
			try_read_sources(sd_file, base_img.sd_data),
			se_data,
			try_read_sources(smc_bin_file, base_img.smc_data) if build_manifest["options"]["use_smc"] else None,
			(bytes(0x10), try_read_sources(kv_file, base_img.kv_data)) if build_manifest["options"]["use_kv"] else None,
			try_read_sources(hvk_patches_file),
			build_manifest["options"]["test_kit"],
			build_manifest["build"]["version"]
		)
		args.output.write_bytes(data)

		print(f"Final image location: \"{str(args.output.absolute())}\"")
	elif args.command == "extract":
		if args.flash:
			img = ShadowbootImage.parse(unecc(str(args.input)), not args.nochecks)
		else:
			img = ShadowbootImage.parse(args.input.read_bytes(), not args.nochecks)

		img.print_info()

		if args.all or args.smc:
			if img.smc_data is not None and len(img.smc_data) > 0:
				(args.output / "SMC_dec.bin").write_bytes(img.smc_data)
		# if args.all or args.smc_config:
		# 	(args.output / "smc_config.bin").write_bytes(img.smc_config_data)
		if args.all or args.keyvault:
			if img.kv_data is not None and len(img.kv_data) > 0:
				(args.output / "KV_enc.bin").write_bytes(img.kv_data)
		if args.all or args.sb:
			(args.output / f"sb_{img.sb_build}.bin").write_bytes(img.sb_data)
		if args.all or args.sc:
			(args.output / f"sc_{img.sc_build}.bin").write_bytes(img.sc_data)
		if args.all or args.sd:
			(args.output / f"sd_{img.sd_build}.bin").write_bytes(img.sd_data)
		if args.all or args.se:
			(args.output / f"se_{img.se_build}.bin").write_bytes(img.se_data)
		if args.all or args.kernel:
			(args.output / "kernel.exe").write_bytes(img.kernel_data)
		if args.all or args.hypervisor:
			(args.output / "hypervisor.bin").write_bytes(img.hypervisor_data)
		if args.all or args.loader:
			if len(img.patches) > 0:
				(args.output / "patch_loader.bin").write_bytes(img.patches[0]["patch_loader"])
			else:
				print("No patch loader found!")
		if args.all or args.patches:
			if len(img.patches) > 1:
				if not (args.output / "Patches").is_dir():
					(args.output / "Patches").mkdir()

				for patch in img.patches[1:]:
					addr = patch["address"]
					if addr > HYPERVISOR_SIZE:
						addr += 0x80000000
					(args.output / "Patches" / f"{addr:08X}.bin").write_bytes(patch["patch_code"])

				combined = b""
				for patch in img.patches[1:]:
					combined += pack(">2I", patch["address"], patch["size_int32"])
					combined += patch["patch_code"]
				combined += (b"\xFF" * 4)

				(args.output / "patches_raw.bin").write_bytes(combined)
			else:
				print("No patches found!")
	elif args.command == "info":
		if args.flash:
			img = ShadowbootImage.parse(unecc(str(args.input)), not args.nochecks)
		else:
			img = ShadowbootImage.parse(args.input.read_bytes(), not args.nochecks)
		img.print_info()
	elif args.command == "split":
		# cabextract -p --filter "KERNEL/*" XDK_0.cab > images.bin

		image_data = args.input.read_bytes()
		IMAGE_EXP = re.compile(rb"Microsoft Corporation\. All rights reserved")
		idxs = [m.start() - 28 for m in IMAGE_EXP.finditer(image_data)]
		for i in range(0, len(idxs)):
			if idxs[i] == idxs[-1]:  # last entry
				data = image_data[idxs[i]:]
			else:  # other entries
				data = image_data[idxs[i]:idxs[i + 1]]
			img = ShadowbootImage.parse(data, not args.nochecks, False)

			if img.is_retail and args.type == "retail":
				if img.kernel_version == args.kernel == img.hypervisor_version:
					if img.console_type.lower() == args.revision.lower():
						(args.output / "xboxromw2d.bin").write_bytes(data)
						print("Found!")
						break
			elif img.is_testkit and args.type == "testkit":
				if img.kernel_version == args.kernel == img.hypervisor_version:
					if img.console_type.lower() == args.revision.lower():
						(args.output / "xboxromtw2d.bin").write_bytes(data)
						print("Found!")
						break
			elif not img.is_testkit and not img.is_retail and args.type == "devkit":
				if img.kernel_version == args.kernel == img.hypervisor_version:
					if img.console_type.lower() == args.revision.lower():
						(args.output / "xboxromw2d.bin").write_bytes(data)
						print("Found!")
						break
	elif args.command == "test":
		pass

	return 0

if __name__ == "__main__":
	exit(main())
