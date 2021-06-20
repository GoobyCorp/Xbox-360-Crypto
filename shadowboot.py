#!/usr/bin/env python3

__author__ = "Visual Studio"
__description__ = "A script to extract and build shadowboots"
__platforms__ = ["Windows"]
__thanks__ = ["tydye81", "c0z", "golden"]

from io import BytesIO
from json import loads
from binascii import crc32
from ctypes import sizeof, c_ubyte
from argparse import ArgumentParser
from struct import pack, pack_into, unpack_from
from os.path import abspath, isdir, isfile, join

from XeCrypt import *
from StreamIO import *
from build_lib import *

# constants
BIN_DIR = "bin"
XELL_DIR = "XeLL"
BUILD_DIR = "Build"
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
ONE_BL_KEY = None
SD_PRV_KEY = None

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

class ShadowbootImage:
	# I/O stream
	_stream = None

	# bootloader header map
	img_map = {}

	# headers
	nand_header = None

	# shadowboot data (all decrypted)
	smc_data = None
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

	def __init__(self) -> None:
		self.reset()

	@staticmethod
	def parse(data: (bytes, bytearray), checks: bool = True):
		img = ShadowbootImage()

		with BytesIO(data) as img._stream:
			img.nand_header = img.read_header(NAND_HEADER)

			img.map_shadowboot()

			img.parse_smc()
			#self.extract_smc_config()
			img.parse_keyvault()

			img.parse_sb_2bl()

			img.parse_sc_3bl()

			img.parse_sd_4bl()

			img.parse_se_5bl()
			img.decompress_se_5bl()

			img.parse_metadata()

			# img.parse_patches()

			if checks:
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
	def create():
		# probably never going to actually implement this since I have building working already

		new_sb_nonce = XeCryptRandom(0x10)
		new_sb_key = XeCryptHmacSha(XECRYPT_1BL_KEY, new_sb_nonce)[:0x10]

		new_sc_nonce = XeCryptRandom(0x10)
		new_sc_key = XeCryptHmacSha((b"\x00" * 0x10), new_sc_nonce)[:0x10]

		new_sd_nonce = XeCryptRandom(0x10)
		new_sd_key = XeCryptHmacSha(new_sc_key, new_sd_nonce)[:0x10]

		new_se_nonce = XeCryptRandom(0x10)
		new_se_key = XeCryptHmacSha(new_sd_key, new_se_nonce)[:0x10]

	def __enter__(self):
		return self

	def __exit__(self, exc_type, exc_val, exc_tb) -> None:
		pass

	def reset(self) -> None:
		self._stream = None
		self.img_map = {}
		self.nand_header = None
		self.smc_data = None
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

	def read_header(self, header_type):
		return header_type.from_buffer_copy(self._stream.read(sizeof(header_type)))

	def map_shadowboot(self) -> None:
		self.img_map["SMC"] = {"offset": self.nand_header.smc_offset, "size": self.nand_header.smc_length}
		self.img_map["KV"] = {"offset": self.nand_header.kv_offset, "size": self.nand_header.kv_length}
		self._stream.seek(self.nand_header.cb_offset)
		for i in range(4):
			header = self.read_header(SB_2BL_HEADER)  # all of them are the same
			bl_name = bytes(header.header.magic).decode("utf8")
			self.img_map[bl_name] = {"offset": self._stream.tell() - sizeof(header), "size": header.header.size, "header": header, "orig_nonce": bytes(header.nonce)}
			if i != 3:  # don't seek for the last entry
				self._stream.seek(header.header.size - 0x20, 1)

	def parse_smc(self) -> None:
		if self.img_map["SMC"]["offset"] > 0:
			self._stream.seek(self.img_map["SMC"]["offset"])
			self.smc_data = XeCryptSmcDecrypt(self._stream.read(self.img_map["SMC"]["size"]))

	#def extract_smc_config(self) -> None:
	#    self._stream.seek(self.nand_header.smc_config_offset)
	#    self.smc_config_data = self._stream.read(SMC_CONFIG_SIZE)

	def parse_keyvault(self) -> None:
		if self.img_map["KV"]["offset"] > 0:
			self._stream.seek(self.img_map["KV"]["offset"])
			self.kv_data = self._stream.read(self.img_map["KV"]["size"])

	def parse_sb_2bl(self) -> None:
		# seek to the CB/SB/2BL start
		self._stream.seek(self.img_map["SB"]["offset"] + sizeof(self.img_map["SB"]["header"]))
		# 16-byte alignment
		self.img_map["SB"]["pad_size"] = (self.img_map["SB"]["size"] + 0xF) & ~0xF
		# read out the encrypted bytes after the header
		SB_2BL_ENC = self._stream.read(self.img_map["SB"]["size"] - sizeof(self.img_map["SB"]["header"]))
		# generate the new RC4 key with the 1BL key as the key and the SB's nonce as the data
		SB_2BL_KEY = XeCryptHmacSha(XECRYPT_1BL_KEY, bytes(self.img_map["SB"]["header"].nonce))[:0x10]
		# decrypt the CB/SB/2BL
		SB_2BL_DEC = XeCryptRc4Ecb(SB_2BL_KEY, SB_2BL_ENC)
		# recreate the CB/SB/2BL header
		self.img_map["SB"]["header"].nonce = (c_ubyte * 0x10).from_buffer_copy(SB_2BL_KEY)
		# prepend the header to the decrypted data
		self.sb_data = bytes(self.img_map["SB"]["header"]) + SB_2BL_DEC + (b"\x00" * (self.img_map["SB"]["pad_size"] - self.img_map["SB"]["size"]))

	def parse_sc_3bl(self) -> None:
		# seek to the CC/SC/3BL start
		self._stream.seek(self.img_map["SC"]["offset"] + sizeof(self.img_map["SC"]["header"]))
		# 16-byte alignment
		self.img_map["SC"]["pad_size"] = (self.img_map["SC"]["size"] + 0xF) & ~0xF
		# read out the encrypted bytes after the header
		SC_3BL_ENC = self._stream.read(self.img_map["SC"]["size"] - sizeof(self.img_map["SC"]["header"]))
		# generate the new RC4 key with 0x10 null bytes as the key and the SC's nonce as the data
		SC_3BL_KEY = XeCryptHmacSha((b"\x00" * 0x10), bytes(self.img_map["SC"]["header"].nonce))[:0x10]  # uses a 0x10 length null key to in CC/SC/3BL
		# decrypt the CC/SC/3BL
		SC_3BL_DEC = XeCryptRc4Ecb(SC_3BL_KEY, SC_3BL_ENC)
		# recreate the CC/SC/3BL header
		self.img_map["SC"]["header"].nonce = (c_ubyte * 0x10).from_buffer_copy(SC_3BL_KEY)
		# prepend the header to the decrypted data
		self.sc_data = bytes(self.img_map["SC"]["header"]) + SC_3BL_DEC + (b"\x00" * (self.img_map["SC"]["pad_size"] - self.img_map["SC"]["size"]))

	def parse_sd_4bl(self) -> None:
		# seek to the CD/SD/4BL start
		self._stream.seek(self.img_map["SD"]["offset"] + sizeof(self.img_map["SD"]["header"]))
		# 16-byte alignment
		self.img_map["SD"]["pad_size"] = (self.img_map["SD"]["size"] + 0xF) & ~0xF
		# read out the encrypted bytes after the header
		SD_4BL_ENC = self._stream.read(self.img_map["SD"]["size"] - sizeof(self.img_map["SD"]["header"]))
		# generate the new RC4 key with the SC's nonce as the key and the SD's nonce as the data
		SD_4BL_KEY = XeCryptHmacSha(bytes(self.img_map["SC"]["header"].nonce), bytes(self.img_map["SD"]["header"].nonce))[:0x10]
		# decrypt the CD/SD/4BL
		SD_4BL_DEC = XeCryptRc4Ecb(SD_4BL_KEY, SD_4BL_ENC)
		# recreate the CD/SD/4BL header
		self.img_map["SD"]["header"].nonce = (c_ubyte * 0x10).from_buffer_copy(SD_4BL_KEY)
		# prepend the header to the decrypted data
		self.sd_data = bytes(self.img_map["SD"]["header"]) + SD_4BL_DEC + (b"\x00" * (self.img_map["SD"]["pad_size"] - self.img_map["SD"]["size"]))

	def parse_se_5bl(self) -> None:
		# seek to the CE/SE/5BL start
		self._stream.seek(self.img_map["SE"]["offset"] + sizeof(self.img_map["SE"]["header"]))
		# calculate padding
		self.img_map["SE"]["pad_size"] = (self.img_map["SE"]["size"] + 0xF) & ~0xF
		# read out the encrypted bytes after the header
		SE_5BL_ENC = self._stream.read(self.img_map["SE"]["size"] - sizeof(self.img_map["SE"]["header"]))
		# generate the new RC4 key with the SD's nonce as the key and the SE's nonce as the data
		SE_5BL_KEY = XeCryptHmacSha(bytes(self.img_map["SD"]["header"].nonce), bytes(self.img_map["SE"]["header"].nonce))[:0x10]
		# decrypt the CE/SE/5BL
		SE_5BL_DEC = XeCryptRc4Ecb(SE_5BL_KEY, SE_5BL_ENC)
		# recreate the CE/SE/5BL header
		self.img_map["SE"]["header"].nonce = (c_ubyte * 0x10).from_buffer_copy(SE_5BL_KEY)
		# prepend the header to the decrypted data
		self.se_data = bytes(self.img_map["SE"]["header"]) + SE_5BL_DEC + (b"\x00" * (self.img_map["SE"]["pad_size"] - self.img_map["SE"]["size"]))

	def decompress_se_5bl(self) -> None:
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
		bl_end = bytes.fromhex("4BFFFFB0000000000000000000000000")
		end_loc = self.sd_data.find(bl_end) + len(bl_end)
		if end_loc == -1 or end_loc == len(self.sd_data):  # no patches
			return
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
		self.sb_pub_key = self.sb_data[616:616 + 272]  # verifies SC and SD
		self.sc_nonce = self.sb_data[888:888 + 0x10]
		self.sc_salt = self.sb_data[904:904 + 0xA]
		self.sd_salt = self.sb_data[914:914 + 0xA]
		self.sd_digest = self.sb_data[924:924 + 0x14]
		# SC
		self.sc_sig = self.sc_data[32:32 + 256]
		# SD
		self.sd_sig = self.sd_data[32:32 + 256]
		self.sd_pub_key = self.sd_data[288:288 + 272]  # verifies SE
		self.sf_nonce = self.sd_data[560:560 + 0x10]
		self.sf_salt = self.sd_data[576:576 + 0xA]
		self.se_digest = self.sd_data[588:588 + 0x14]
		# SMC and kernel
		if self.smc_data is not None:
			num = self.smc_data[256]
			self.console_type = [
				"Error",
				"Xenon",
				"Zephyr",
				"Falcon",
				"Jasper",
				"Trinity",
				"Corona",
				"Winchester"
			][num >> 4 & 15]
			self.smc_version = f"{num >> 4 & 15}.{num & 15} ({self.smc_data[257]}.{self.smc_data[258]})"
		# (self.kernel_version,) = unpack_from(">H", self.kernel_data, 0x40C)
		self.sb_build = self.img_map["SB"]["header"].header.build
		self.sc_build = self.img_map["SC"]["header"].header.build
		self.sd_build = self.img_map["SD"]["header"].header.build
		self.se_build = self.img_map["SE"]["header"].header.build
		(self.hypervisor_version,) = unpack_from(">H", self.hypervisor_data, 0x10)
		self.kernel_version = self.se_build

	def check_signature_sb_2bl(self) -> bool:
		sb_hash = XeCryptRotSumSha(self.sb_data[:0x10] + self.sb_data[0x140:])  # skips the nonce and signature
		assert len(ONE_BL_KEY) == XECRYPT_RSAPUB_2048_SIZE, "Invalid 1BL public key size"
		return XeCryptBnQwBeSigVerify(self.sb_sig, sb_hash, XECRYPT_1BL_SALT, ONE_BL_KEY)

	def check_signature_sc_3bl(self) -> bool:
		sc_hash = XeCryptRotSumSha(self.sc_data[:0x10] + self.sc_data[0x120:])  # skips the nonce and signature
		assert len(self.sb_pub_key) == XECRYPT_RSAPUB_2048_SIZE, "Invalid SB public key size"
		return XeCryptBnQwBeSigVerify(self.sc_sig, sc_hash, self.sc_salt, self.sb_pub_key)

	def check_signature_sd_4bl(self) -> bool:
		sd_hash = XeCryptRotSumSha(self.sd_data[:0x10] + self.sd_data[0x120:])  # skips the nonce and signature
		assert len(self.sb_pub_key) == XECRYPT_RSAPUB_2048_SIZE, "Invalid SB public key size"
		return XeCryptBnQwBeSigVerify(self.sd_sig, sd_hash, self.sd_salt, self.sb_pub_key)

	def check_hash_sd_4bl(self) -> bool:
		if self.sd_digest != b"\x00" * len(self.sd_digest):
			return XeCryptRotSumSha(self.sd_data[:0x10] + self.sd_data[0x20:]) == self.sd_digest
		return True

	def check_hash_se_5bl(self) -> bool:
		if self.sd_digest != b"\x00" * len(self.se_digest):
			return XeCryptRotSumSha(self.se_data[:0x10] + self.se_data[0x20:]) == self.se_digest
		return True

def main() -> None:
	global MANIFEST_FILE, ONE_BL_KEY, SD_PRV_KEY

	parser = ArgumentParser(description=__description__)
	subparsers = parser.add_subparsers(dest="command")

	build_parser = subparsers.add_parser("build")
	# build_parser.add_argument("input", type=str, help="The input path")
	build_parser.add_argument("output", type=str, help="The output path")
	build_parser.add_argument("-m", "--manifest", type=str, help="The build manifest file")

	extract_parser = subparsers.add_parser("extract")
	extract_parser.add_argument("input", type=str, help="The input path")
	extract_parser.add_argument("output", type=str, help="The output path")
	extract_parser.add_argument("--nochecks", action="store_true", help="Extract without doing sanity checks")
	# extract_parser.add_argument("--raw", action="store_true", help="No decryption performed")
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
	info_parser.add_argument("input", type=str, help="The input path")

	test_parser = subparsers.add_parser("test")
	test_parser.add_argument("input", type=str, help="The input path")
	test_parser.add_argument("output", type=str, help="The output path")

	args = parser.parse_args()

	#if hasattr(args, "input") and args.input:
	#	assert isfile(args.input) or isdir(args.input), "The specified input path or directory doesn't exist"
	# if hasattr(args, "output") and args.output:
	#	assert isfile(args.output) or isdir(args.output), "The specified output path or directory doesn't exist"

	#sb = ShadowbootImage(read_file("C://Users/John/Desktop/xboxrom_13146_patched.bin"), False)
	#write_file("C://Users/John/Desktop/hv.bin", sb.hypervisor_data)
	#write_file("C://Users/John/Desktop/kernel.exe", sb.kernel_data)
	#exit(0)

	# the 1BL public key
	ONE_BL_KEY = read_file("Keys/1BL_pub.bin")
	assert crc32(ONE_BL_KEY) == 0xD416B5E1, "Invalid 1BL public key"

	# this used to sign the SD and it's public key is in SB
	SD_PRV_KEY = read_file("Keys/SD_prv.bin")
	assert crc32(SD_PRV_KEY) == 0x490C9D35, "Invalid SD private key"

	if args.command == "build":
		# load the manifest file
		print("Loading build manifest...")
		build_manifest = loads(read_file(args.manifest, True))

		# remove comments
		del build_manifest["_comment"]
		del build_manifest["build"]["_comment"]
		del build_manifest["options"]["_comment"]
		del build_manifest["files"]["_comment"]

		# settings
		test_kit_compile = build_manifest["options"]["test_kit"]
		sd_code_enabled = build_manifest["options"]["SD_code_enabled"]
		sd_patches_enabled = build_manifest["options"]["SD_patches_enabled"]

		# paths
		print("Setting up paths...")
		base_dir = join(BUILD_DIR, build_manifest["files"]["base_directory"])
		base_img_file = join(base_dir, build_manifest["files"]["base_image"])
		sb_file = join(base_dir, build_manifest["files"]["SB"])
		sc_file = join(base_dir, build_manifest["files"]["SC"])
		sd_file = join(base_dir, build_manifest["files"]["SD"])
		se_file = join(base_dir, build_manifest["files"]["SE"])
		kernel_file = join(base_dir, build_manifest["files"]["kernel"])
		hypervisor_file = join(base_dir, build_manifest["files"]["HV"])
		sd_patches_file = join(base_dir, build_manifest["files"]["SD_patches"])
		sd_code_file = join(base_dir, build_manifest["files"]["SD_code"])
		hvk_patches_file = join(base_dir, build_manifest["files"]["HVK_patches"])
		# patch_loader_file = join("bin/loaders", "patch_loader.bin")

		# check build manifest files
		print("Verifying checksums...")

		all_files_available = True
		for (key, value) in build_manifest["files"].items():
			if not key.endswith("_checksum"):
				if value != "":
					if key == "base_image":
						if not isfile(value):
							all_files_available = False
					elif key == "base_directory":
						if not isdir(join(BUILD_DIR, value)):
							all_files_available = False
					else:
						if not isfile(join(base_dir, value)):
							all_files_available = False
			else:
				assert verify_checksum(build_manifest["files"][key.replace("_checksum", "")], value), f"Invalid {key}"

		# all_files_available = all([isfile(x) for x in build_manifest["files"]])
		# print(all_files_available)

		# verify checksums if present
		# print("Verifying checksums...")
		# assert verify_checksum(base_img_file, build_manifest["files"]["base_image_checksum"]), "Invalid base image checksum"
		# assert verify_checksum(sb_file, build_manifest["files"]["SB_checksum"]), "Invalid SB checksum"
		# assert verify_checksum(sc_file, build_manifest["files"]["SC_checksum"]), "Invalid SC checksum"
		# assert verify_checksum(sd_file, build_manifest["files"]["SD_checksum"]), "Invalid SD checksum"
		# assert verify_checksum(se_file, build_manifest["files"]["SE_checksum"]), "Invalid SE checksum"
		# assert verify_checksum(kernel_file, build_manifest["files"]["kernel_checksum"]), "Invalid kernel checksum"
		# assert verify_checksum(hypervisor_file, build_manifest["files"]["HV_checksum"]), "Invalid HV checksum"
		# assert verify_checksum(sd_patches_file, build_manifest["files"]["SD_patches_checksum"]), "Invalid SD patches checksum"
		# assert verify_checksum(sd_code_file, build_manifest["files"]["SD_code_checksum"]), "Invalid SD code checksum"
		# assert verify_checksum(khv_patches_file, build_manifest["files"]["HVK_patches_checksum"]), "Invalid HVK patches checksum"

		# output_file = join(args.output, "shadowboot.bin")
		output_file = args.output

		# compile patches
		# print("Compiling HV/kernel patches...")
		# assemble_patch(join(PATCH_DIR, "HVK", f"{BUILD_VER}-dev", "RGLoader-dev.S"), hvk_patches_file, PATCH_DIR)
		# print("Compiling XAM patches...")
		# assemble_patch(join(PATCH_DIR, "XAM", f"{BUILD_VER}-dev", "rglXam.S"), f"xam_{BUILD_VER}.rglp", PATCH_DIR)

		# assemble_patch(join(PATCH_DIR, "Test Kit", "patches.S"), "fakeanim.bin", PATCH_DIR)
		# return

		# check for the base image and load it if it exists
		base_img = None
		base_img_available = isfile(base_img_file)
		if base_img_available:
			base_img = ShadowbootImage.parse(base_img_file, not build_manifest["options"]["base_image_checks_disabled"])

		if isfile(kernel_file) and isfile(hypervisor_file):
			print("Reading raw HV/kernel...")
			kernel = read_file(kernel_file)
			hypervisor = read_file(hypervisor_file)
			se_data = hypervisor + kernel
		elif isfile(se_file):
			print("Decompressing SE...")
			se_data = decompress_se(read_file(se_file))
		elif base_img_available:
			print("Using fallback image HV/kernel...")
			se_data = base_img.se_data
		else:
			raise Exception("No HV/kernel pair, SE, or fallback image was provided!")

		# update build version in HV
		# print("Updating HV build version...")
		# se_blob = bytearray(se_blob)
		# build version
		# pack_into(">H", se_blob, 2, BUILD_VER)
		# base kernel version
		# pack_into(">H", se_blob, 0x10, 0)

		# cs = Cs(CS_ARCH_PPC, CS_MODE_64 + CS_MODE_BIG_ENDIAN)

		print("Applying patches to HV and kernel...")
		se_data = apply_patches(se_data, hvk_patches_file)

		# if test_kit_compile:
		# boot animation patch
		# pack_into(">I", se_data, 0x41EA8 + HYPERVISOR_SIZE, 0x60000000)

		# print(hexlify(se_blob[:0x40000]))

		# check to make sure our private key matches the public key in the SB
		# key_check = sb_prv_key[:XECRYPT_RSAPUB_2048_SIZE] == shadow.sb_pub_key
		# assert key_check, "Public key in SB doesn't match the private key"

		# generate new nonce's and keys
		print("Generating new nonce's and encryption keys...")
		new_sb_nonce = XeCryptRandom(0x10)
		new_sb_key = XeCryptHmacSha(XECRYPT_1BL_KEY, new_sb_nonce)[:0x10]

		new_sc_nonce = XeCryptRandom(0x10)
		new_sc_key = XeCryptHmacSha((b"\x00" * 0x10), new_sc_nonce)[:0x10]

		new_sd_nonce = XeCryptRandom(0x10)
		new_sd_key = XeCryptHmacSha(new_sc_key, new_sd_nonce)[:0x10]

		new_se_nonce = XeCryptRandom(0x10)
		new_se_key = XeCryptHmacSha(new_sd_key, new_se_nonce)[:0x10]

		# set header values
		print("Setting initial NAND header values...")
		if build_manifest["build"]["copyright"]:
			print("Using custom copyright...")
			copyright = b"\xA9 " + build_manifest["build"]["copyright"].encode("UTF8")
		else:
			copyright = b"\xA9 2004-2019 Microsoft Corporation. All rights reserved"

		if build_manifest["build"]["version"] > 0:
			print("Using custom build version...")
			build_ver = build_manifest["build"]["version"]
		else:
			build_ver = unpack_from(">H", se_data, HYPERVISOR_SIZE + 0x40C)[0]

		# create NAND header
		nand_header = NAND_HEADER()
		nand_header.magic = 0xFF4F
		nand_header.build = build_ver
		nand_header.qfe = 0x8000
		nand_header.copyright = (c_ubyte * 0x40)(*copyright)

		# create room for the NAND header
		print("Creating empty NAND header...")
		new_img = bytearray(sizeof(nand_header))

		# SMC
		smc_offset = len(new_img)
		if isfile(join(BUILD_DIR, "SMC_dec.bin")):
			print(f"Encrypting and writing SMC_dec.bin @ 0x{smc_offset:04X}...")
			nand_header.smc_offset = sizeof(nand_header)  # right after NAND header
			smc_data = XeCryptSmcEncrypt(read_file(join(BUILD_DIR, "SMC_dec.bin")))
			nand_header.smc_length = len(smc_data)
			new_img += smc_data
		elif isfile(join(BUILD_DIR, "SMC_enc.bin")):
			print(f"Writing encrypted SMC_enc.bin @ 0x{smc_offset:04X}...")
			nand_header.smc_offset = sizeof(nand_header)  # right after NAND header
			smc_data = read_file(join(BUILD_DIR, "SMC_enc.bin"))
			nand_header.smc_length = len(smc_data)
			new_img += smc_data
		else:
			print("SMC_dec.bin and SMC_enc.bin not found, skipping...")

		# KeyVault
		kv_offset = len(new_img)
		if isfile(join(BUILD_DIR, "KV_dec.bin")):
			nand_header.kv_offset = kv_offset
			if isfile(join(BUILD_DIR, "cpukey.txt")):
				cpu_key = bytes.fromhex(read_file(join(BUILD_DIR, "cpukey.txt")))
			elif isfile(join(BUILD_DIR, "cpukey.bin")):
				cpu_key = read_file(join(BUILD_DIR, "cpukey.bin"))
			else:
				raise Exception("cpukey.txt or cpukey.bin is required if you're building with a keyvault")
			print(f"Encrypting and writing KV_dec.bin @ 0x{kv_offset:04X}...")
			kv_data = XeCryptKeyVaultEncrypt(cpu_key, read_file(join(BUILD_DIR, "KV_dec.bin")))
			nand_header.kv_length = len(kv_data)
			new_img += kv_data
		elif isfile(join(BUILD_DIR, "KV_enc.bin")):
			print(f"Writing encrypted KV_enc.bin @ 0x{kv_offset:04X}...")
			nand_header.kv_offset = kv_offset
			kv_data = read_file(join(BUILD_DIR, "KV_enc.bin"))
			nand_header.kv_length = len(kv_data)
			new_img += kv_data
		else:
			print("KV_dec.bin and KV_enc.bin not found, skipping...")

		# write SB
		sb_offset = len(new_img)
		nand_header.cb_offset = sb_offset
		print(f"Encrypting and writing SB @ 0x{sb_offset:04X}...")
		nonce_sb = bytearray(read_file(sb_file))
		pack_into("<16s", nonce_sb, 0x10, new_sb_nonce)
		if test_kit_compile:
			print("Compiling for test kit, SB signature will be broken!")
			pack_into("<4s", nonce_sb, 0x1348, b"\x48\x00\x01\x94")
			pack_into("<4s", nonce_sb, 0x1E10, b"\x4E\x80\x00\x20")
		sb_enc = encrypt_bl(new_sb_key, nonce_sb)
		new_img += sb_enc
		sc_offset = len(new_img)

		# write SC
		print(f"Encrypting and writing SC @ 0x{sc_offset:04X}...")
		nonce_sc = bytearray(read_file(sc_file))
		pack_into("<16s", nonce_sc, 0x10, new_sc_nonce)
		sc_enc = encrypt_bl(new_sc_key, nonce_sc)
		new_img += sc_enc
		sd_offset = len(new_img)

		# create SE image
		print("Creating SE...")
		se_dec = se_data
		print("Compressing SE...")
		se_com = compress_se(se_dec)
		# magic, build, QFE, flags, and entry point
		pack_into(">2s 3H I", se_com, 0, b"SE", build_ver, 0x8000, 0, 0)
		# write the nonce into the image
		pack_into("<16s", se_com, 0x10, new_se_nonce)
		# append padding
		se_com += (b"\x00" * (((len(se_com) + 0xF) & ~0xF) - len(se_com)))
		print("Hashing SE...")
		se_hash = XeCryptRotSumSha(se_com[:0x10] + se_com[0x20:])
		print("Encrypting SE...")
		se_enc = encrypt_bl(new_se_key, se_com)

		# write SD
		print(f"Signing, encrypting, and writing SD @ 0x{sd_offset:04X}...")
		nonce_sd = bytearray(read_file(sd_file))
		pack_into("<16s", nonce_sd, 0x10, new_sd_nonce)
		pack_into("<20s", nonce_sd, 0x24C, se_hash)
		sd_patched = nonce_sd
		# load additional binary data to run after the SD here
		if sd_code_enabled and isfile(sd_code_file):
			print("Patching RFID jump and appending SD code binary...")
			sd_patched = apply_jump_sd_4bl(sd_patched, unpack_from(">I", sd_patched, 0xC)[0])
			# sd_patched += read_file(patch_loader_file)
			sd_patched += read_file(sd_code_file)
		# apply SD patches directly
		if sd_patches_enabled and isfile(sd_patches_file):
			print("Applying SD patches directly...")
			sd_patched = apply_patches(sd_patched, read_file(sd_patches_file))
		# apply padding
		sd_patched += (b"\x00" * (((len(sd_patched) + 0xF) & ~0xF) - len(sd_patched)))
		pack_into(">I", sd_patched, 0xC, len(sd_patched))  # set the new size
		sd_res = sign_sd_4bl(SD_PRV_KEY, XECRYPT_SD_SALT, sd_patched)
		sd_enc = encrypt_bl(new_sd_key, sd_res)
		new_img += sd_enc
		se_offset = len(new_img)

		# write SE
		print(f"Writing SE to 0x{se_offset:04X}...")
		new_img += se_enc

		# write NAND header
		print("Writing NAND header @ 0x0...")
		pack_into(f"<{sizeof(nand_header)}s", new_img, 0, bytes(nand_header))

		# write the output image
		print("Writing output image...")
		write_file(output_file, new_img)
		img_size = len(new_img)

		print(f"Image size: {img_size}/{SHADOWBOOT_SIZE} (0x{img_size:04X}/0x{SHADOWBOOT_SIZE:04X}) bytes")
		if len(new_img) < SHADOWBOOT_SIZE:
			red_size = SHADOWBOOT_SIZE - len(new_img)
			print(f"Image reduced by {red_size} (0x{red_size:04X}) bytes!")

		# sanity checks on new image
		if test_kit_compile:
			print("Image is test kit compiled, verification is disabled!")
		else:
			ShadowbootImage.parse(new_img)
			print("Modified image verified!")

		print(f"Final image location: \"{abspath(output_file)}\"")
	elif args.command == "extract":
		img = ShadowbootImage.parse(read_file(args.input), not args.nochecks)

		print(f"Console Type:       {img.console_type}")
		print(f"SMC Version:        {img.smc_version}")
		print(f"Kernel Version:     {img.kernel_version}")
		print(f"HyperVisor Version: {img.hypervisor_version}")

		if args.all or args.smc:
			write_file(join(args.output, "SMC_dec.bin"), img.smc_data)
		if args.all or args.keyvault:
			write_file(join(args.output, "KV_dec.bin"), img.kv_data)
		if args.all or args.sb:
			write_file(join(args.output, f"sb_{img.sb_build}.bin"), img.sb_data)
		if args.all or args.sc:
			write_file(join(args.output, f"sc_{img.sc_build}.bin"), img.sc_data)
		if args.all or args.sd:
			write_file(join(args.output, f"sd_{img.sd_build}.bin"), img.sd_data)
		if args.all or args.se:
			write_file(join(args.output, f"se_{img.se_build}.bin"), img.se_data)
		if args.all or args.kernel:
			write_file(join(args.output, "kernel.exe"), img.kernel_data)
		if args.all or args.hypervisor:
			write_file(join(args.output, "hypervisor.bin"), img.hypervisor_data)
		if args.all or args.loader:
			if len(img.patches) > 0:
				write_file(join(args.output, "patch_loader.bin"), img.patches[0]["patch_loader"])
			else:
				print("No patch loader found!")
		if args.all or args.patches:
			if len(img.patches) > 1:
				for patch in img.patches[1:]:
					write_file(join(args.output, f"{patch['address']:04X}.bin"), patch["patch_code"])
			else:
				print("No patches found!")
	elif args.command == "info":
		img = ShadowbootImage.parse(read_file(args.input))

		print(f"Console Type:   {img.console_type}")
		print(f"SMC Version:    {img.smc_version}")
		print(f"SB Version:     {img.sb_build}")
		print(f"SC Version:     {img.sc_build}")
		print(f"SD Version:     {img.sd_build}")
		print(f"SE Version:     {img.se_build}")
		print(f"HV Version:     {img.hypervisor_version}")
		print(f"Kernel Version: {img.kernel_version}")

		is_retail = img.hypervisor_data[0] == 0x4E
		is_testkit = bytes.fromhex("5C746573746B69745C") in img.kernel_data

		if is_retail:
			print("Main Menu:      Dashboard")
		else:
			print("Main Menu:      XShell")

		if is_testkit:
			print("Hardware:       Test Kit")
		else:
			print("Hardware:       Development Kit")
	elif args.command == "test":
		#sb = ShadowbootImage(read_file("C://Users/John/Desktop/xboxrom_13146_patched.bin"), False)
		#write_file("C://Users/John/Desktop/hv.bin", sb.hypervisor_data)
		#write_file("C://Users/John/Desktop/kernel.exe", sb.kernel_data)
		#exit(0)
		pass

if __name__ == "__main__":
	main()
