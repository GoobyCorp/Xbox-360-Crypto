#!/usr/bin/env python3

from enum import IntEnum
from ctypes import BigEndianStructure, sizeof, c_ubyte, c_uint16, c_uint32, c_uint64

from StreamIO import *

"""
References:
https://free60project.github.io/wiki/STFS/
https://github.com/Free60Project/wiki/blob/master/STFS.md
http://www.arkem.org/xbox360-file-reference.pdf
"""

class STFSVolumeDescriptor(BigEndianStructure):
	_fields_ = [
		("reserved", c_ubyte),
		("block_separation", c_ubyte),
		("file_table_block_count", c_uint16),
		("file_table_block_number", c_uint16),
		("file_table_hash", c_ubyte * 0x14),
		("total_alloc_block_count", c_uint32),
		("tital_unalloc_block_count", c_uint32)
	]

class SVODVolumeDescriptor(BigEndianStructure):
	_fields_ = [
		("block_cache_element_count", c_ubyte),
		("worker_thread_processor", c_ubyte),
		("worker_thread_priority", c_ubyte),
		("hash", c_ubyte * 0x14),
		("device_features", c_ubyte),
		("data_block_count", c_uint16),
		("data_block_offset", c_uint16),
		("reserved", c_ubyte * 5)
	]

class LicenseEntry(BigEndianStructure):
	_fields_ = [
		("license_id", c_uint64),
		("license_bits", c_uint32),
		("license_flags", c_uint32)
	]

class PlatformType(IntEnum):
	XBOX360 = 2
	PC      = 4

class DescriptorType(IntEnum):
	STFS = 0
	SVOD = 1

class TransferFlags(IntEnum):
	DEVICE_ID_AND_PROFILE_ID_TRANSFER = 0
	MOVE_ONLY_TRANSFER = 0x20
	DEVICE_ID_TRANSFER = 0x40
	PROFILE_ID_TRANSFER = 0x80
	NONE = 0xC0

class ContentType(IntEnum):
	ARCADE_TITLE = 0xD0000
	AVATAR_ITEM = 0x9000
	CACHE_FILE = 0x40000
	COMMUNITY_GAME = 0x2000000
	GAME_DEMO = 0x80000
	GAMER_PICTURE = 0x20000
	GAME_TITLE = 0xA0000
	GAME_TRAILER = 0xC0000
	GAME_VIDEO = 0x400000
	INSTALLED_GAME = 0x4000
	INSTALLER = 0xB0000
	IPTV_PAUSE_BUFFER = 0x2000
	LICENSE_STORE = 0xF0000
	MARKETPLACE_CONTENT = 0x2
	MOVIE = 0x100000
	MUSIC_VIDEO = 0x300000
	PODCAST_VIDEO = 0x500000
	PROFILE = 0x10000
	PUBLISHER = 0x3
	SAVE_GAME = 0x1
	STORAGE_DOWNLOAD = 0x50000
	THEM = 0x30000
	TV = 0x200000
	VIDEO = 0x90000
	VIRAL_VIDEO = 0x600000
	XBOX_DOWNLOAD = 0x70000
	XBOX_ORIGINAL_GAME = 0x5000
	XBOX_SAVE_GAME = 0x60000
	XBOX_360_TITLE = 0x1000
	XBOX_TITLE = 0x5000
	XNA = 0xE0000

class PackageType(IntEnum):
	CON =  0
	PIRS = 1
	LIVE = 2

def main() -> None:
	with StreamIO("Research/su20076000_00000000", Endian.BIG) as package:
		magic = package.read(4)
		if magic == b"CON ":
			pass
		elif magic == b"PIRS" or magic == b"LIVE":
			package_sig = package.read(0x100)
			package.seek(0x128, SEEK_CUR)
			for i in range(0x100 // sizeof(LicenseEntry)):
				license_ent = package.read_struct(LicenseEntry)
			content_id = package.read(0x14)  # header hash
			entry_id = package.read_uint32()
			content_type = package.read_uint32()
			metadata_version = package.read_uint32()
			content_size = package.read_uint64()
			media_id = package.read_uint32()
			version = package.read_uint32()
			base_version = package.read_uint32()
			title_id = package.read_uint32()
			platform = package.read_ubyte()
			executable_type = package.read_ubyte()
			disc_number = package.read_ubyte()
			disc_in_set = package.read_ubyte()
			save_game_id = package.read_uint32()
			console_id = package.read(5)
			profile_id = package.read(8)
			descriptor_size = package.read_ubyte()
			descriptor = package.read(descriptor_size)
			data_file_count = package.read_uint32()
			data_file_combined_size = package.read_uint64()
			descriptor_type = package.read_ubyte()
			package.seek(4 + 0x4C, SEEK_CUR)
			device_id = package.read(0x14)
			display_name = package.read(0x900)
			display_description = package.read(0x900)
			publisher_name = package.read(0x80)
			title_name = package.read(0x80)
			transfer_flags = package.read_ubyte()
			thumbnail_image_size = package.read_uint32()
			title_thumbnail_image_size = package.read_uint32()
			thumbnail_image = package.read(thumbnail_image_size)
			title_thumbnail_image = package.read(title_thumbnail_image_size)

			print("Metadata Version: " + str(metadata_version))
			print("Descriptor Type:  " + str(DescriptorType(descriptor_type)))
			print("Console ID:       " + console_id.hex())
			print("Profile ID:       " + profile_id.hex())
			print("Device ID:        " + device_id.hex())

			print("Display Name:     " + display_name.decode("utf8"))
			print("Display Desc.:    " + display_description.decode("utf8"))
			print("Publisher Name:   " + publisher_name.decode("utf8"))
			print("Title Name:       " + title_name.decode("utf8"))

			with open("thumbnail_image", "wb") as f:
				f.write(thumbnail_image)
			with open("title_thumbnail_image", "wb") as f:
				f.write(title_thumbnail_image)
		else:
			print("Invalid package magic")

if __name__ == "__main__":
	main()