#!/usr/bin/env python3

from os import name
from math import ceil
from io import BytesIO
from typing import Union
from pathlib import Path
from struct import unpack_from
from subprocess import Popen, PIPE
from argparse import ArgumentParser
from tempfile import TemporaryDirectory
from zlib import compressobj, decompressobj
from shutil import copyfile, copyfileobj, move
from ctypes import LittleEndianStructure, sizeof, c_ubyte, c_uint16, c_uint32, c_uint64

from struct import pack

from XeCrypt import *
from StreamIO import *

# constants
BUFF_SIZE = 4096
XENON_DATA_SIZE = 0x1C
WORK_DIR = None
CACHE_DIR = "cache"
TMP_CAB_FILE = "tmp.cab"

# aliases
c_word = c_uint16
c_dword = c_uint32
c_qword = c_uint64

class CAB_HEADER(LittleEndianStructure):
	_fields_ = [
		("magic", c_dword),
		("cksm_hdr", c_dword),
		("cb_cabinet", c_dword),
		("cksm_folders", c_dword),
		("off_files", c_dword),
		("cksm_files", c_dword),
		("version", c_word),
		("cnt_folders", c_word),
		("cnt_files", c_word),
		("cnt_flags", c_word),
		("flags", c_word),
		("set_id", c_word),
		("i_cabinet", c_word),
	]

class CAB_FOLDER(LittleEndianStructure):
	_fields_ = [
		("off_cab_start", c_dword),
		("cf_data", c_word),
		("type_compress", c_word)
		# ("xenon_data", c_ubyte * 0x1C)
	]

class CAB_ENTRY(LittleEndianStructure):
	_fields_ = [
		("cb_file", c_dword),
		("off_folder_start", c_dword),
		("i_folder", c_word),
		("date", c_word),
		("time", c_word),
		("attribs", c_word),
	]

class CAB_DATA(LittleEndianStructure):
	_fields_ = [
		("cksm", c_dword),
		("cb_data", c_word),
		("cb_uncomp", c_word)
	]

class RC4_SHA_HEADER(LittleEndianStructure):
	_fields_ = [
		("cksm", c_ubyte * 0x14),
		("confounder", c_ubyte * 8)
	]

def path_type(s: str) -> Path:
	return Path(s)

def extract_cab(filename: str, path: str) -> bool:
	if name == "nt":
		p = Popen(["expand", filename, "-F:*", path], stdout=PIPE, stderr=PIPE)
	elif name == "posix":
		p = Popen(["cabextract", "-d", path, "-F", "*", filename], stdout=PIPE, stderr=PIPE)
	else:
		raise NotImplemented("Only Windows and Linux are supported!")
	(out, err) = p.communicate()
	p.wait()
	return p.returncode == 0

def stream_decrypt_with_struct(xcp: StreamIO, key: Union[bytes, bytearray], struct_offset: int, data_offset: int, size: int) -> bytes:
	xcp.offset = struct_offset
	rc4_sha_struct = xcp.read_struct(RC4_SHA_HEADER)
	cipher = XeCryptRc4.new(XeCryptHmacSha(key, bytes(rc4_sha_struct.cksm)))
	cipher.decrypt(bytes(rc4_sha_struct.confounder))

	dec_data = xcp.perform_function_at(data_offset, size, cipher.decrypt)

	return dec_data

class XCPFile:
	SVOD_INDEX_SIZE = 0xB000
	SVOD_BLOCK_SIZE = 0x1000
	SVOD_DATA_SIZE  = 0xA290000

	handle = None
	total_size: int = 0

	#@property
	#def data_size(self) -> int:
	#	return self.total_size - self.SVOD_INDEX_SIZE

	def __init__(self, path: str):
		self.handle = open(path, "rb")
		self.handle.seek(0, 2)
		self.total_size = self.handle.tell()
		self.handle.seek(0)

	def __enter__(self):
		return self

	def __exit__(self, exc_type, exc_val, exc_tb):
		if self.handle is not None:
			self.handle.close()

	def create_file_struct(self, out_path: str, hdr: bytes | bytearray) -> Path:
		svod_name = hdr[0x32C:0x32C + (34 // 2)].hex().upper()
		title_id = hdr[0x360:0x360 + 4].hex().upper()

		p = Path(out_path)
		p /= title_id
		p /= "00007000"
		# create content path
		p.mkdir(parents=True, exist_ok=True)
		p /= svod_name

		# write header file
		with p.open("wb") as f:
			f.write(hdr)

		p = p.parent
		p /= (svod_name + ".data")
		# create folder for data files
		p.mkdir(exist_ok=True)

		return p

	def calc_buffer_len(self, stream, data: bytes | bytearray) -> int:
		return stream.tell() + len(data)

	def calc_bytes_left(self, stream, size: int) -> int:
		return size - stream.tell()

	def get_chunk(self, data: bytes | bytearray, offset: int = 0, size: int = 0) -> bytes:
		if size == 0:
			return data[offset:]
		return data[offset:offset + size]

	def calc_data_file_num_from_offset(self, offset: int) -> int:
		if offset <= self.SVOD_INDEX_SIZE:
			return -1  # index file
		offset -= self.SVOD_INDEX_SIZE
		return ceil(offset / self.SVOD_DATA_SIZE)

	def extract(self, out_path: str):
		# variables
		dfn = 0  # data file number
		buf = b""
		idx = b""
		data_written = 0
		idx_done = False

		# handles
		pd = None
		f = None
		with BytesIO() as bio:  # holds the index
			while self.handle.tell() < self.total_size or len(buf) > 0:
				dec = decompressobj()
				while True:
					if buf == b"":  # no remainder buffer, so fetch more data
						buf = self.handle.read(self.SVOD_BLOCK_SIZE)
						if not buf:  # eof
							if f is not None:
								f.close()
							print("Done!")
							break
						buf = dec.decompress(buf)
						if not buf:
							self.handle.seek(-len(dec.unused_data), 1)
							buf = dec.flush()
							dec = decompressobj()

					if not idx_done:  # index file
						if self.calc_buffer_len(bio, buf) < self.SVOD_INDEX_SIZE:  # <, all of the buffer is consumed
							bio.write(buf)
							buf = b""
						elif self.calc_buffer_len(bio, buf) > self.SVOD_INDEX_SIZE:  # >, part of the buffer is consumed, and the file is complete
							bl = self.calc_bytes_left(bio, self.SVOD_INDEX_SIZE)

							bio.write(self.get_chunk(buf, size=bl))

							# carry remainder to data files
							buf = self.get_chunk(buf, bl)

							idx = bio.getvalue()
							pd = self.create_file_struct(out_path, idx)
							idx_done = True

							# open the new file
							f = (pd / f"Data{dfn:0{4}}").open("wb")
						elif self.calc_buffer_len(bio, buf) == self.SVOD_INDEX_SIZE:  # ==, all of the buffer is consumed, and the file is complete
							bio.write(buf)
							buf = b""

							idx = bio.getvalue()
							pd = self.create_file_struct(out_path, idx)
							idx_done = True

							# open the new file
							f = (pd / f"Data{dfn:0{4}}").open("wb")
						# done with header, start on data files
						continue

					if self.calc_buffer_len(f, buf) < self.SVOD_DATA_SIZE:  # <, same as above
						data_written += f.write(buf)
						buf = b""
					elif self.calc_buffer_len(f, buf) > self.SVOD_DATA_SIZE:  # >, same as above
						bl = self.calc_bytes_left(f, self.SVOD_DATA_SIZE)

						data_written += f.write(self.get_chunk(buf, size=bl))

						# carry remainder to next data file
						buf = self.get_chunk(buf, bl)

						# close the file
						f.close()

						dfn += 1

						# open the new file
						f = (pd / f"Data{dfn:0{4}}").open("wb")
					elif self.calc_buffer_len(f, buf) == self.SVOD_DATA_SIZE:  # ==, same as above
						data_written += f.write(buf)
						buf = b""

						# close the file
						f.close()

						dfn += 1

						# open the new file
						f = (pd / f"Data{dfn:0{4}}").open("wb")

		# db_cnt = int.from_bytes(idx[0x392:0x392 + 3], "big")
		# print(f"0x{db_cnt:X}")
		# db_offs = int.from_bytes(idx[0x395:0x395 + 3], "big")
		# print(f"0x{db_offs:X}")

		(df_cnt, df_size) = unpack_from(">iq", idx, 0x39D)
		# print(f"0x{df_size // df_cnt:X}")
		assert (dfn + 1) == df_cnt, "Not enough data files generated!"
		assert data_written == df_size, "Not enough data decompressed!"


def main() -> int:
	# setup arguments
	parser = ArgumentParser(description="A script to decrypt, merge, and convert XCP files for the Xbox 360")
	parser.add_argument("input", type=path_type, help="The file to extract")
	parser.add_argument("-k", "--key", type=str, help="The key used to decrypt the XCP package if it's encrypted")
	parser.add_argument("--ignore", action="store_true", help="Ignore the file overwrite warning")
	parser.add_argument("--no-backup", action="store_true", help="Disable backups")
	# parse arguments
	args = parser.parse_args()

	# validate arguments
	assert args.input.is_file(), "The specified input file or directory doesn't exist"

	# print("Testing...")

	# with XCPFile("C://Users/John/Desktop/5685de381fc23eb4a130e362da33e79263237d3f.xcp") as xcp:
	#	xcp.extract("C://Users/John/Desktop/svod")

	# return 1

	# create work directory
	with TemporaryDirectory(f"_{args.input.stem.upper()}_XCP") as work_dir:
		work_dir = Path(work_dir)
		out_dir = args.input.parents[0]

		if not args.ignore:
			input("This will OVERWRITE and DELETE the original XCP file, press \"ENTER\" if you want to continue...")

		if not args.no_backup:
			print("Backing up the input file...")
			copyfile(args.input, out_dir / (args.input.stem + ".bak"))
		else:
			print("Skipping backup...")

		print("Extracting XCP file...")
		with StreamIO(str(args.input), Endian.LITTLE) as xcp:
			print("Checking CAB header...")
			cab_hdr_data = xcp.read_bytes_at(0, sizeof(CAB_HEADER))
			cab_hdr_struct = CAB_HEADER.from_buffer_copy(cab_hdr_data)
			encrypted = not (cab_hdr_struct.magic in (0x4D534346, 0x4643534D))
			print("XCP file is " + ("encrypted" if encrypted else "not encrypted"))

			if encrypted:
				if args.key and len(args.key) % 2 == 0:
					args.key = bytes.fromhex(args.key)
				else:
					raise Exception("Decryption key not specified and the file is encrypted!")

			if encrypted:
				print("Decrypting CAB header...")
				cab_hdr_data = stream_decrypt_with_struct(xcp, args.key, 0x60, 0, 0x60)
				cab_hdr_struct = CAB_HEADER.from_buffer_copy(cab_hdr_data)
				assert cab_hdr_struct.magic in (0x4D534346, 0x4643534D), "Invalid key specified"
				print("Key appears to be OK!")

			if encrypted:
				print("Decrypting folder data...")
				folder_size = cab_hdr_struct.cnt_folders * (sizeof(CAB_FOLDER) + XENON_DATA_SIZE)
				stream_decrypt_with_struct(xcp, args.key, 0x28, 0x180, folder_size)

			print("Processing filenames...")
			xcp.offset = 0x44
			rc4_sha_struct = xcp.read_struct(RC4_SHA_HEADER)
			cipher = XeCryptRc4.new(XeCryptHmacSha(args.key, bytes(rc4_sha_struct.cksm)))
			cipher.decrypt(bytes(rc4_sha_struct.confounder))
			# decrypt filenames
			xcp.offset = cab_hdr_struct.off_files
			for i in range(cab_hdr_struct.cnt_files):
				# decrypt header if necessary
				if encrypted:
					xcp.perform_function_at(xcp.offset, sizeof(CAB_ENTRY), cipher.decrypt)

				xcp.offset += sizeof(CAB_ENTRY)

				xcp.set_label(f"filename{i}")

				# decrypt filename if necessary
				idx = 0
				byt = 0
				while byt != 0 or idx == 0:
					if encrypted:
						byt = xcp.perform_function_at(xcp.offset, 1, cipher.decrypt)[0]
						xcp.offset += 1
					else:
						byt = xcp.read_byte()
					idx += 1
				# rename the files to extract them properly
				xcp.write_bytes_at(xcp.offset - 4, str(i).zfill(3).encode("UTF8"))

			if encrypted:
				print("Preprocessing folders...")
				xcp.offset = 0x180
				folders = []
				for i in range(cab_hdr_struct.cnt_folders):
					xcp.set_label(f"folder{i}")
					folders.append(xcp.read_struct(CAB_FOLDER))
					xcp.seek(XENON_DATA_SIZE, SEEK_CUR)

			if encrypted:
				print("Processing folders...")
				for i in range(cab_hdr_struct.cnt_folders):
					curr_folder = folders[i]

					if (i + 1) == cab_hdr_struct.cnt_folders:
						size = xcp.length() - curr_folder.off_cab_start
					else:
						next_folder = folders[i + 1]
						size = next_folder.off_cab_start - curr_folder.off_cab_start

					stream_decrypt_with_struct(xcp, args.key, xcp.get_label(f"folder{i}") + sizeof(CAB_FOLDER), curr_folder.off_cab_start, size)

		if not (work_dir / CACHE_DIR).is_dir():
			print("Creating output directory...")
			(work_dir / CACHE_DIR).mkdir()

		print("Renaming XCP file...")
		if (work_dir / TMP_CAB_FILE).is_file():
			(work_dir / TMP_CAB_FILE).unlink()
		# args.input.rename(work_dir / TMP_CAB_FILE)
		move(args.input, work_dir / TMP_CAB_FILE)

		print("Extracting CAB file...")
		# extract the cabinet file and make sure it exited properly
		assert extract_cab(str(work_dir / TMP_CAB_FILE), str(work_dir / CACHE_DIR)), "CAB extraction failed!"

		print("Merging the extracted files...")
		# merge the files together to make them into one file
		with StreamIO(str(work_dir / (args.input.stem.upper()))) as fw:
			for single in (work_dir / CACHE_DIR).iterdir():
				with single.open("rb") as fr:
					copyfileobj(fr, fw, BUFF_SIZE)
			print("Converting to a LIVE package...")
			# really hacky way to make it a LIVE file
			fw.write_bytes_at(0, b"LIVE")

		print("Moving file...")
		# (work_dir / (args.input.stem.upper())).rename(args.input.parents[0] / args.input.stem.upper())
		move(work_dir / args.input.stem.upper(), out_dir / args.input.stem.upper())

		print("Done!")

	return 0

if __name__ == "__main__":
	exit(main())