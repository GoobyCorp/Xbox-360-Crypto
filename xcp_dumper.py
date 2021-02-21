#!/usr/bin/env python3

from ctypes import *
from shutil import copyfile
from subprocess import Popen, PIPE
from argparse import ArgumentParser
from os.path import join, isdir, isfile
from os import name, listdir, makedirs, remove, rmdir, rename

from XeCrypt import *
from StreamIO import *

# constants
BUFF_SIZE = 4096
XENON_DATA_SIZE = 0x1C

c_word = c_uint16
c_dword = c_uint32
c_qword = c_uint64

class CAB_HEADER(Structure):
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

class CAB_FOLDER(Structure):
	_fields_ = [
		("off_cab_start", c_dword),
		("cf_data", c_word),
		("type_compress", c_word)
		#("xenon_data", c_ubyte * 0x1C)
	]

class CAB_ENTRY(Structure):
	_fields_ = [
		("cb_file", c_dword),
		("off_folder_start", c_dword),
		("i_folder", c_word),
		("date", c_word),
		("time", c_word),
		("attribs", c_word),
	]

class CAB_DATA(Structure):
	_fields_ = [
		("cksm", c_dword),
		("cb_data", c_word),
		("cb_uncomp", c_word)
	]

class RC4_SHA_HEADER(Structure):
	_fields_ = [
		("cksm", c_ubyte * 0x14),
		("confounder", c_ubyte * 8)
	]

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

def main() -> None:
	# setup arguments
	parser = ArgumentParser(description="A script to decrypt, merge, and convert XCP files for the Xbox 360")
	parser.add_argument("input", type=str, help="The file or directory to use (no extension on files!)")
	parser.add_argument("-k", "--key", type=str, help="The key used to decrypt the XCP package")
	parser.add_argument("--ignore", action="store_true", help="Ignore the file overwrite warning")
	parser.add_argument("--keep", action="store_true", help="Keep the CAB file after conversion")
	# parse arguments
	args = parser.parse_args()

	# validate arguments
	assert isfile(args.input + ".xcp") or isdir(args.input), "The specified input file or directory doesn't exist"
	if args.key and len(args.key) % 2 == 0:
		args.key = bytes.fromhex(args.key)

	if not args.ignore:
		input("This will OVERWRITE and DELETE the original XCP file, press \"ENTER\" if you want to continue...")

	print("Decrypting XCP file...")
	with StreamIO(args.input + ".xcp", Endian.LITTLE) as xcp:
		def init_crypto_at(offset: int) -> None:
			xcp.offset = offset
			rc4_sha_struct = xcp.read_struct(RC4_SHA_HEADER)
			XeCryptRc4EcbKey(XeCryptHmacSha(args.key, bytes(rc4_sha_struct.cksm)))
			XeCryptRc4(bytes(rc4_sha_struct.confounder))

		print("Decrypting CAB header...")
		# init crypto
		init_crypto_at(0x60)
		# decrypt cab header
		cab_hdr_data = xcp.perform_function_at(0, 0x60, XeCryptRc4)
		cab_hdr_struct = CAB_HEADER.from_buffer_copy(cab_hdr_data)
		assert cab_hdr_struct.magic in (0x4D534346, 0x4643534D), "Invalid key specified"
		print("Key appears to be OK!")

		print("Decrypting folder data...")
		# init crypto
		init_crypto_at(0x28)
		# decrypt folder data
		folder_size = cab_hdr_struct.cnt_folders * (sizeof(CAB_FOLDER) + XENON_DATA_SIZE)
		xcp.perform_function_at(0x180, folder_size, XeCryptRc4)

		print("Decrypting filenames...")
		# init crypto
		init_crypto_at(0x44)
		# decrypt filenames
		xcp.offset = cab_hdr_struct.off_files
		for i in range(cab_hdr_struct.cnt_files):
			# decrypt header
			xcp.perform_function_at(xcp.offset, sizeof(CAB_ENTRY), XeCryptRc4)
			# ent = xcp.read_struct_at(xcp.offset, CAB_ENTRY)

			xcp.offset += 0x10

			# decrypt filename
			idx = 0
			byt = 0
			while byt != 0 or idx == 0:
				byt = xcp.perform_function_at(xcp.offset, 1, XeCryptRc4)[0]
				xcp.offset += 1
				idx += 1
			# rename the files to extract them properly
			xcp.write_ubytes_at(xcp.offset - 4, str(i).zfill(3).encode("utf8"))

		print("Decrypting folders...")
		xcp.offset = 0x180
		for i in range(cab_hdr_struct.cnt_folders):
			xcp.set_label("folder")
			folder = xcp.read_struct(CAB_FOLDER)

			endoff = xcp.length()
			if (i + 1) < cab_hdr_struct.cnt_folders:
				endoff = xcp.read_struct_at(xcp.get_label("folder") + (sizeof(CAB_FOLDER) + XENON_DATA_SIZE), CAB_FOLDER).off_cab_start
			size = endoff - folder.off_cab_start

			if size <= 0:
				break

			# init crypto
			init_crypto_at(xcp.offset)  # folder->XenonData
			# decrypt folder
			xcp.perform_function_at(folder.off_cab_start, size, XeCryptRc4)

	print("Renaming the XCP file...")
	# renaming is quicker than copying
	if args.keep:
		# copy instead of renaming so we can keep the original file
		copyfile(args.input + ".xcp", args.input + ".cab")
	else:
		# renaming is quicker than copying
		rename(args.input + ".xcp", args.input + ".cab")

	if not isdir(args.input):
		print("Creating output directory...")
		makedirs(args.input)

	print("Extracting CAB file...")
	# extract the cabinet file and make sure it exited properly
	assert extract_cab(args.input + ".cab", args.input), "CAB extraction failed!"

	print("Merging the extracted files...")
	# merge the files together to make them into one file
	with StreamIO(args.input + ".bin") as f0:
		for single in listdir(args.input):
			with open(join(args.input, single), "rb") as f1:
				while True:
					buff = f1.read(BUFF_SIZE)
					if not buff:
						break
					f0.write(buff)
		print("Converting to a LIVE package...")
		# really hacky way to make it a LIVE file
		f0.write_ubytes_at(0, b"LIVE")

	print("Cleaning up...")
	# clean up
	if not args.keep:
		remove(args.input + ".cab")
	for single in listdir(args.input):
		remove(join(args.input, single))
	rmdir(args.input)

	print("Done!")

if __name__ == "__main__":
	main()