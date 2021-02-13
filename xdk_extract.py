#!/usr/bin/env python3

__author__ = "Visual Studio"
__description__ = "A script to extract XDKRecoveryXenonXXXXX.exe and XDKSetupXenonXXXXX.exe files"
__platforms__ = ["Windows", "Linux", "macOS"]

from ctypes import *
from os import mkdir
from argparse import ArgumentParser
from os.path import join, isfile, isdir

DOSMagic = 0x5A4D
PEMagic = b"PE\x00\x00"
CABMagic = b"MSCF"
MachineI386 = 0x14C
NumberOfDataDirectories = 16
NameSize = 8

class CabHeader(Structure):
	_fields_ = [
		("Magic", (c_ubyte * 4)),
		("Reserved", c_uint32),
		("PackedSize", c_uint32)
	]

class DOSHeader(Structure):
	_fields_ = [
		("Magic", c_uint16),
		("UsedBytesInTheLastPage", c_uint16),
		("FileSizeInPages", c_uint16),
		("NumberOfRelocationItems", c_uint16),
		("HeaderSizeInParagraphs", c_uint16),
		("MinimumExtraParagraphs", c_uint16),
		("MaximumExtraParagraphs", c_uint16),
		("InitialRelativeSS", c_uint16),
		("InitialSP", c_uint16),
		("InitialSP", c_uint16),
		("InitialIP", c_uint16),
		("InitialRelativeCS", c_uint16),
		("AddressOfRelocationTable", c_uint16),
		("OverlayNumber", c_uint16),
		("Reserved", (c_uint16 * 4)),
		("OEMid", c_uint16),
		("OEMinfo", c_uint16),
		("Reserved2", (c_uint16 * 10)),
		("AddressOfNewExeHeader", c_uint32)
	]

class FileHeader(Structure):
	_fields_ = [
		("Machine", c_uint16),
		("NumberOfSections", c_uint16),
		("TimeDateStamp", c_uint32),
		("PointerToSymbolTable", c_uint32),
		("NumberOfSymbols", c_uint32),
		("SizeOfOptionalHeader", c_uint16),
		("Characteristics", c_uint16),
	]

class DataDirectory(Structure):
	_fields_ = [
		("RelativeVirtualAddress", c_uint32),
		("Size", c_uint32)
	]

class PE32Header(Structure):
	_fields_ = [
		("Magic", c_uint16),
		("MajorLinkerVersion", c_ubyte),
		("MinorLinkerVersion", c_ubyte),
		("SizeOfCode", c_uint32),
		("SizeOfInitializedData", c_uint32),
		("SizeOfUninitializedData", c_uint32),
		("AddressOfEntryPoint", c_uint32),
		("BaseOfCode", c_uint32),
		("BaseOfData", c_uint32),
		("ImageBase", c_uint32),
		("SectionAlignment", c_uint32),
		("FileAlignment", c_uint32),
		("MajorOperatingSystemVersion", c_uint16),
		("MinorOperatingSystemVersion", c_uint16),
		("MajorImageVersion", c_uint16),
		("MinorImageVersion", c_uint16),
		("MajorSubsystemVersion", c_uint16),
		("MinorSubsystemVersion", c_uint16),
		("Win32VersionValue", c_uint32),
		("SizeOfImage", c_uint32),
		("SizeOfHeaders", c_uint32),
		("CheckSum", c_uint32),
		("Subsystem", c_uint16),
		("DLLCharacteristics", c_uint16),
		("SizeOfStackReserve", c_uint32),
		("SizeOfStackCommit", c_uint32),
		("SizeOfHeapReserve", c_uint32),
		("SizeOfHeapCommit", c_uint32),
		("LoaderFlags", c_uint32),
		("NumberOfRvaAndSize", c_uint32),
		("DataDirectories", (DataDirectory * NumberOfDataDirectories))
	]

class SectionHeader(Structure):
	_fields_ = [
		("Name", (c_ubyte * NameSize)),
		("VirtualSize", c_uint32),
		("VirtualAddress", c_uint32),
		("SizeOfRawData", c_uint32),
		("PointerToRawData", c_uint32),
		("PointerToRelocations", c_uint32),
		("PointerToLineNumbers", c_uint32),
		("NumberOfRelocations", c_uint16),
		("NumberOfLineNumbers", c_uint16),
		("Characteristics", c_uint32),
	]

def get_size_of_image(stream) -> int:
	dos_header = DOSHeader.from_buffer_copy(stream.read(sizeof(DOSHeader)))
	assert dos_header.Magic == DOSMagic, "Invalid DOS header"
	stream.seek(dos_header.AddressOfNewExeHeader)
	magic = stream.read(4)
	assert magic == PEMagic, "Invalid or corrupt executable"
	file_header = FileHeader.from_buffer_copy(stream.read(sizeof(FileHeader)))
	assert file_header.Machine == MachineI386, "Input file isn't an i386 executable"
	#pe32_header = PE32Header.from_buffer_copy(stream.read(sizeof(PE32Header)))
	stream.seek(sizeof(PE32Header), 1)
	top_offset = 0
	for i in range(file_header.NumberOfSections):
		section_header = SectionHeader.from_buffer_copy(stream.read(sizeof(SectionHeader)))
		top_offset = max(top_offset, section_header.PointerToRawData + section_header.SizeOfRawData)
	return top_offset

def main() -> None:
	parser = ArgumentParser(description="A script to extract XDKRecoveryXenonXXXXX.X(X).exe and XDKSetupXenonXXXXX.X(X).exe files")
	parser.add_argument("input", type=str, help="The input executable to extract from")
	parser.add_argument("output", type=str, default="output", help="The directory to write cabinet files out to")
	parser.add_argument("-p", "--prefix", type=str, default="data", help="The prefix to use on the cabinet files")
	args = parser.parse_args()

	assert isfile(args.input), "Input file missing"

	if not isdir(args.output):
		mkdir(args.output)

	with open(args.input, "rb") as recovery_exe:
		pe_size = get_size_of_image(recovery_exe)
		print(f"Start of data: 0x{pe_size:04X}")
		index = 0
		while True:
			recovery_exe.seek(pe_size)
			cab_header = CabHeader.from_buffer_copy(recovery_exe.read(sizeof(CabHeader)))
			if not bytes(cab_header.Magic) == CABMagic:
				break
			recovery_exe.seek(pe_size)
			cab_data = recovery_exe.read(cab_header.PackedSize)
			cab_file_name = f"{args.prefix}_{index}.cab"
			index += 1
			print(f"Extracting \"{cab_file_name}\"...")
			with open(join(args.output, cab_file_name), "wb") as f:
				f.write(cab_data)
			pe_size += cab_header.PackedSize

if __name__ == "__main__":
	main()