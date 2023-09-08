#!/usr/bin/env python3

from struct import pack
from enum import IntEnum
from pathlib import Path

from XeCrypt import XeCryptCpuKeyGen, XeCryptKeyVaultEncrypt

class ConsoleType(IntEnum):
	RETAIL_PHAT = 0
	RETAIL_SLIM = 1
	TEST_KIT    = 2
	DEVKIT      = 3

def set_fuseline(fuse_data: bytes | bytearray, line: int, value: str | int | bytes | bytearray) -> bytearray:
	if type(fuse_data) is bytes:
		fuse_data = bytearray(fuse_data)

	if type(value) is int:
		value = pack(">Q", value)
	elif type(value) is str:
		assert len(value) == 16, "Invalid fuse line"
		value = bytes.fromhex(value)

	assert len(value) == 8, "Invalid fuse line"
	fuse_data[(line * 8):(line * 8) + 8] = value

	return fuse_data

def main() -> int:
	cpu_key = bytes.fromhex("EDD52AE49E4E0FAA3B186288DC8E5715")  # XeCryptCpuKeyGen() 50542B1369572BAEBDB26405FBDA1622
	dvd_key = bytes.fromhex("8E168C4DBB56F38B66CB66B7B4F60441")
	console_type = ConsoleType.DEVKIT

	print("CPU key: " + cpu_key.hex().upper())
	print("DVD key: " + dvd_key.hex().upper())

	# create fuse buffer 12 lines by 8 bytes
	fuse_data = bytearray(12 * 8)
	# ("8s", fuse_data, 0, bytes.fromhex("C0FFFFFFFFFFFFFF"))  # line #1
	fuse_data = set_fuseline(fuse_data, 0, "C0FFFFFFFFFFFFFF")  # line #1
	fuse_data[0x38:0x38 + 1] = b"\xF0"

	# read the KV
	kv_path = Path("KV/banned.bin")
	kv_data = bytearray(kv_path.read_bytes())

	# update the DVD key
	kv_data[0x100:0x100 + 0x10] = dvd_key

	# encrypt the KV with the specified CPU key
	kv_data = XeCryptKeyVaultEncrypt(cpu_key, kv_data)

	# update console type
	fuse_data[8:8 + 6] = bytes.fromhex("0F0F0F0F0F0F")
	if console_type == ConsoleType.TEST_KIT:
		fuse_data[0xE:0xE + 2] = bytes.fromhex("F00F")
	elif console_type == ConsoleType.DEVKIT:
		fuse_data[0xE:0xE + 2] = bytes.fromhex("0F0F")
	elif console_type == ConsoleType.RETAIL_PHAT:
		fuse_data[0xE:0xE + 2] = bytes.fromhex("0FF0")
	elif console_type == ConsoleType.RETAIL_SLIM:
		fuse_data[0xE:0xE + 2] = bytes.fromhex("F0F0")

	# update CPU key in fuses
	fuse_data = set_fuseline(fuse_data, 3, cpu_key[:8])
	fuse_data = set_fuseline(fuse_data, 4, cpu_key[:8])
	fuse_data = set_fuseline(fuse_data, 5, cpu_key[8:16])
	fuse_data = set_fuseline(fuse_data, 6, cpu_key[8:16])

	# setup fuse path
	fuse_path = Path("Output/Zero/fuses.bin")
	# write fuses
	fuse_path.write_bytes(fuse_data)
	# setup KV path
	kv_path = Path("Output/Zero/kv_enc.bin")
	# write the KV
	kv_path.write_bytes(kv_data)

	# print fuse lines
	print()
	print("Fuses:")
	for i in range(12):
		print(fuse_data[i * 8:(i * 8) + 8].hex().upper())

	# print output paths
	print()
	print(f"KV written to \"{str(kv_path.absolute())}\"!")
	print(f"Fuses written to \"{str(fuse_path.absolute())}\"!")

	return 0

if __name__ == "__main__":
	exit(main())