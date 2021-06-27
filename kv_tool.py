#!/usr/bin/env python3

from enum import IntEnum
from pathlib import Path
from struct import pack_into

from XeCrypt import XeCryptCpuKeyGen, XeCryptKeyVaultEncrypt

class ConsoleType(IntEnum):
	RETAIL_PHAT = 0
	RETAIL_SLIM = 1
	TEST_KIT    = 2
	DEVKIT      = 3

def main() -> None:
	cpu_key = XeCryptCpuKeyGen()
	dvd_key = bytes.fromhex("C7F720142AB22847757398FEB4AECDD1")
	console_type = ConsoleType.DEVKIT

	print("CPU key: " + cpu_key.hex().upper())
	print("DVD key: " + dvd_key.hex().upper())

	# create fuse buffer 12 lines by 8 bytes
	fuse_data = bytearray(12 * 8)
	pack_into("8s", fuse_data, 0, bytes.fromhex("C0FFFFFFFFFFFFFF"))  # line #1
	pack_into("1s", fuse_data, 0x38, b"\xF0")  # line #8

	# read the KV
	kv_path = Path("KV/banned.bin")
	kv_data = bytearray(kv_path.read_bytes())

	# update the DVD key
	pack_into("16s", kv_data, 0x100, dvd_key)
	# encrypt the KV with the specified CPU key
	kv_data = XeCryptKeyVaultEncrypt(cpu_key, kv_data)

	# update console type
	pack_into("6s", fuse_data, 8, bytes.fromhex("0F0F0F0F0F0F"))
	if console_type == ConsoleType.TEST_KIT:
		pack_into("2s", fuse_data, 0xE, bytes.fromhex("F00F"))
	elif console_type == ConsoleType.DEVKIT:
		pack_into("2s", fuse_data, 0xE, bytes.fromhex("0F0F"))
	elif console_type == ConsoleType.RETAIL_PHAT:
		pack_into("2s", fuse_data, 0xE, bytes.fromhex("0FF0"))
	elif console_type == ConsoleType.RETAIL_SLIM:
		pack_into("2s", fuse_data, 0xE, bytes.fromhex("F0F0"))

	# update CPU key in fuses
	pack_into("8s8s8s8s", fuse_data, 0x18, cpu_key[:8], cpu_key[:8], cpu_key[8:16], cpu_key[8:16])

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

if __name__ == "__main__":
	main()