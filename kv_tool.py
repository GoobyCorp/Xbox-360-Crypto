#!/usr/bin/env python3

from pathlib import Path
from struct import pack_into, unpack_from

from XeCrypt import XeCryptKeyVaultEncrypt

CONSOLE_DEVKIT      = "0F0F0F0F0F0F0F0F"
CONSOLE_PHAT_RETAIL = "0F0F0F0F0F0F0FF0"
CONSOLE_SLIM_RETAIL = "0F0F0F0F0F0FF0F0"
CONSOLE_TESTKIT     = "0F0F0F0F0F0FF00F"

def main() -> None:
	cpu_key = bytes.fromhex("A55F6604990DD4736DE6A0E09FC576F1")
	dvd_key = bytes.fromhex("C7F720142AB22847757398FEB4AECDD1")
	console_type = CONSOLE_DEVKIT

	print("CPU key: " + cpu_key.hex().upper())
	print("DVD key: " + dvd_key.hex().upper())

	# devkit
	# fuseset 01: 0F0F0F0F0F0F0F0F
	# retail
	# fuseset 01: 0F0F0F0F0F0F0FF0
	# testkit
	# fuseset 01: 0F0F0F0F0F0FF00F
	# slim retail (trinity/corona)
	# fuseset 01: 0F0F0F0F0F0FF0F0

	fuse_lines = [
		"C0FFFFFFFFFFFFFF",
		"0000000000000000",  # line #2 - console type
		"0000000000000000",
		"0000000000000000",  # line #4 - CPU #1
		"0000000000000000",  # line #5 - CPU #2
		"0000000000000000",  # line #6 - CPU #3
		"0000000000000000",  # line #7 - CPU #4
		"F000000000000000",
		"0000000000000000",
		"0000000000000000",
		"0000000000000000",
		"0000000000000000"
	]
	fuse_data = bytearray(b"".join([bytes.fromhex(x) for x in fuse_lines]))

	kv_path = Path("KV/banned.bin")
	kv_data = bytearray(kv_path.read_bytes())

	fuse_path = Path("Output/Zero/fuses.bin")

	pack_into("16s", kv_data, 0x100, dvd_key)
	kv_data = XeCryptKeyVaultEncrypt(cpu_key, kv_data)

	# update console type
	pack_into("8s", fuse_data, 8, bytes.fromhex(console_type))
	# update CPU key in fuses
	pack_into("8s", fuse_data, 0x18, cpu_key[:8])
	pack_into("8s", fuse_data, 0x20, cpu_key[:8])
	pack_into("8s", fuse_data, 0x28, cpu_key[8:8 + 8])
	pack_into("8s", fuse_data, 0x30, cpu_key[8:8 + 8])

	fuse_path.write_bytes(fuse_data)
	kv_path = Path("Output/Zero/kv_enc.bin")
	kv_path.write_bytes(kv_data)

	print("\nFuses:")
	for i in range(12):
		print(fuse_data[i * 8:(i * 8) + 8].hex().upper())

if __name__ == "__main__":
	main()