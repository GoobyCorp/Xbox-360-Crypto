#!/usr/bin/env python3

from pathlib import Path

from XeCrypt import *

def main() -> None:
	pub_key = Path("Keys/Master_pub.bin").read_bytes()
	kv_data = Path("KV/banned.bin").read_bytes()

	# this CPU key is banned!
	print(XeCryptKeyVaultVerify(bytes.fromhex("9179C6012E1ECD5EE5378335AC99C960"), kv_data, pub_key))

if __name__ == "__main__":
	main()