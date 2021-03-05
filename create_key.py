#!/usr/bin/env python3

# This script creates an Xbox 360 RSA keypair

from pathlib import Path

from XeCrypt import *

def main() -> None:
	(pub_key, prv_key) = XeCryptBnQwNeRsaKeyGen(2048)
	Path("Keys/custom_pub.bin").write_bytes(pub_key)
	Path("Keys/custom_prv.bin").write_bytes(prv_key)
	print("Done!")

if __name__ == "__main__":
	main()