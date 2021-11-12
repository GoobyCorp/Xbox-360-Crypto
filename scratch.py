#!/usr/bin/env python3

from pathlib import Path

from XeCrypt import *

def main() -> None:
	_1bl_key = PY_XECRYPT_RSA_KEY(Path("Keys/1BL_pub.bin").read_bytes())
	print(_1bl_key.n)
	print(_1bl_key.e)

if __name__ == "__main__":
	main()