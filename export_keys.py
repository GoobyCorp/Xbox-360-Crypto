#!/usr/bin/env python3

from os import urandom
from pathlib import Path

from bin2lang import lang_format

from XeCrypt import *

def main() -> None:
	lang_format("Keys/custom_prv.bin", var_name="TestPrvKey")
	lang_format("Keys/custom_pub.bin", var_name="TestPubKey")

	prv_key = Path("Keys/custom_prv.bin").read_bytes()
	d = urandom(0x100)
	h = XeCryptRotSumSha(d)
	s = XeCryptBnQwBeSigCreate(h, b"SALTTEST", prv_key)
	s = XeCryptBnQwNeRsaPrvCrypt(s, prv_key)

	lang_format(d, var_name="TestData")
	lang_format(s, var_name="TestSignature")

if __name__ == "__main__":
	main()