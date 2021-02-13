#!/usr/bin/env python3

from os import urandom
from array import array
from struct import pack, unpack

from XeCrypt import *

def main() -> None:
	hvx_prv = read_file("Keys/HVX_prv.bin")
	exp_final = read_file("Output/HVPP_test_signed.bin")

	b_hash = XeCryptRotSumSha(exp_final[:0x30])
	b_sig = exp_final[0x30:0x30 + 0x100]
	print(XeKeysPkcs1Verify(b_sig, b_hash, hvx_prv[:XECRYPT_RSAPUB_2048_SIZE]))

if __name__ == "__main__":
	main()