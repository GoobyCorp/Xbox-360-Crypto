#!/usr/bin/env python3

from struct import pack_into, unpack_from

from StreamIO import *
from XeCrypt import BIGBLOCK, calc_page_ecc, check_page_ecc, fix_page_ecc

def all_zero(b: bytes) -> bool:
	for i in range(len(b)):
		if b[i] != 0:
			return False
	return True

def main() -> None:
	with open(r"C:\Users\John\Desktop\xeBuild_1.21_zero\zero_rgl.bin", "rb") as f:
		with StreamIO(f, Endian.BIG) as sio:
			while sio.tell() < len(sio):
				page = sio.read(512)
				spare = sio.read(16)

				bb = BIGBLOCK.from_buffer_copy(spare)
				print(bb.block_id)

				if check_page_ecc(page, spare):
					# print("YA #1!")
					pass
				else:
					print("NO #1!")
					break

				if all_zero(page):
					# print("YA #2!")
					pass

if __name__ == "__main__":
	main()