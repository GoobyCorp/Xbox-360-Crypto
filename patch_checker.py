#!/usr/bin/env python3

from StreamIO import *

def is_overlapping(x1: int, x2: int, y1: int, y2: int):
	return x1 <= y2 and y1 <= x2

def eval_patches(patch_data: (bytes, bytearray)) -> None:
	patches = []
	with StreamIO(patch_data, Endian.BIG) as psio:
		while True:
			addr = psio.read_uint32()
			if addr == 0xFFFFFFFF:
				break
			size = psio.read_uint32()
			patch = psio.read_ubytes(size * 4)
			patches.append(range(addr, addr + len(patch)))

	for i in range(len(patches)):
		tmp = list(patches)
		patch_range = tmp.pop(i)

		x = patch_range
		for j in range(len(tmp)):
			y = tmp[j]
			if is_overlapping(x.start, x.stop + 1, y.start, y.stop + 1):
				print("Patch Conflict!")
				print(f"Patch A: 0x{x.start:08X} - 0x{x.stop:08X}")
				print(f"Patch B: 0x{y.start:08X} - 0x{y.stop:08X}")

def read_file(filename: str) -> bytes:
	with open(filename, "rb") as f:
		data = f.read()
	return data

def write_file(filename: str, data: (bytes, bytearray)) -> None:
	with open(filename, "wb") as f:
		f.write(data)

def main() -> None:
	eval_patches(read_file("Output/Zero/HVK.bin"))

if __name__ == "__main__":
	main()