#!/usr/bin/env python3

from gzip import decompress
from os.path import join, isfile

# constants
XELL_DIR = "XeLL"
GZIP_HEADER_SIZE = 10
GZIP_FOOTER_SIZE = 8
XELL_SIZE        = 256 * 1024
XELL_FOOTER_SIZE = 16
XELL_STAGE1_SIZE = 16 * 1024
XELL_STAGE2_SIZE = (XELL_SIZE - XELL_STAGE1_SIZE - XELL_FOOTER_SIZE - GZIP_HEADER_SIZE - GZIP_FOOTER_SIZE)

# utilities
def read_file(filename: str, text: bool = False) -> (bytes, str):
	with open(filename, "r" if text else "rb", buffering=4096) as f:
		data = f.read()
	return data

def write_file(filename: str, data: (str, bytes, bytearray)) -> None:
	with open(filename, "w" if type(data) == str else "wb", buffering=4096) as f:
		f.write(data)

def main() -> None:
	# xell-1f.bin
	xell_1f = read_file(join(XELL_DIR, "xell-1f.bin"))
	xell_1f_stage_1 = xell_1f[:XELL_STAGE1_SIZE]
	write_file(join(XELL_DIR, "xell-1f-stage-1.bin"), xell_1f_stage_1)
	xell_1f_stage_2 = xell_1f[XELL_STAGE1_SIZE:XELL_STAGE1_SIZE + XELL_STAGE2_SIZE]
	write_file(join(XELL_DIR, "xell-1f-stage-2-compressed.elf"), xell_1f_stage_2)
	xell_1f_stage_2 = decompress(xell_1f_stage_2)
	write_file(join(XELL_DIR, "xell-1f-stage-2-decompressed.elf"), xell_1f_stage_2)

	# xell-2f.bin
	xell_2f = read_file(join(XELL_DIR, "xell-2f.bin"))
	xell_2f_stage_1 = xell_2f[:XELL_STAGE1_SIZE]
	write_file(join(XELL_DIR, "xell-2f-stage-1.bin"), xell_2f_stage_1)
	xell_2f_stage_2 = xell_2f[XELL_STAGE1_SIZE:XELL_STAGE1_SIZE + XELL_STAGE2_SIZE]
	write_file(join(XELL_DIR, "xell-2f-stage-2-compressed.elf"), xell_2f_stage_2)
	xell_2f_stage_2 = decompress(xell_2f_stage_2)
	write_file(join(XELL_DIR, "xell-2f-stage-2-decompressed.elf"), xell_2f_stage_2)

	# xell-gggggg.bin
	xell_gggggg = read_file(join(XELL_DIR, "xell-gggggg.bin"))
	xell_gggggg_stage_1 = xell_gggggg[:XELL_STAGE1_SIZE]
	write_file(join(XELL_DIR, "xell-gggggg-stage-1.bin"), xell_gggggg_stage_1)
	xell_gggggg_stage_2 = xell_gggggg[XELL_STAGE1_SIZE:XELL_STAGE1_SIZE + XELL_STAGE2_SIZE]
	write_file(join(XELL_DIR, "xell-gggggg-stage-2-compressed.elf"), xell_gggggg_stage_2)
	xell_gggggg_stage_2 = decompress(xell_gggggg_stage_2)
	write_file(join(XELL_DIR, "xell-gggggg-stage-2-decompressed.elf"), xell_gggggg_stage_2)

if __name__ == "__main__":
	main()