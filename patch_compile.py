#!/usr/bin/env python3

import subprocess
from pathlib import Path

from build_lib import assemble_patch

PATCH_DIR = "Patches"

def main() -> None:
	assemble_patch("Patches/Zero/HVK/vfuses_17489.S", "Output/Zero/vfuses_17489.bin", PATCH_DIR)
	assemble_patch("Patches/Zero/HVK/17559-dev/RGLoader-dev.S", "Output/Zero/RGL-zero.bin", PATCH_DIR)
	assemble_patch("Patches/Zero/SD/sd_17489_patches.S", "Output/Zero/xell.bin", PATCH_DIR)

	# assemble_patch("C://Users/John/Desktop/BlowFuselines.S", r"C://Users/John/Desktop/BlowFuselines.bin", PATCH_DIR)

	p0 = Path("Output/Zero/vfuses_17489.bin")
	p1 = Path("Output/Zero/RGL-zero.bin")
	p2 = Path("Output/Zero/HVK.bin")
	p2.write_bytes(p0.read_bytes()[:-4] + p1.read_bytes())

if __name__ == "__main__":
	main()