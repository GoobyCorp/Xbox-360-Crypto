#!/usr/bin/env python3

from pathlib import Path

from build_lib import *

PATCH_DIR = "Patches"

def main() -> None:
	assemble_patch("Patches/Zero/HVK/vfuses_17489.S", "Output/Zero/vfuses_17489.bin", PATCH_DIR)
	assemble_patch("Patches/Zero/HVK/17559-dev/RGLoader-dev.S", "Output/Zero/RGL.bin", PATCH_DIR)
	assemble_patch("Patches/XAM/17559-dev/rglXam.S", "Output/xam_17559.rglp", PATCH_DIR)
	assemble_patch("Patches/Zero/SD/sd_17489_patches.S", "Output/Zero/xell.bin", PATCH_DIR)
	assemble_patch("Patches/Spoofy.S", "Output/Spoofy.bin", PATCH_DIR)

	assemble_patch("Patches/remap_bootanim_17559.S", "Output/remap_bootanim_17559.bin", PATCH_DIR)

	# assemble_patch("C://Users/John/Desktop/BlowFuselines.S", r"C://Users/John/Desktop/BlowFuselines.bin", PATCH_DIR)

	vfuses_data = Path("Output/Zero/vfuses_17489.bin").read_bytes()
	rgl_data = Path("Output/Zero/RGL.bin").read_bytes()
	Path("Output/Zero/HVK.bin").write_bytes(vfuses_data[:-4] + rgl_data)

if __name__ == "__main__":
	main()