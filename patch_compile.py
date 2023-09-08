#!/usr/bin/env python3

from pathlib import Path

from build_lib import *

PATCH_DIR = "Patches"


def main() -> int:
	assemble_patch("Patches/Zero/HVK/vfuses_17489.S", "Output/Zero/vfuses_17489.bin")
	assemble_patch("Patches/Zero/HVK/17559-dev/RGLoader-dev.S", "Output/Zero/RGL.bin")

	assemble_patch("Patches/Zero/SD/cd_9452_patches.S", "Output/Zero/cd_9452.bin")
	# assemble_patch("Patches/Zero/HVK/printlr_17559.S", "Output/Zero/printlr_17559.bin")

	cd_data = Path("X:/Xbox 360/xeBuild_1.21/Builds/17559 - FB/bootloaders_zephyr/cd_9452.bin").read_bytes()
	patch_data = Path("Output/Zero/cd_9452.bin").read_bytes()
	cd_data = apply_patches(cd_data, patch_data)
	Path("X:/Xbox 360/xeBuild_1.21/Builds/17559 - FB/bootloaders_zephyr/cd_9452_test.bin").write_bytes(cd_data)

	# hv_data = Path("Research/HV/hypervisor_17559.bin").read_bytes()
	# patch_data = Path("Output/Zero/printlr_17559.bin").read_bytes()
	# hv_data = apply_patches(hv_data, patch_data)
	# Path("Output/Zero/HV_printlr.bin").write_bytes(hv_data)

	# assemble_patch("Patches/XAM/17559-dev/rglXam.S", "Output/xam_17559.rglp")
	# assemble_patch("Patches/Zero/SD/sd_17489_patches.S", "Output/Zero/xell.bin")
	# assemble_patch("Patches/HVPP.S", "Output/HVPP.bin")

	# assemble_patch("Patches/Test Kit/patches.S", "Output/testkit.bin", PATCH_DIR)
	assemble_patch("Patches/NonZero/HVK/17559-dev/RGLoader-dev.S", "Output/NonZero/RGL_hdd.bin")

	# assemble_patch("Patches/remap_bootanim_17559.S", "Output/remap_bootanim_17559.bin")
	# assemble_patch("Patches/RGH3/rgh3_bl.S", "Output/rgh3_bl.bin")

	# assemble syscall zero payload
	assemble_devkit_patch("Patches/SC0.S", "Output/Compiled/Patches/SC0_dev.bin")
	assemble_devkit_patch("Patches/SC0.S", "Output/Compiled/Patches/SpoofySC0_dev.bin", "SPOOFY")

	assemble_devkit_patch("Patches/CheckPatchFuses.S", "Output/Compiled/Patches/CheckPatchFuses.bin")

	# test_data = Path("Output/Compiled/Patches/test.bin").read_bytes()

	# dwords = (len(test_data) - 4) // 4
	# print(f"0x{dwords:X} ({dwords}) quads = 0x{dwords * 4:X} ({dwords * 4}) bytes")
	# for i in range(0, len(test_data), 4):
	#	cnk = test_data[i:i + 4]
	#	print(".long 0x" + cnk.hex().upper())

	vfuses_data = Path("Output/Zero/vfuses_17489.bin").read_bytes()
	rgl_data = Path("Output/Zero/RGL.bin").read_bytes()
	Path("Output/Zero/VRGL.bin").write_bytes(vfuses_data[:-4] + rgl_data)

	# assemble_patch("Patches/Dump100C0.S", "Output/Dump100C0.bin")
	# assemble_patch("Patches/SpoofyTest.S", "Output/SpoofyTest.bin")

	return 0


if __name__ == "__main__":
	exit(main())
