#!/usr/bin/env python3

from pathlib import Path

from build_lib import *

PATCH_DIR = "Patches"


def main() -> int:
	assemble_rgl_flash("Patches/RGL/17559-dev/RGLoader-dev.S", "Output/NonZero/RGL_flash.bin")
	assemble_rgl_hdd("Patches/RGL/17559-dev/RGLoader-dev.S", "Output/NonZero/RGL_hdd.bin")

	assemble_rgl_vfuses_flash("Patches/RGL/17559-dev/RGLoader-dev.S", "Output/Zero/VRGL_flash.bin")
	assemble_rgl_vfuses_hdd("Patches/RGL/17559-dev/RGLoader-dev.S", "Output/Zero/VRGL_hdd.bin")

	# assemble syscall zero payload
	assemble_devkit_patch("Patches/SC0.S", "Output/Compiled/Patches/SC0_dev.bin")
	assemble_devkit_patch("Patches/SC0.S", "Output/Compiled/Patches/SpoofySC0_dev.bin", "SPOOFY")

	return 0


if __name__ == "__main__":
	exit(main())
