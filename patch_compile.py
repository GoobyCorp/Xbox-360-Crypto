#!/usr/bin/env python3

import subprocess
from pathlib import Path

BIN_DIR = "bin"
PATCH_DIR = "Patches"

def assemble_patch(asm_filename: str, bin_filename: str, *includes) -> None:
	args = [str(Path(BIN_DIR) / "xenon-as.exe"), "-be", "-many", "-mregnames", asm_filename, "-o", "temp.elf"]
	args.extend(["-I", str(Path(asm_filename).parent.absolute())])
	[args.extend(["-I", str(Path(x).absolute())]) for x in includes]
	result = subprocess.run(args, shell=True, stdout=subprocess.DEVNULL)
	assert result.returncode == 0, f"Patch assembly failed with error code {result.returncode}"

	args = [str(Path(BIN_DIR) / "xenon-objcopy.exe"), "temp.elf", "-O", "binary", bin_filename]
	result = subprocess.run(args, shell=True, stdout=subprocess.DEVNULL)
	assert result.returncode == 0, f"ELF conversion failed with error code {result.returncode}"

	Path("temp.elf").unlink()

def main() -> None:
	assemble_patch("Patches/Zero/HVK/vfuses_17489.S", "Output/Zero/vfuses_17489.bin", PATCH_DIR)
	assemble_patch("Patches/Zero/HVK/17559-dev/RGLoader-dev.S", "Output/Zero/RGL-zero.bin", PATCH_DIR)
	assemble_patch("Patches/Zero/SD/sd_17489_patches.S", "Output/Zero/xell.bin", PATCH_DIR)
	assemble_patch("Patches/HVPP.S", "Output/Zero/HVPP.bin", PATCH_DIR)

	# assemble_patch("C://Users/John/Desktop/BlowFuselines.S", r"C://Users/John/Desktop/BlowFuselines.bin", PATCH_DIR)

	p0 = Path("Output/Zero/vfuses_17489.bin")
	p1 = Path("Output/Zero/RGL-zero.bin")
	p2 = Path("Output/Zero/HVK.bin")
	p2.write_bytes(p0.read_bytes()[:-4] + p1.read_bytes())

if __name__ == "__main__":
	main()