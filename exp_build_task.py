#!/usr/bin/env python3

import subprocess
from pathlib import Path

from exp_signer import sign_exp
from bin2lang import lang_format

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
	print("Assembling HVPP...")
	assemble_patch("Patches/HVPP.S", "Output/HVPP.bin", PATCH_DIR)
	print("Signing HVPP...")
	sign_exp("Output/HVPP.bin", "Output/HVPP_signed.bin", 0x48565050, False)
	print("Outputting HVPP...")
	lang_format("Output/HVPP_signed.bin", "Output/HVPP.h", "cpp", "ExpansionData")
	print("Done!")

if __name__ == "__main__":
	main()