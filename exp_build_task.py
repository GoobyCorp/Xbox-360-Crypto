#!/usr/bin/env python3

from build_lib import assemble_patch
from exp_signer import sign_exp
from bin2lang import Language, lang_format

PATCH_DIR = "Patches"

def main() -> None:
	print("Assembling HVPP...")
	assemble_patch("Patches/Spoofy.S", "Output/Spoofy.bin", PATCH_DIR)
	print("Signing HVPP...")
	sign_exp("Output/Spoofy.bin", "Output/Spoofy_signed.bin")
	print("Outputting HVPP...")
	lang_format("Output/Spoofy_signed.bin", "Output/Spoofy.h", Language.CPLUSPLUS, "ExpansionData")
	print("Done!")

if __name__ == "__main__":
	main()