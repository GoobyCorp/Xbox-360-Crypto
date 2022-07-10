#!/usr/bin/env python3

from build_lib import assemble_patch
from exp_signer import sign_exp, ExpansionMagic
from bin2lang import Language, lang_format

PATCH_DIR = "Patches"

def main() -> int:
	print("Assembling Spoofy.S...")
	assemble_patch("Patches/Spoofy.S", "Output/Spoofy.bin", PATCH_DIR)
	# print("Signing HVPP...")
	sign_exp("Output/Spoofy.bin", "Output/Spoofy_signed.bin")
	# print("Outputting HVPP...")
	lang_format("Output/Spoofy_signed.bin", "Output/Spoofy.h", Language.CPLUSPLUS, "ExpansionData")
	print("Done!")

	# assemble HVPP
	print("Assembling HVPP.S...")
	assemble_patch("Patches/HVPP.S", "Output/HVPP.bin", PATCH_DIR)

	# devkit
	print("Creating devkit HVPP...")
	# print("Signing HVPP...")
	sign_exp("Output/HVPP.bin", "Output/HVPP_dev_signed.bin")
	# print("Outputting HVPP...")
	lang_format("Output/HVPP_dev_signed.bin", "Output/HVPP_dev.h", Language.CPLUSPLUS, "ExpansionData")

	# test kit
	print("Creating test kit HVPP...")
	# assemble_patch("Patches/HVPP.S", "Output/HVPP_test.bin", PATCH_DIR)
	# print("Signing HVPP...")
	sign_exp("Output/HVPP.bin", "Output/HVPP_test_signed.bin", exp_magic=ExpansionMagic.SIGM)
	# print("Outputting HVPP...")
	lang_format("Output/HVPP_test_signed.bin", "Output/HVPP_test.h", Language.CPLUSPLUS, "ExpansionData")

	# retail
	print("Creating retail HVPP...")
	# assemble_patch("Patches/HVPP.S", "Output/HVPP_test.bin", PATCH_DIR)
	# print("Signing HVPP...")
	sign_exp("Output/HVPP.bin", "Output/HVPP_retail_signed.bin", encrypt=False)
	# print("Outputting HVPP...")
	lang_format("Output/HVPP_retail_signed.bin", "Output/HVPP_retail.h", Language.CPLUSPLUS, "ExpansionData")

	print("Done!")

	return 0

if __name__ == "__main__":
	exit(main())