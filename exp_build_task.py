#!/usr/bin/env python3

from build_lib import assemble_patch
from exp_signer import sign_exp
from bin2lang import *

PATCH_DIR = "Patches"

def main() -> None:
	print("Assembling HVPP...")
	assemble_patch("Patches/HVPP.S", "Output/HVPP.bin", PATCH_DIR)
	print("Signing HVPP...")
	# sign_exp("Output/HVPP.bin", "Output/HVPP_signed.bin")
	sign_exp("Output/HVPP.bin", "Output/HVPP_signed.bin", key_file="Keys/custom_prv.bin", exp_id=0x74657374)
	print("Outputting HVPP...")
	# lang_format("Output/HVPP_signed.bin", "Output/HVPP.h", Language.CPLUSPLUS, "ExpansionData")
	lang_format("Output/HVPP_signed.bin", "Output/HVPP.h", Language.CPLUSPLUS, "TestExpansionData")
	print("Done!")

if __name__ == "__main__":
	main()