#!/usr/bin/env python3

from build_lib import *
from bin2lang import Language, lang_format
from exp_signer import sign_exp, ExpansionMagic

DEFAULT_EXP_ID = 0x48565050
XBONLINE_EXP_ID = 0x48564050

def main() -> int:
	# assemble HVPP
	print("Assembling HVPP.S...")
	assemble_patch("Patches/HVPP.S", "Output/Compiled/HVPP.bin")

	print("Assembling devkit Spoofy.S...")
	assemble_devkit_patch("Patches/Spoofy.S", "Output/Compiled/Spoofy_dev.bin")
	print("Assembling retail Spoofy.S...")
	assemble_retail_patch("Patches/Spoofy.S", "Output/Compiled/Spoofy_retail.bin")

	# generic
	# spoofy
	print("Creating generic Spoofy...")
	sign_exp("Output/Compiled/Spoofy_dev.bin", "Output/Compiled/Generic/Spoofy_signed.bin", exp_id=DEFAULT_EXP_ID)
	lang_format("Output/Compiled/Generic/Spoofy_signed.bin", "Output/Compiled/Generic/Spoofy.h", Language.CPLUSPLUS, "ExpansionData")

	# devkit
	print("Creating generic devkit HVPP...")
	sign_exp("Output/Compiled/HVPP.bin", "Output/Compiled/Generic/HVPP_dev_signed.bin", exp_id=DEFAULT_EXP_ID)
	lang_format("Output/Compiled/Generic/HVPP_dev_signed.bin", "Output/Compiled/Generic/HVPP_dev.h", Language.CPLUSPLUS, "ExpansionData")

	# test kit
	print("Creating generic test kit HVPP...")
	sign_exp("Output/Compiled/HVPP.bin", "Output/Compiled/Generic/HVPP_test_signed.bin", exp_magic=ExpansionMagic.SIGM, exp_id=DEFAULT_EXP_ID)
	lang_format("Output/Compiled/Generic/HVPP_test_signed.bin", "Output/Compiled/Generic/HVPP_test.h", Language.CPLUSPLUS, "ExpansionData")

	# retail
	print("Creating generic retail HVPP...")
	sign_exp("Output/Compiled/HVPP.bin", "Output/Compiled/Generic/HVPP_retail_signed.bin", encrypt=False, exp_id=DEFAULT_EXP_ID)
	lang_format("Output/Compiled/Generic/HVPP_retail_signed.bin", "Output/Compiled/Generic/HVPP_retail.h", Language.CPLUSPLUS, "ExpansionData")

	# xbOnline
	# spoofy
	print("Creating xbOnline Spoofy...")
	sign_exp("Output/Compiled/Spoofy_dev.bin", "Output/Compiled/xbOnline/Spoofy_signed.bin", exp_id=XBONLINE_EXP_ID)
	lang_format("Output/Compiled/xbOnline/Spoofy_signed.bin", "Output/Compiled/xbOnline/Spoofy.h", Language.CPLUSPLUS, "ExpansionData")

	# devkit
	print("Creating xbOnline devkit HVPP...")
	sign_exp("Output/Compiled/HVPP.bin", "Output/Compiled/xbOnline/HVPP_dev_signed.bin", exp_id=XBONLINE_EXP_ID)
	lang_format("Output/Compiled/xbOnline/HVPP_dev_signed.bin", "Output/Compiled/xbOnline/HVPP_dev.h", Language.CPLUSPLUS, "ExpansionData")

	# test kit
	print("Creating xbOnline test kit HVPP...")
	sign_exp("Output/Compiled/HVPP.bin", "Output/Compiled/xbOnline/HVPP_test_signed.bin", exp_magic=ExpansionMagic.SIGM, exp_id=XBONLINE_EXP_ID)
	lang_format("Output/Compiled/xbOnline/HVPP_test_signed.bin", "Output/Compiled/xbOnline/HVPP_test.h", Language.CPLUSPLUS, "ExpansionData")

	# retail
	print("Creating xbOnline retail HVPP...")
	sign_exp("Output/Compiled/HVPP.bin", "Output/Compiled/xbOnline/HVPP_retail_signed.bin", encrypt=False, exp_id=XBONLINE_EXP_ID)
	lang_format("Output/Compiled/xbOnline/HVPP_retail_signed.bin", "Output/Compiled/xbOnline/HVPP_retail.h", Language.CPLUSPLUS, "ExpansionData")

	print("Done!")

	return 0

if __name__ == "__main__":
	exit(main())