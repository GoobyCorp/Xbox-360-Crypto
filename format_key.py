#!/usr/bin/env python3

from bin2lang import lang_format

def main() -> None:
	print(lang_format("Keys/custom_pub.bin", "Output/Zero/ExpPubKey.h", var_name="ExpPubKey"))

if __name__ == "__main__":
	main()