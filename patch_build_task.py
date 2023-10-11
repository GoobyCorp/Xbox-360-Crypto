#!/usr/bin/env python3

import patch_compile
import se_patcher
import patch_checker

def main() -> None:
	print("Compiling...")
	patch_compile.main()
	# print("Patching...")
	# se_patcher.main()
	print("Checking...")
	patch_checker.main()

	print("Done!")

if __name__ == "__main__":
	main()