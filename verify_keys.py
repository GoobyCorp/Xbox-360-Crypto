#!/usr/bin/env python3

# Used to check key files to make sure you have all the keys necessary to use this tool suite

from pathlib import Path
from binascii import crc32

KEY_NAMES = {
	0xD416B5E1: "1BL_pub",
	0xDCC4B906: "HVX_prv",
	0xE86E10FD: "Master_pub",
	0x4233AD81: "PIRS_prv_dev",
	0x4C523F84: "PIRS_pub_retail",
	0x490C9D35: "SD_prv",
	0xE4F01473: "XMACS_pub"
}

def main() -> None:
	key_path = Path("Keys")
	for file in key_path.iterdir():
		if str(file).endswith(".bin"):
			data = file.read_bytes()
			cksm = crc32(data)

			if cksm in list(KEY_NAMES.keys()):
				print(f"Found {KEY_NAMES[cksm]}!")
				if file.name != f"{KEY_NAMES[cksm]}.bin":
					print(f"Renaming \"{file.name}\" to {KEY_NAMES[cksm]}.bin")
					print(file.absolute())
					print("to")
					print(file.parent.joinpath(f"{KEY_NAMES[cksm]}.bin").absolute())
					file.rename(file.parent.absolute().joinpath(f"{KEY_NAMES[cksm]}.bin"))

if __name__ == "__main__":
	main()