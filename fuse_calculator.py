#!/usr/bin/env python3

def main() -> None:
	# print(12 * 8 * 8)

	fuse_pos = 720
	fuse_line = fuse_pos // 64
	print(f"Fuse Pos:  0x{fuse_pos:04X}")

	fuse_pos %= 64
	fuse_pos -= 1
	fuses = ["0"] * 64
	fuses[fuse_pos] = "1"
	fuse_seq = "0b" + "".join(fuses)
	fuse_mask = eval(fuse_seq)

	print(f"Fuse Seq:  {fuse_seq}")
	print(f"Fuse Line: {fuse_line}")
	print(f"Fuse Mask: 0x{fuse_mask:016X}")
	print(f"Fuse Val:  {fuse_mask}")

if __name__ == "__main__":
	main()