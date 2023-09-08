#!/usr/bin/env python3

from os import urandom

from keystore import load_and_verify_1bl_pub
from XeCrypt import XeCryptBnQwNeRsaKeyGen, XeCryptSha, PY_XECRYPT_RSA_KEY

def main() -> int:
	pub_key = load_and_verify_1bl_pub()

	print("0x" + pub_key.mod_inv.to_bytes(8, "big").hex().upper())
	# print("0x" + (pub_key.r & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "big").hex().upper())
	# print("0x" + (pub_key.inv_r & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "big").hex().upper())


	v0 = pub_key.n
	print(hex(v0))
	v1 = v0 * 3 ^ 2
	print(hex(v1))
	v2 = v1 * v0
	print(hex(v2))
	v3 = ~v2 + 2
	print(hex(v3))

	v0 &= 0xFFFFFFFFFFFFFFFF
	print(f"0x{v0:X}")
	v1 &= 0xFFFFFFFFFFFFFFFF
	print(f"0x{v1:X}")
	v2 &= 0xFFFFFFFFFFFFFFFF
	print(f"0x{v2:X}")
	v3 &= 0xFFFFFFFFFFFFFFFF
	print(f"0x{v3:X}")

	return 0

	(pub_key, prv_key) = XeCryptBnQwNeRsaKeyGen(2048)

	print(prv_key.hex().upper())

	salt = urandom(10)
	data = urandom(0x4000)
	h = XeCryptSha(data)

	key = PY_XECRYPT_RSA_KEY(prv_key)
	sig = key.sig_create(h, salt)

	print(sig.hex().upper())
	print(key.sig_verify(sig, h, salt))

	return 0

if __name__ == "__main__":
	exit(main())