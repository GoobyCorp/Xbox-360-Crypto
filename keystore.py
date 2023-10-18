#!/usr/bin/env python3

from pathlib import Path
from binascii import crc32

from XeCrypt import XeCryptRsaKey

KEY_PATH = Path("Keys")

# checksums - public keys
CKSM_1BL_PUB    = 0xD416B5E1
CKSM_XMACS_PUB  = 0xE4F01473
CKSM_MASTER_PUB = 0xE86E10FD
# checksums - private keys
CKSM_SB_PRV    = 0x490C9D35
CKSM_HVX_PRV   = 0xDCC4B906

def load_and_verify_1bl_pub() -> XeCryptRsaKey:
	data = (KEY_PATH / "1BL_pub.bin").read_bytes()
	assert crc32(data) == CKSM_1BL_PUB, "Invalid key checksum!"
	return XeCryptRsaKey(data)

def load_and_verify_xmacs_pub() -> XeCryptRsaKey:
	data = (KEY_PATH / "XMACS_pub.bin").read_bytes()
	assert crc32(data) == CKSM_XMACS_PUB, "Invalid key checksum!"
	return XeCryptRsaKey(data)

def load_and_verify_sb_prv() -> XeCryptRsaKey:
	data = (KEY_PATH / "SB_prv.bin").read_bytes()
	assert crc32(data) == CKSM_SB_PRV, "Invalid key checksum!"
	return XeCryptRsaKey(data)

def load_and_verify_hvx_prv() -> XeCryptRsaKey:
	data = (KEY_PATH / "HVX_prv.bin").read_bytes()
	assert crc32(data) == CKSM_HVX_PRV, "Invalid key checksum!"
	return XeCryptRsaKey(data)

def load_and_verify_master_pub() -> XeCryptRsaKey:
	data = (KEY_PATH / "Master_pub.bin").read_bytes()
	assert crc32(data) == CKSM_MASTER_PUB, "Invalid key checksum!"
	return XeCryptRsaKey(data)

__all__ = [
	"load_and_verify_1bl_pub",
	"load_and_verify_xmacs_pub",
	"load_and_verify_sb_prv",
	"load_and_verify_hvx_prv",
	"load_and_verify_master_pub"
]