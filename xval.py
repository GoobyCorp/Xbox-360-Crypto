#!/usr/bin/env python3

# XVal.py By Redline99, updated xvals by cz
# Decrypts the "X:" Value from the Xbox 360 dashboard
# This can indicate if the console has been flagged
# for some types of security violations

# Modified by Visual Studio to be more modern :D

import hmac
from hashlib import sha1
from struct import unpack
from argparse import ArgumentParser

# pip install pycryptodome
from Crypto.Cipher import DES

FLAG_SSB_NONE                         = 0x0000
FLAG_SSB_AUTH_EX_FAILURE_D            = 0x0001	# DEPRECATED
FLAG_SSB_AUTH_EX_NO_TABLE_D           = 0x0002	# DEPRECATED
FLAG_SSB_AUTH_EX_RESERVED             = 0x0004
FLAG_SSB_INVALID_DVD_GEOMETRY         = 0x0008
FLAG_SSB_INVALID_DVD_DMI              = 0x0010
FLAG_SSB_DVD_KEYVAULT_PAIR_MISMATCH_D = 0x0020	# DEPRECATED
FLAG_SSB_CRL_DATA_INVALID_D           = 0x0040	# DEPRECATED
FLAG_SSB_CRL_CERTIFICATE_REVOKED      = 0x0080
FLAG_SSB_UNAUTHORIZED_INSTALL         = 0x0100
FLAG_SSB_KEYVAULT_POLICY_VIOLATION    = 0x0200
FLAG_SSB_CONSOLE_BANNED_D             = 0x0400	# DEPRECATED
FLAG_SSB_ODD_VIOLATION                = 0x0800
FLAG_SSB_CIV_HASH_FAILURE             = 0x1000
FLAG_SSB_AUTH_EX_NO_TABLE             = 0x2000
FLAG_SSB_CRL_DATA_INVALID             = 0x4000
FLAG_SSB_ODD_ENFORCE_THROUGHPUT_LOW   = 0x8000
FLAG_SSB_ODD_ENFORCE_THROUGHPUT_HIGH  = 0x10000

def decrypt_xval(console_serial: str, console_xval: str) -> bytes:
	console_serial = console_serial.encode("ASCII")
	console_xval = bytes.fromhex(console_xval.replace("-", ""))
	assert len(console_serial) == 0xC, "Invalid console serial length"
	des_key = hmac.new(console_serial + b"\0", b"XBOX360SSB", sha1).digest()[:8]
	des = DES.new(des_key, DES.MODE_ECB)
	assert len(console_xval) == 8, "Invalid decrypted XVal size"
	return des.decrypt(console_xval)

def display_results(xval: (bytes, bytearray)) -> None:
	# extract our integers formt the buffer
	(xval_h, xval_l) = unpack(">LL", xval)
	# nothing is flagged in secdata.bin, all is good from this standpoint
	if xval_h == 0 and xval_l == 0:
		print("Secdata is Clean")
	# secdata was prob tampered with
	elif xval_h == 0xFFFFFFFF and xval_l == 0xFFFFFFFF:
		print("Secdata is invalid")
	# most likely the serial or xval is incorrect
	elif xval_h != 0 and xval_l != 0:
		print("Secdata decryption error")
	# the high dword = 0 and low dword not 0
	else:
		if xval_l & FLAG_SSB_AUTH_EX_FAILURE_D:  # AP25 related
			print("AuthEx Challenge Failure (Deprecated)")
		if xval_l & FLAG_SSB_AUTH_EX_NO_TABLE_D:  # AP25 related
			print("AuthEx Table missing (Deprecated)")
		if xval_l & FLAG_SSB_AUTH_EX_RESERVED:  # AP25 related
			print("AuthEx Reserved Flag")
		if xval_l & FLAG_SSB_INVALID_DVD_GEOMETRY:
			print("Invalid DVD Geometry")
		if xval_l & FLAG_SSB_INVALID_DVD_DMI:
			print("Invalid DVD DMI")
		if xval_l & FLAG_SSB_DVD_KEYVAULT_PAIR_MISMATCH_D:
			print("DVD Keyvault Pair Mismatch (Deprecated)")
		if xval_l & FLAG_SSB_CRL_DATA_INVALID_D:
			print("Invalid CRL Data (Deprecated)")
		if xval_l & FLAG_SSB_CRL_CERTIFICATE_REVOKED:
			print("CRL Certificate Revoked")
		if xval_l & FLAG_SSB_UNAUTHORIZED_INSTALL:
			print("Unauthorized Install")
		if xval_l & FLAG_SSB_KEYVAULT_POLICY_VIOLATION:
			print("Keyvault Policy Violation")
		if xval_l & FLAG_SSB_CONSOLE_BANNED_D:
			print("Console Banned (Deprecated)")
		if xval_l & FLAG_SSB_ODD_VIOLATION:
			print("ODD Violation")
		if xval_l & FLAG_SSB_CIV_HASH_FAILURE:  # AP25 related
			print("Content Intergrity Verification Hash Failure")
		if xval_l & FLAG_SSB_AUTH_EX_NO_TABLE:	# AP25 related
			print("AuthEx Table missing")
		if xval_l & FLAG_SSB_CRL_DATA_INVALID:
			print("Invalid CRL Data")
		if xval_l & FLAG_SSB_ODD_ENFORCE_THROUGHPUT_LOW:
			print("Enforce ODD Throughput Low")
		if xval_l & FLAG_SSB_ODD_ENFORCE_THROUGHPUT_HIGH:
			print("Enforce ODD Throughput High")
		if xval_l & 0xFFFE0000:  # mask for bits we dont have a description for,
			print("Unknown Violation(s)")

def main() -> None:
	parser = ArgumentParser(description="A script to decrypt the \"X:\" Value from the Xbox 360 dashboard")
	parser.add_argument("serial", type=str, help="The console's serial number")
	parser.add_argument("xval", type=str, help="The console's X: value")
	args = parser.parse_args()
	display_results(decrypt_xval(args.serial, args.xval))

if __name__ == "__main__":
	main()