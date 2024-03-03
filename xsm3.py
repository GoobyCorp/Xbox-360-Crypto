#!/usr/bin/env python3

# References:
# http://oct0xor.github.io/2017/05/03/xsm3/
# https://github.com/oct0xor/xbox_security_method_3
# https://github.com/InvoxiPlayGames/libxsm3/blob/master/xsm3.c

from enum import IntEnum
from typing import TypeVar
from random import randbytes
from struct import pack_into, unpack_from

from XeCrypt import *
from build_lib import *

BinLike = TypeVar("BinLike", bytes, bytearray)

STATIC_KEY_1 = b""
STATIC_KEY_2 = b""

DYNAMIC_KEY_1 = b""
DYNAMIC_KEY_2 = b""

SBOX = bytes([
	0xB0, 0x3D, 0x9B, 0x70, 0xF3, 0xC7, 0x80, 0x60,
	0x73, 0x9F, 0x6C, 0xC0, 0xF1, 0x3D, 0xBB, 0x40,
	0xB3, 0xC8, 0x37, 0x14, 0xDF, 0x49, 0xDA, 0xD4,
	0x48, 0x22, 0x78, 0x80, 0x6E, 0xCD, 0xE7, 0x00,
	0x81, 0x86, 0x68, 0xE1, 0x5D, 0x7C, 0x54, 0x2C,
	0x55, 0x7B, 0xEF, 0x48, 0x42, 0x7B, 0x3B, 0x68,
	0xE3, 0xDB, 0xAA, 0xC0, 0x0F, 0xA9, 0x96, 0x20,
	0x95, 0x05, 0x93, 0x94, 0x9A, 0xF6, 0xA3, 0x64,
	0x5D, 0xCC, 0x76, 0x00, 0xE5, 0x08, 0x19, 0xE8,
	0x8D, 0x29, 0xD7, 0x4C, 0x21, 0x91, 0x17, 0xF4,
	0xBC, 0x6A, 0xB3, 0x80, 0x83, 0xC6, 0xD4, 0x90,
	0x9B, 0xAE, 0x0E, 0xFE, 0x2E, 0x4A, 0xF2, 0x00,
	0x73, 0x88, 0xD9, 0x40, 0x66, 0xC5, 0xD4, 0x08,
	0x57, 0xB1, 0x89, 0x48, 0xDC, 0x54, 0xFC, 0x43,
	0x6A, 0x26, 0x87, 0xB8, 0x09, 0x5F, 0xCE, 0x80,
	0xE4, 0x0B, 0x05, 0x9C, 0x24, 0xF3, 0xDE, 0xE2,
	0x3E, 0xEC, 0x38, 0x8A, 0xA2, 0x55, 0xA4, 0x50,
	0x4E, 0x4B, 0xE9, 0x58, 0x7F, 0x9F, 0x7D, 0x80,
	0x23, 0x0C, 0x4D, 0x80, 0x05, 0x44, 0x26, 0xB8,
	0xE9, 0xD8, 0xBC, 0xE6, 0x76, 0x3A, 0x6E, 0xA4,
	0x19, 0xDE, 0xC2, 0xD0, 0xC4, 0xBC, 0xC3, 0x5C,
	0x59, 0xDF, 0x16, 0x46, 0x39, 0x70, 0xF4, 0xEE,
	0x2D, 0x58, 0x5A, 0xA8, 0x17, 0x86, 0x6B, 0x60,
	0x29, 0x58, 0x4D, 0xD2, 0x5F, 0x28, 0x7A, 0xD8,
	0x8E, 0x79, 0xEA, 0x82, 0x94, 0x33, 0x31, 0x81,
	0xD9, 0x22, 0xD5, 0x10, 0xDA, 0x92, 0xA0, 0x7D,
	0x3D, 0xDA, 0xAC, 0x1C, 0xA2, 0x53, 0x31, 0xB8,
	0x3C, 0x96, 0x52, 0x00, 0x82, 0x6B, 0x56, 0xA0,
	0xD3, 0xC2, 0x40, 0xC7, 0x1B, 0x7F, 0xDC, 0x01,
	0x72, 0x70, 0xB1, 0x8C, 0x01, 0x09, 0x09, 0x36,
	0xFC, 0x97, 0xEA, 0xDE, 0xE3, 0x0D, 0xAE, 0x7E,
	0xE3, 0x0D, 0xAE, 0x7E, 0x33, 0x69, 0x80, 0x40
])

UsbdSecPlainTextData = bytes([
	0xD1, 0xD2, 0xF2, 0x80, 0x6E, 0xBA, 0x0C, 0xC0,
	0xB6, 0xC4, 0xC9, 0xD8, 0x61, 0x75, 0x1D, 0x1A,
	0x3F, 0x95, 0x58, 0xBE, 0xD8, 0x0D, 0xE2, 0xC0,
	0xD0, 0x21, 0x79, 0x20, 0x65, 0x2D, 0x99, 0x40,
	0x3C, 0x96, 0x52, 0x00, 0x1B, 0x7F, 0xDC, 0x01,
	0x82, 0x1C, 0x13, 0xD8, 0x33, 0x69, 0x80, 0x40,
	0xFC, 0x97, 0xEA, 0xDE, 0x08, 0xEA, 0x14, 0xDC,
	0xEB, 0x0F, 0x6A, 0x18, 0x6F, 0x78, 0x2C, 0xB0,
	0xD3, 0xC2, 0x40, 0xC7, 0x82, 0x6B, 0x56, 0xA0,
	0x19, 0x09, 0x36, 0xE0, 0x72, 0x70, 0xB1, 0x8C,
	0xE3, 0x0D, 0xAE, 0x7E, 0x50, 0xA5, 0x2B, 0xE2,
	0xC9, 0xAF, 0xC7, 0x70, 0x1C, 0x29, 0x80, 0x56,
	0x24, 0xF0, 0x66, 0xFA, 0x02, 0x2B, 0x58, 0x98,
	0x8F, 0xE4, 0xD1, 0x3C, 0x6E, 0x38, 0x2A, 0xFF,
	0xB8, 0xFA, 0x35, 0xB0, 0x52, 0x49, 0xC5, 0xB4,
	0x66, 0xFA, 0x47, 0x55, 0x6C, 0x8D, 0x40, 0x08
])

UsbdSecXSM3GetIdentificationProtocolData = bytes([
	0x49, 0x4B, 0x00, 0x00, 0x17, 0x04, 0xE1, 0x11,
	0x54, 0x15, 0xED, 0x88, 0x55, 0x21, 0x01, 0x33,
	0x00, 0x00, 0x80, 0x02, 0x5E, 0x04, 0x8E, 0x02,
	0x03, 0x00, 0x01, 0x01, 0xC1
])

UsbdSecXSM3SetChallengeProtocolData = bytes([
	0x09, 0x40, 0x00, 0x00, 0x1C, 0x0A, 0x0F, 0x6B,
	0x0B, 0xA1, 0x18, 0x26, 0x5F, 0x83, 0x3C, 0x45,
	0x13, 0x49, 0x53, 0xBD, 0x18, 0x61, 0x73, 0xCF,
	0x29, 0xDE, 0x2C, 0xD8, 0x66, 0xE4, 0xAE, 0x34,
	0xA9, 0x9C
])

UsbdSecXSM3GetResponseChallengeProtocolData = bytes([
	0x49, 0x4C, 0x00, 0x00, 0x28, 0x81, 0xBD, 0x7C,
	0xB3, 0x70, 0xBD, 0x76, 0x1A, 0x2F, 0x28, 0x6E,
	0xD1, 0xF2, 0xC3, 0x8E, 0xF9, 0x0B, 0xB2, 0x83,
	0x49, 0xCB, 0x4B, 0x24, 0xA2, 0x90, 0x6C, 0x27,
	0xB1, 0x05, 0x0A, 0xB0, 0x47, 0x09, 0x75, 0x16,
	0x07, 0xE1, 0xD7, 0xE8, 0xAF, 0x57
])

UsbdSecXSM3SetVerifyProtocolData1 = bytes([
	0x09, 0x41, 0x00, 0x00, 0x10, 0x5A, 0xDD, 0x1B,
	0xA0, 0x74, 0x87, 0xB7, 0x62, 0xB7, 0xA5, 0x8F,
	0x34, 0xFF, 0xE3, 0xD1, 0xD9, 0xA7
])

UsbdSecXSM3GetResponseVerifyProtocolData1 = bytes([
	0x49, 0x4C, 0x00, 0x00, 0x10, 0x5A, 0x9C, 0xD6,
	0x72, 0xB3, 0x70, 0x8D, 0xA7, 0x57, 0x01, 0x06,
	0x50, 0x20, 0x60, 0xA9, 0xBC, 0xDE
])

xsm3_id_data_ms_controller = bytes([
	0x49, 0x4B, 0x00, 0x00, 0x17, 0x41, 0x41, 0x41,
	0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
	0x00, 0x00, 0x80, 0x02, 0x5E, 0x04, 0x8E, 0x02,
	0x03, 0x00, 0x01, 0x01, 0x16
])

class CryptMode(IntEnum):
	DECRYPT = 0
	ENCRYPT = 1

def xsm3_calculate_checksum(packet: BinLike) -> int:
	size = packet[4] + 5
	csum = 0
	for i in range(5, size):
		csum ^= packet[i]
	return csum & 0xFF

def xsm3_verify_checksum(packet: BinLike) -> bool:
	pkt_len = packet[4] + 5
	return xsm3_calculate_checksum(packet) == packet[pkt_len]

def UsbdSecXSM3AuthenticationCrypt(key: BinLike, data: BinLike, mode: CryptMode) -> BinLike:
	c = XeCryptDes3((key * 2)[:0x18], XeCryptDes3.MODE_CBC, bytes(8))
	if mode == CryptMode.DECRYPT:
		return c.decrypt(data)
	elif mode == CryptMode.ENCRYPT:
		return c.encrypt(data)
	return b""

def UsbdSecXSM3AuthenticationMac(key: BinLike, salt: BinLike | None, data: BinLike) -> tuple[BinLike, BinLike]:
	temp = b""

	c = XeCryptDes(key[:8])
	if salt:
		v0 = int.from_bytes(salt, "big", signed=False)
		v0 += 1
		salt = (v0 & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "big", signed=False)
		temp = c.encrypt(salt)

	for i in range(0, len(data), 8):
		v0 = int.from_bytes(temp, "big", signed=False)
		v1 = int.from_bytes(data[i:i + 8], "big", signed=False)
		v0 ^= v1
		temp = (v0 & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "big", signed=False)
		temp = c.encrypt(temp)

	temp = bytearray(temp)
	temp[0] ^= 0x80

	c = XeCryptDes3((key * 2)[:0x18])
	return (salt, c.encrypt(temp))

def UsbdSecXSMAuthenticationAcr(key: BinLike, cert: BinLike, data: BinLike) -> BinLike:
	block = data[:4] + cert[:4]

	iv = XeCryptParveEcb(key, SBOX, data[0x10:])

	cd = XeCryptParveEcb(key, SBOX, block)

	ab = XeCryptParveCbcMac(key, SBOX, iv, UsbdSecPlainTextData[:0x80])
	output = XeCryptChainAndSumMac(cd, ab, UsbdSecPlainTextData[:0x80])

	v0 = int.from_bytes(output, "big", signed=False)
	v1 = int.from_bytes(ab, "big", signed=False)
	output = (v0 ^ v1).to_bytes(8, "big", signed=False)

	return output

class XSM3State:
	xsm3_identification_data: BinLike = None
	xsm3_random_console_data: BinLike = None
	xsm3_console_id: BinLike = None
	xsm3_challenge_init_hash: BinLike = None
	xsm3_random_controller_data: BinLike = None

	xsm3_random_console_data_enc: BinLike = None
	xsm3_random_console_data_swap_enc: BinLike = None

	def __init__(self, xsm3_ident_packet: BinLike):
		self.reset()

		self.xsm3_set_identification_data(xsm3_ident_packet)

	def __enter__(self):
		return self

	def __exit__(self, exc_type, exc_val, exc_tb):
		pass

	def reset(self) -> None:
		self.xsm3_identification_data = None
		self.xsm3_random_console_data = None
		self.xsm3_console_id = None
		self.xsm3_challenge_init_hash = None
		self.xsm3_random_controller_data = None

		self.xsm3_random_console_data_enc = None
		self.xsm3_random_console_data_swap_enc = None

	def xsm3_set_identification_data(self, ident_packet: BinLike) -> None:
		assert len(ident_packet) == 0x1D, "Invalid identification packet!"

		if not xsm3_verify_checksum(ident_packet):
			print("[ Checksum failed when setting identification data! ]")

		(v0, v1, v2, v3, v4, v5) = unpack_from(">15s 2H B H B", ident_packet, 5)
		self.xsm3_identification_data = bytearray(0x20)
		pack_into(">15s x 2H 2B H", self.xsm3_identification_data, 0, v0, v1, v2, v3, v5, v4)

	def xsm3_do_challenge_init(self, challenge_packet: BinLike) -> BinLike | None:
		assert len(challenge_packet) == 0x22, "Invalid challenge packet!"

		if not xsm3_verify_checksum(challenge_packet):
			print("[ Checksum failed when validating challenge init! ]")
			return

		# decrypt the packet content using the static key from the keyvault
		xsm3_decryption_buffer = UsbdSecXSM3AuthenticationCrypt(STATIC_KEY_1, challenge_packet[5:5 + 0x18], CryptMode.DECRYPT)
		# first 0x10 bytes are random data
		self.xsm3_random_console_data = xsm3_decryption_buffer[:0x10]
		# next 0x8 bytes are from the console certificate
		self.xsm3_console_id = xsm3_decryption_buffer[0x10:0x10 + 8]
		# last 4 bytes of the packet are the last 4 bytes of the MAC
		(salt, incoming_packet_mac) = UsbdSecXSM3AuthenticationMac(STATIC_KEY_2, None, challenge_packet[5:5 + 0x18])

		# validate the MAC
		if incoming_packet_mac[4:] != challenge_packet[5 + 0x18:5 + 0x18 + 4]:
			print("[ MAC failed when validating challenge init! ]")
			return

		# the random value is swapped at an 8 byte boundary
		xsm3_random_console_data_swap = self.xsm3_random_console_data[8:8 + 8] + self.xsm3_random_console_data[:8]
		# and then encrypted - the regular value encrypted with key 1, the swapped value encrypted with key 2
		self.xsm3_random_console_data_enc = UsbdSecXSM3AuthenticationCrypt(STATIC_KEY_1, self.xsm3_random_console_data, CryptMode.ENCRYPT)
		self.xsm3_random_console_data_swap_enc = UsbdSecXSM3AuthenticationCrypt(STATIC_KEY_2, xsm3_random_console_data_swap, CryptMode.ENCRYPT)

		# generate random data
		self.xsm3_random_controller_data = randbytes(0x10)

		# set header and packet length of challenge response
		xsm3_challenge_response = bytearray(0x30)
		xsm3_challenge_response[0] = 0x49  # packet magic
		xsm3_challenge_response[1] = 0x4C
		xsm3_challenge_response[4] = 0x28  # packet length

		# copy random controller, random console data to the encryption buffer
		xsm3_decryption_buffer = bytearray(xsm3_decryption_buffer)
		xsm3_decryption_buffer[:0x10] = self.xsm3_random_controller_data
		xsm3_decryption_buffer[0x10:0x10 + 0x10] = self.xsm3_random_console_data

		# save the sha1 hash of the decrypted contents for later
		self.xsm3_challenge_init_hash = XeCryptSha(xsm3_decryption_buffer)

		# encrypt challenge response packet using the encrypted random key
		xsm3_challenge_response[5:5 + 0x20] = UsbdSecXSM3AuthenticationCrypt(self.xsm3_random_console_data_enc, xsm3_decryption_buffer, CryptMode.ENCRYPT)
		# calculate MAC using the encrypted swapped random key and use it to calculate ACR
		(salt, xsm3_response_packet_mac) = UsbdSecXSM3AuthenticationMac(self.xsm3_random_console_data_swap_enc, None, xsm3_challenge_response[5:5 + 0x20])
		# calculate ACR and append to the end of the xsm3_challenge_response
		xsm3_challenge_response[5 + 0x20:5 + 0x20 + 8] = UsbdSecXSMAuthenticationAcr(xsm3_response_packet_mac, self.xsm3_console_id, self.xsm3_identification_data)
		# calculate the checksum for the response packet
		xsm3_challenge_response[5 + 0x28] = xsm3_calculate_checksum(xsm3_challenge_response)

		self.xsm3_random_console_data = bytearray(self.xsm3_random_console_data)
		self.xsm3_random_console_data[:4] = self.xsm3_random_controller_data[0xC:0xC + 4]
		self.xsm3_random_console_data[4:4 + 4] = self.xsm3_random_console_data[0xC:0xC + 4]

		return xsm3_challenge_response[:5 + xsm3_challenge_response[4] + 1]

	def xsm3_do_challenge_verify(self, challenge_packet: BinLike) -> BinLike | None:
		assert len(challenge_packet) == 0x16, "Invalid challenge packet!"

		if not xsm3_verify_checksum(challenge_packet):
			print("[ Checksum failed when validating challenge verify! ]")
			return

		xsm3_decryption_buffer = UsbdSecXSM3AuthenticationCrypt(self.xsm3_random_controller_data, challenge_packet[5:5 + 8], CryptMode.DECRYPT)
		self.xsm3_random_console_data[8:8 + 8] = xsm3_decryption_buffer

		(salt, xsm3_incoming_packet_mac) = UsbdSecXSM3AuthenticationMac(self.xsm3_challenge_init_hash, self.xsm3_random_console_data, challenge_packet[5:5 + 8])

		if xsm3_incoming_packet_mac != challenge_packet[5 + 8:5 + 8 + 8]:
			print("[ MAC failed when validating challenge verify! ]")
			return

		# set header and packet length of challenge response
		xsm3_challenge_response = bytearray(0x30)
		xsm3_challenge_response[0] = 0x49  # packet magic
		xsm3_challenge_response[1] = 0x4C
		xsm3_challenge_response[4] = 0x10  # packet length

		# calculate the ACR value and encrypt it into the outgoing packet using the encrypted random
		xsm3_decryption_buffer = UsbdSecXSMAuthenticationAcr(self.xsm3_identification_data, self.xsm3_console_id, self.xsm3_random_console_data[8:])
		xsm3_challenge_response[5:5 + 8] = UsbdSecXSM3AuthenticationCrypt(self.xsm3_random_console_data_enc, xsm3_decryption_buffer[:8], CryptMode.ENCRYPT)
		# calculate the MAC of the encrypted packet and append it to the end
		(salt, xsm3_challenge_response[5 + 8:5 + 8 + 8]) = UsbdSecXSM3AuthenticationMac(self.xsm3_random_console_data_swap_enc, self.xsm3_random_console_data, xsm3_challenge_response[5:5 + 8])
		# calculate the checksum for the response packet
		xsm3_challenge_response[5 + 0x10] = xsm3_calculate_checksum(xsm3_challenge_response)

		return xsm3_challenge_response[:5 + xsm3_challenge_response[4] + 1]

def main() -> int:
	global STATIC_KEY_1, STATIC_KEY_2, DYNAMIC_KEY_1, DYNAMIC_KEY_2

	kv = XECRYPT_KEYVAULT.from_buffer_copy(read_file("KV/banned.bin"))

	STATIC_KEY_1 = bytes(kv.global_dev_2des_key_1)
	STATIC_KEY_2 = bytes(kv.global_dev_2des_key_2)
	DYNAMIC_KEY_1 = bytes.fromhex("F19D6F2CB1EE6AC4635336A54C11007D")
	DYNAMIC_KEY_2 = bytes.fromhex("C45582C89FC3DAD28C1FBBCF3D049B6F")

	# cid = bytearray.fromhex("086D40C2C6")
	# cid += bytearray.fromhex("808182")
	# hcid = XeCryptSha(cid)[:0x10]

	with XSM3State(xsm3_id_data_ms_controller) as xsm3:
		xsm3_challenge_response = xsm3.xsm3_do_challenge_init(UsbdSecXSM3SetChallengeProtocolData)
		print(f"0x{len(xsm3_challenge_response):X}")
		xsm3_challenge_response = xsm3.xsm3_do_challenge_verify(UsbdSecXSM3GetResponseVerifyProtocolData1)
		# print(f"0x{len(xsm3_challenge_response):X}")

	return 0

if __name__ == "__main__":
	exit(main())