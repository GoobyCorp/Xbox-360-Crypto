#!/usr/bin/env python3

# reference: https://tools.ietf.org/html/draft-jaganathan-rc4-hmac-03

__description__ = "A script to check if Xbox 360 keyvaults are banned or not"

import socket
from os import urandom
from binascii import crc32
from datetime import datetime
from struct import pack_into, unpack_from
from argparse import ArgumentParser, FileType

from XeCrypt import *
from StreamIO import *

# pip install pycryptodome
from Crypto.Hash import SHA1
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import PKCS1_v1_5

XMACS_RSA_PUB_2048 = None

XEAS_REALM = "xeas.gtm.xboxlive.com"
XETGS_REALM = "xetgs.gtm.xboxlive.com"
SERVER_PORT = 88
BUFF_SIZE = 4096

"""
struct EDATA {
	struct HEADER {
			OCTET Checksum[16];
			OCTET Confounder[8];
	} Header;
	OCTET Data[0];
} edata;
"""

def HMAC_RC4_encrypt(key: (bytes, bytearray), dec_data: (bytes, bytearray), msg_type: int) -> (bytes, bytearray):
	k1 = XeCryptHmacMd5(key, msg_type.to_bytes(4, "little"))
	k2 = k1  # no idea why this is done

	confounder = bytes.fromhex("9B6BFACB5C488190")
	checksum = XeCryptHmacMd5(k2, confounder + dec_data)
	k3 = XeCryptHmacMd5(k1, checksum)

	XeCryptRc4EcbKey(k3)
	confounder = XeCryptRc4(confounder)
	data = XeCryptRc4(dec_data)

	# refer to edata struct
	return checksum + confounder + data

def HMAC_RC4_decrypt(key: (bytes, bytearray), enc_data: (bytes, bytearray), msg_type: int) -> (bytes, bytearray):
	k1 = XeCryptHmacMd5(key, msg_type.to_bytes(4, "little"))
	k2 = k1  # no idea why this is done

	# refer to edata struct
	checksum = enc_data[:16]
	confounder = enc_data[16:16 + 8]
	data = enc_data[16 + 8:]

	k3 = XeCryptHmacMd5(k1, checksum)

	XeCryptRc4EcbKey(k3)
	confounder = XeCryptRc4(confounder)
	data = XeCryptRc4(data)

	# check the checksum
	assert checksum == XeCryptHmacMd5(k2, confounder + data), "Invalid HMAC"
	return confounder + data

def compute_client_name(console_id: (bytes, bytearray)) -> (bytes, bytearray):
	num = 0
	for i in range(5):
		num = (num | console_id[i]) << 8
		num &= 0xFFFFFFFFFFFFFFFF
	num2 = num >> 8
	num3 = (num2 & 0xFFFFFFFF) & 15
	text = f"XE.{num2 >> 4}{num3}@xbox.com"
	if len(text) != 24:
		for i in range(24 - len(text)):
			text = text[:3] + "0" + text[3:]
	return text.encode("ASCII")

def compute_kdc_nonce(key: (bytes, bytearray)) -> (bytes, bytearray):
	key = XeCryptHmacMd5(key, bytes.fromhex("7369676E61747572656B657900"))
	return XeCryptHmacMd5(key, XeCryptMd5(b"\x02\x04\x00\x00", b"\x00\x00\x00\x00"))

# def get_tick_count() -> int:
#	return int(uptime() * 1000)

def get_file_time() -> int:
	dt0 = datetime.strptime("12:00 AM, January 1, 1601 UTC", "%I:%M %p, %B %d, %Y %Z")
	dt1 = datetime.utcnow()
	return int((dt1 - dt0).total_seconds() * 10000000)

# def get_seeded_random(seed: int, size: int) -> (bytes, bytearray):
#	random.seed(seed)
#	return random.getrandbits(size * 8).to_bytes(size, "little")

def generate_timestamp() -> (bytes, bytearray):
	array = bytearray(bytes.fromhex("301AA011180F32303132313231323139303533305AA10502030B3543"))
	s = datetime.utcnow().strftime("%Y%m%d%H%M%S") + "Z"
	pack_into("<15s", array, 6, s.encode("ASCII"))
	return array

def get_title_auth_data(key: (bytes, bytearray), data: (bytes, bytearray)) -> (bytes, bytearray):
	src_arr = XeCryptHmacSha(compute_kdc_nonce(key), data[:66])
	array = bytearray(82)
	pack_into("<16s", array, 0, src_arr[:16])
	pack_into("<66s", array, 16, data)
	return array

def get_xmacs_logon_key(stream) -> (bytes, bytearray):
	rsa_prov = PKCS1_OAEP.new(XeCryptBnQwNeRsaKeyToRsaProv(XMACS_RSA_PUB_2048))
	rand_key = urandom(16)  # get_seeded_random(get_tick_count(), 16)
	array_2 = reverse(rsa_prov.encrypt(rand_key))
	array_3 = bytearray(read_file("bin/KV/XMACSREQ.bin"))
	pack_into("<256s", array_3, 0x2C, array_2)
	serial_num = stream.read_ubytes_at(0xB0, 12)
	console_cert = stream.read_ubytes_at(0x9C8, 0x1A8)
	console_prv_key = stream.read_ubytes_at(0x298, 0x1D0)
	console_id = stream.read_ubytes_at(0x9CA, 5)

	client_name = compute_client_name(console_id)
	rsa_prov = PKCS1_v1_5.new(XeCryptBnQwNeRsaKeyToRsaProv(console_prv_key))
	file_time = get_file_time().to_bytes(8, "big")
	ts = generate_timestamp()
	enc_ts = HMAC_RC4_encrypt(rand_key, ts, 1)
	array_7 = reverse(rsa_prov.sign(SHA1.new(file_time + serial_num + XeCryptSha(rand_key))))
	pack_into("<8s", array_3, 0x12C, file_time)
	pack_into("<12s", array_3, 0x134, serial_num)
	pack_into("<128s", array_3, 0x140, array_7)
	pack_into("<424s", array_3, 0x1C0, console_cert)
	pack_into("<52s", array_3, 0x3E0, enc_ts)
	pack_into("<15s", array_3, 0x430, client_name)
	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	sock.connect((XEAS_REALM, SERVER_PORT))
	sock.send(array_3)
	src_arr_4 = sock.recv(BUFF_SIZE)
	sock.close()
	array_8 = src_arr_4[53:53 + 108]
	src_arr_5 = HMAC_RC4_decrypt(compute_kdc_nonce(rand_key), array_8, 1203)
	return src_arr_5[76:76 + 16]

def main() -> None:
	global XMACS_RSA_PUB_2048

	parser = ArgumentParser(description=__description__)
	parser.add_argument("input", type=FileType("rb"), help="The KV file to test")
	args = parser.parse_args()

	XMACS_RSA_PUB_2048 = read_file("Keys/XMACS_pub.bin")
	assert crc32(XMACS_RSA_PUB_2048) == 0xE4F01473, "Invalid XMACS public key"

	with StreamIO(args.input, Endian.BIG) as sio:
		xmacs_logon_key = get_xmacs_logon_key(sio)
		console_id = sio.read_ubytes_at(0x9CA, 5)
		src_arr_0 = XeCryptSha(sio.read_ubytes_at(0x9C8, 0xA8))
	array_1 = bytearray(read_file("bin/KV/apReq1.bin"))
	array_2 = compute_client_name(console_id)
	print("Attempting logon for \"" + array_2.decode("ASCII") + "\"...")
	print("Creating Kerberos AS-REQ...")
	pack_into("<24s", array_1, 258, array_2[:24])
	pack_into("<20s", array_1, 36, src_arr_0[:20])
	ts = generate_timestamp()
	pack_into("<52s", array_1, 176, HMAC_RC4_encrypt(xmacs_logon_key, ts, 1))
	with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
		sock.connect((XEAS_REALM, SERVER_PORT))
		sock.send(array_1)
		print("Sending Kerberos AS-REQ...")
		array_4 = sock.recv(BUFF_SIZE)
	print("AS replied wanting pre-auth data...")
	print("Creating new Kerberos AS-REQ...")
	array_5 = array_4[-16:]
	array_6 = bytearray(read_file("bin/KV/apReq2.bin"))
	pack_into("<24s", array_6, 286, array_2)
	pack_into("<20s", array_6, 36, src_arr_0)
	ts = generate_timestamp()
	pack_into("<52s", array_6, 204, HMAC_RC4_encrypt(xmacs_logon_key, ts, 1))
	pack_into("<16s", array_6, 68, array_5)
	with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
		sock.connect((XEAS_REALM, SERVER_PORT))
		sock.send(array_6)
		print("Sending Kerberos AS-REQ...")
		array_8 = sock.recv(BUFF_SIZE)
	print("Got AS-REP...")
	print("Decrypting our session key...")
	print("Creating Kerberos TGS-REQ...")
	# write_file("bin/KV/APRESP.bin", array_8)
	array_9 = array_8[-210:]
	array_10 = HMAC_RC4_decrypt(xmacs_logon_key, array_9, 8)
	array_11 = array_10[27:27 + 16]
	# write_file("bin/KV/test.bin", array_10)
	print("Setting TGS ticket...")
	array_12 = array_8[168:168 + 345]
	array_13 = bytearray(read_file("bin/KV/TGSREQ.bin"))
	pack_into("<345s", array_13, 437, array_12[:345])
	array_14 = bytearray(read_file("bin/KV/authenticator.bin"))
	pack_into("<15s", array_14, 40, array_2[:15])
	s = datetime.utcnow().strftime("%Y%m%d%H%M%S") + "Z"
	pack_into("<15s", array_14, 109, s.encode("ASCII"))
	pack_into("<16s", array_14, 82, XeCryptMd5(array_13[954:954 + 75]))
	pack_into("<153s", array_13, 799, HMAC_RC4_encrypt(array_11, array_14, 7))
	key = compute_kdc_nonce(array_11)
	array_15 = bytearray(read_file("bin/KV/servicereq.bin"))
	pack_into("<150s", array_13, 55, HMAC_RC4_encrypt(key, array_15, 1201))
	array_16 = array_6[116:116 + 66]
	pack_into("<82s", array_13, 221, get_title_auth_data(array_11, array_16))
	print("Sending our TGS-REQ...")
	with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
		sock.connect((XETGS_REALM, SERVER_PORT))
		sock.send(array_13)
		array_17 = sock.recv(BUFF_SIZE)
	print("Got TGS-REP...")
	# write_file("bin/KV/tgsres.bin", array_17)
	print("Decrypting logon status...")
	array_18 = array_17[50:50 + 84]
	value = HMAC_RC4_decrypt(key, array_18, 1202)
	# array_19 = array_17[58:58 + 208]
	# b0 = RC4_HMAC_decrypt(key, array_19, 1202)
	# write_file("bin/KV/resp.bin", b0)
	(logon_status_code,) = unpack_from("<I", value, 8)
	print(f"Logon status: 0x{logon_status_code:04X}")
	if logon_status_code != 0x8015190D:
		print("Unbanned")
	else:
		print("Banned")

if __name__ == "__main__":
	main()