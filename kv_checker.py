#!/usr/bin/env python3

# References:
# https://tools.ietf.org/html/draft-jaganathan-rc4-hmac-03

__description__ = "A script to check if Xbox 360 keyvaults are banned or not"

import os
import socket
import shutil
import logging
from os import urandom
from pathlib import Path
from typing import Union
from datetime import datetime
from argparse import ArgumentParser
from struct import pack_into, unpack_from

from XeCrypt import *
from StreamIO import *
from keystore import load_and_verify_xmacs_pub

# py -3 -m pip install cryptography
from cryptography.hazmat.primitives.hashes import SHA1
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15, OAEP, MGF1

XMACS_RSA_PUB_2048: PY_XECRYPT_RSA_KEY = None

XEAS_REALM = "xeas.xboxlive.com"
XETGS_REALM = "xetgs.xboxlive.com"
SERVER_PORT = 88
BUFF_SIZE = 4096

# change these to match the latest kernel and dash.xex version
XBOX_VERSION = b"2.00.17559.0"
TITLE_VERSION = b"541366016"

def HMAC_RC4_encrypt(key: Union[bytes, bytearray], dec_data: Union[bytes, bytearray], msg_type: int) -> bytes:
	k1 = XeCryptHmacMd5(key, msg_type.to_bytes(4, "little"))
	k2 = k1  # no idea why this is done

	confounder = bytes.fromhex("9B6BFACB5C488190")
	checksum = XeCryptHmacMd5(k2, confounder + dec_data)
	k3 = XeCryptHmacMd5(k1, checksum)

	cipher = XeCryptRc4.new(k3)
	confounder = cipher.encrypt(confounder)
	data = cipher.encrypt(dec_data)

	# refer to edata struct
	return checksum + confounder + data

def HMAC_RC4_decrypt(key: Union[bytes, bytearray], enc_data: Union[bytes, bytearray], msg_type: int) -> Union[bytes, None]:
	k1 = XeCryptHmacMd5(key, msg_type.to_bytes(4, "little"))
	k2 = k1  # no idea why this is done

	# refer to edata struct
	checksum = enc_data[:16]
	confounder = enc_data[16:16 + 8]
	data = enc_data[16 + 8:]

	k3 = XeCryptHmacMd5(k1, checksum)

	cipher = XeCryptRc4.new(k3)
	confounder = cipher.decrypt(confounder)
	data = cipher.decrypt(data)

	# check the checksum
	if checksum != XeCryptHmacMd5(k2, confounder + data):
		return None
	return confounder + data

def compute_client_name(console_id: Union[bytes, bytearray]) -> bytes:
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

def compute_kdc_nonce(key: Union[bytes, bytearray]) -> Union[bytes, bytearray]:
	key = XeCryptHmacMd5(key, b"signaturekey\x00")
	return XeCryptHmacMd5(key, XeCryptMd5(bytes.fromhex("02040000"), b"\x00" * 4))

def get_file_time() -> int:
	dt0 = datetime.strptime("12:00 AM, January 1, 1601 UTC", "%I:%M %p, %B %d, %Y %Z")
	dt1 = datetime.utcnow()
	return int((dt1 - dt0).total_seconds() * 10000000)

def generate_timestamp() -> Union[bytes, bytearray]:
	array = bytearray.fromhex("301AA011180F32303132313231323139303533305AA10502030B3543")
	s = datetime.utcnow().strftime("%Y%m%d%H%M%S") + "Z"
	pack_into("15s", array, 6, s.encode("ASCII"))
	return array

def get_title_auth_data(key: Union[bytes, bytearray], data: Union[bytes, bytearray]) -> Union[bytes, bytearray]:
	src_arr = XeCryptHmacSha(compute_kdc_nonce(key), data)
	array = bytearray(82)
	pack_into("<16s", array, 0, src_arr[:16])
	pack_into("<66s", array, 16, data)
	return array

def get_xmacs_logon_key(serial_num: bytes, console_cert: bytes, console_prv_key: bytes, console_id: bytes) -> (bytes, bytearray):
	k = XMACS_RSA_PUB_2048.to_cryptography()
	rand_key = urandom(16)
	enc_key = reverse(k.encrypt(rand_key, OAEP(MGF1(SHA1()), SHA1(), None)))

	k = PY_XECRYPT_RSA_KEY(console_prv_key).to_cryptography()
	client_name = compute_client_name(console_id)
	file_time = get_file_time().to_bytes(8, "big")
	ts = generate_timestamp()
	enc_ts = HMAC_RC4_encrypt(rand_key, ts, 1)
	array_7 = reverse(k.sign(file_time + serial_num + XeCryptSha(rand_key), PKCS1v15(), SHA1()))

	# can't use StreamIO inside of StreamIO ???
	with StreamIO(read_file("bin/KV/XMACSREQ.bin"), Endian.BIG) as sio:
		sio.write_bytes_at(0x395, XBOX_VERSION)
		sio.write_bytes_at(0x3C0, TITLE_VERSION)

		sio.write_bytes_at(0x2C, enc_key)
		sio.write_bytes_at(0x12C, file_time)
		sio.write_bytes_at(0x134, serial_num)
		sio.write_bytes_at(0x140, array_7)
		sio.write_bytes_at(0x1C0, console_cert)
		sio.write_bytes_at(0x3E0, enc_ts)
		sio.write_bytes_at(0x430, client_name[:15])  # remove @xbox.com from the end
		xmacs_req = sio.getvalue()

	with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
		sock.connect((XEAS_REALM, SERVER_PORT))
		sock.send(xmacs_req)
		xmacs_res = sock.recv(BUFF_SIZE)

	array_8 = xmacs_res[0x35:0x35 + 108]
	src_arr_5 = HMAC_RC4_decrypt(compute_kdc_nonce(rand_key), array_8, 1203)
	return src_arr_5[76:76 + 16]

def find_kvs(path: str) -> list[str]:
	kvs = []
	for root, dirs, files in os.walk(path):
		for file in files:
			path = os.path.join(root, file)
			if file.endswith(".bin") and os.path.getsize(path) == 0x4000:
				kvs.append(path)
	return kvs

def is_kv_banned(data: Union[bytes, bytearray]) -> bool:
	with StreamIO(data, Endian.BIG) as sio:
		serial_num = sio.read_bytes_at(0xB0, 12)
		console_cert = sio.read_bytes_at(0x9C8, 0x1A8)
		console_prv_key = sio.read_bytes_at(0x298, 0x1D0)
		console_id = sio.read_bytes_at(0x9CA, 5)
		# consoleCertSize - abConsolePubKeyModulus
		src_arr_0 = XeCryptSha(sio.read_bytes_at(0x9C8, 0xA8))

	logging.info("Serial #:   " + serial_num.decode("ASCII"))
	logging.info("Console ID: " + console_id.hex().upper())

	xmacs_logon_key = get_xmacs_logon_key(serial_num, console_cert, console_prv_key, console_id)

	client_name = compute_client_name(console_id)
	logging.info("Attempting logon for \"" + client_name.decode("ASCII") + "\"...")
	logging.info("Creating Kerberos AS-REQ...")

	ts = generate_timestamp()
	with StreamIO(read_file("bin/KV/apReq1.bin"), Endian.BIG) as sio:
		sio.write_bytes_at(0x65, XBOX_VERSION)  # console version
		sio.write_bytes_at(0x90, TITLE_VERSION)  # title version

		sio.write_bytes_at(258, client_name[:24])
		sio.write_bytes_at(36, src_arr_0[:20])
		sio.write_bytes_at(176, HMAC_RC4_encrypt(xmacs_logon_key, ts, 1))
		ap_req_1 = sio.getvalue()

	with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
		sock.connect((XEAS_REALM, SERVER_PORT))
		sock.send(ap_req_1)
		logging.info("Sending Kerberos AS-REQ...")
		ap_res_1 = sock.recv(BUFF_SIZE)

	logging.info("AS replied wanting pre-auth data...")
	logging.info("Creating new Kerberos AS-REQ...")
	array_5 = ap_res_1[-16:]

	ts = generate_timestamp()
	with StreamIO(read_file("bin/KV/apReq2.bin"), Endian.BIG) as sio:
		sio.write_bytes_at(0x81, XBOX_VERSION)  # console version
		sio.write_bytes_at(0xAC, TITLE_VERSION)  # title version

		sio.write_bytes_at(286, client_name)
		sio.write_bytes_at(36, src_arr_0)
		sio.write_bytes_at(204, HMAC_RC4_encrypt(xmacs_logon_key, ts, 1))
		sio.write_bytes_at(68, array_5)
		ap_req_2 = sio.getvalue()

	with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
		sock.connect((XEAS_REALM, SERVER_PORT))
		sock.send(ap_req_2)
		logging.info("Sending Kerberos AS-REQ...")
		ap_res_2 = sock.recv(BUFF_SIZE)

	logging.info("Got AS-REP...")
	logging.info("Decrypting our session key...")
	logging.info("Creating Kerberos TGS-REQ...")
	array_9 = ap_res_2[-210:]
	array_10 = HMAC_RC4_decrypt(xmacs_logon_key, array_9, 8)
	array_11 = array_10[27:27 + 16]

	logging.info("Setting TGS ticket...")
	array_12 = ap_res_2[168:168 + 345]

	tgs_req = bytearray(read_file("bin/KV/TGSREQ.bin"))
	auth = bytearray(read_file("bin/KV/authenticator.bin"))
	s = datetime.utcnow().strftime("%Y%m%d%H%M%S") + "Z"
	pack_into(f"<{len(XBOX_VERSION)}s", tgs_req, 0xFA, XBOX_VERSION)
	pack_into(f"<{len(TITLE_VERSION)}s", tgs_req, 0x125, TITLE_VERSION)
	pack_into("<15s", auth, 40, client_name[:15])  # remove @xbox.com from the end
	pack_into("<15s", auth, 109, s.encode("ASCII"))
	pack_into("<16s", auth, 82, XeCryptMd5(tgs_req[954:954 + 75]))
	pack_into("<345s", tgs_req, 437, array_12[:345])
	pack_into("<153s", tgs_req, 799, HMAC_RC4_encrypt(array_11, auth, 7))

	key = compute_kdc_nonce(array_11)
	service_req = bytearray(read_file("bin/KV/servicereq.bin"))
	pack_into("<150s", tgs_req, 55, HMAC_RC4_encrypt(key, service_req, 1201))
	array_16 = ap_req_2[116:116 + 66]
	pack_into("<82s", tgs_req, 221, get_title_auth_data(array_11, array_16))
	logging.log(logging.INFO, "Sending our TGS-REQ...")
	with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
		sock.connect((XETGS_REALM, SERVER_PORT))
		sock.send(tgs_req)
		tgs_res = sock.recv(BUFF_SIZE)

	logging.info("Got TGS-REP...")
	logging.info("Decrypting logon status...")
	array_18 = tgs_res[50:50 + 84]
	value = HMAC_RC4_decrypt(key, array_18, 1202)
	(logon_status_code,) = unpack_from("<I", value, 8)
	logging.info(f"Logon status: 0x{logon_status_code:04X}")
	if logon_status_code == 0x8015190D:
		return True
	else:
		return False

def main() -> None:
	global XMACS_RSA_PUB_2048

	logging.basicConfig(level=logging.INFO)

	parser = ArgumentParser(description=__description__)
	subparsers = parser.add_subparsers(dest="command")

	check_parser = subparsers.add_parser("single")
	check_parser.add_argument("path", type=Path, help="The KV file to check")

	bulk_parser = subparsers.add_parser("bulk")
	bulk_parser.add_argument("path", type=Path, help="The directory to check for KV's")

	args = parser.parse_args()

	XMACS_RSA_PUB_2048 = load_and_verify_xmacs_pub()

	# get absolute path
	args.path = args.path.resolve()

	if args.command == "single":
		logging.info(args.path)
		kv_data = read_file(args.path)
		if is_kv_banned(kv_data):
			logging.info("Banned")
		else:
			logging.info("Unbanned")
			kv_serial = kv_data[0xB0:0xB0 + 12].decode("ASCII")
			if not (args.path.parents[0] / kv_serial).is_dir():
				(args.path.parents[0] / kv_serial).mkdir()
			shutil.copy(args.path, (args.path.parents[0] / kv_serial / "KV_dec.bin"))
	elif args.command == "bulk":
		for kv_path in find_kvs(args.path):
			logging.info(kv_path)
			kv_data = read_file(kv_path)
			if is_kv_banned(kv_data):
				logging.info("Banned")
			else:
				logging.info("Unbanned")
				kv_serial = kv_data[0xB0:0xB0 + 12].decode("ASCII")
				if not (args.path / kv_serial).is_dir():
					(args.path / kv_serial).mkdir()
				shutil.copy(kv_path, (args.path / kv_serial / "KV_dec.bin"))

if __name__ == "__main__":
	main()