#!/usr/bin/env python3

import socket
from struct import pack_into, unpack_from
from binascii import unhexlify, hexlify as _hexlify

# References:
# http://sysprogs.com/legacy/articles/kdvmware/kdcom/

# constants
SERVER_HOST = "0.0.0.0"
SERVER_PORT = 50001
BUFFER_SIZE = 2048
DATA_SIG = 0x30303030
CTRL_SIG = 0x69696969

hexlify = lambda b: _hexlify(b).decode("utf8").upper()

if __name__ == "__main__":
	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	sock.bind((SERVER_HOST, SERVER_PORT))
	print("KDNET server listening on %s:%s..." % (SERVER_HOST, SERVER_PORT))
	while True:
		(data, addr) = sock.recvfrom(16)
		(packet_sig, packet_type, packet_len, packet_id, packet_checksum) = unpack_from("<I2H2I", data, 0)