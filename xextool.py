#!/usr/bin/env python3

from ctypes import *
from os.path import isfile
from argparse import ArgumentParser
from struct import pack_into, unpack_from

from XeCrypt import *
from StreamIO import *

XEX_SALT = b"XBOX360XEX"

IMAGE_XEX_HEADER_SIZE = 24
HV_IMAGE_INFO_SIZE = 374
HV_PAGE_INFO_SIZE = 24
XEX_SECURITY_INFO_SIZE = 388

PIRS_PUB_KEY_RETAIL = None
PIRS_PRV_KEY_DEVELOPMENT = None
PIRS_PUB_KEY_DEVELOPMENT = None

# XEX constants
# directory entries
XEX_FILE_DATA_DESCRIPTOR_HEADER  = 3
XEX_HEADER_ORIGINAL_BASE_ADDRESS = 0x0100
XEX_HEADER_ENTRY_POINT           = 0x101
XEX_HEADER_PE_MODULE_NAME        = 0x103
# image flags
XEX_SECURITY_FLAG_MFG_SUPPORT    = 0x00000004
# data flags
XEX_DATA_FLAG_ENCRYPTED          = 0x0001
# data formats
XEX_DATA_FORMAT_NONE             = 0x0000
XEX_DATA_FORMAT_RAW              = 0x0001
XEX_DATA_FORMAT_COMPRESSED       = 0x0002
XEX_DATA_FORMAT_DELTA_COMPRESSED = 0x0003

# keys
XEX_1_KEY = bytes.fromhex("A26C10F71FD935E98B99922CE9321572")  # MFG mode
XEX_2_KEY = bytes.fromhex("20B185A59D28FDC340583FBB0896BF91")
ZERO_KEY = (b"\x00" * 16)  # devkit key

def xex_fix_header_hash(stream: StreamIO, xex_header: dict, sec_info: dict) -> bool:
    tmp = stream.tell()
    second_size = xex_header["security_info_offset"] + 8
    first_offset = xex_header["security_info_offset"] + 0x17C
    first_size = xex_header["size_of_headers"] - first_offset

    stream.seek(first_offset)
    data_0 = stream.read(first_size)
    stream.seek(0)
    data_1 = stream.read(second_size)
    hash_buf = XeCryptSha(data_0, data_1)
    if sec_info["image_info"]["header_hash"] != hash_buf:
        stream.seek(xex_header["security_info_offset"] + 8 + 0x100 + 4 + 4 + 4 + 0x14 + 4 + 0x14 + 0x10 + 0x10 + 4)  # header hash
        print("fixing header hash...")
        stream.write(hash_buf)
        sec_info["image_info"]["header_hash"] = hash_buf
    stream.seek(tmp)
    return sec_info["image_info"]["header_hash"] == hash_buf

def xex_fix_signature(stream: StreamIO, xex_header: dict, sec_info: dict) -> bool:
    global PIRS_PRV_KEY_DEVELOPMENT
    global PIRS_PUB_KEY_DEVELOPMENT
    global PIRS_PUB_KEY_RETAIL

    tmp = stream.tell()
    stream.seek(xex_header["security_info_offset"] + 0x108)  # image info
    data_size = sec_info["image_info"]["info_size"] - 0x100  # remove signature size from info size
    data = stream.read(data_size)
    hash_buf = XeCryptRotSumSha(data)

    sig = XeCryptBnQwBeSigCreate(hash_buf, XEX_SALT, PIRS_PRV_KEY_DEVELOPMENT)
    sig = XeCryptBnQwNeRsaPrvCrypt(sig, PIRS_PRV_KEY_DEVELOPMENT)

    if XeCryptBnQwBeSigVerify(sec_info["image_info"]["signature"], hash_buf, XEX_SALT, PIRS_PUB_KEY_DEVELOPMENT):
        print("devkit signed")
    elif XeCryptBnQwBeSigVerify(sec_info["image_info"]["signature"], hash_buf, XEX_SALT, PIRS_PUB_KEY_RETAIL):
        print("retail signed")
    elif sec_info["image_info"]["signature"] != sig:
        print("fixing signature...")
        stream.seek(xex_header["security_info_offset"] + 4 + 4)  # xex signature
        stream.write(sig)
        sec_info["image_info"]["signature"] = sig
    stream.seek(tmp)
    return True

def xex_decrypt(stream: StreamIO, image_flags: int, image_key: (bytes, bytearray), image_size: int) -> None:
    if image_flags & XEX_SECURITY_FLAG_MFG_SUPPORT:
        temp_key = XeCryptAesCbc(XEX_1_KEY, image_key, (b"\x00" * 16), False)
        print(temp_key.hex())
        print(image_flags & XEX_DATA_FLAG_ENCRYPTED)
    else:
        temp_key = XeCryptAesCbc(XEX_2_KEY, image_key, (b"\x00" * 16), False)
        print(temp_key.hex())

def read_image_xex_header(stream: StreamIO) -> dict:
    output = {
        "magic": stream.read_uint32(),
        "module_flags": stream.read_uint32(),
        "size_of_headers": stream.read_uint32(),
        "size_of_discardable_headers": stream.read_uint32(),
        "security_info_offset": stream.read_uint32(),
        "header_directory_entry_count": stream.read_uint32(),
    }
    return output

def read_hv_page_info(stream: StreamIO, count: int) -> list:
    output = []
    for x in range(count):
        output.append({
            "size": stream.read_uint32(),
            "encrypt": stream.read_uint32(),
            "protect": stream.read_uint32(),
            "no_execute": stream.read_uint32(),
            "no_write": stream.read_uint32(),
            "digest": stream.read(0x14)
        })
    return output

def read_hv_image_info(stream: StreamIO) -> dict:
    output = {
        "signature": stream.read(0x100),
        "info_size": stream.read_uint32(),
        "image_flags": stream.read_uint32(),
        "load_address": stream.read_uint32(),
        "image_hash": stream.read(0x14),
        "import_table_count": stream.read_uint32(),
        "import_digest": stream.read(0x14),
        "media_id": stream.read(0x10),
        "image_key": stream.read(0x10),
        "export_table_address": stream.read_uint32(),
        "header_hash": stream.read(0x14),
        "game_region": stream.read_uint32()
    }
    return output

def read_xex_security_info(stream: StreamIO) -> dict:
    output = {
        "size": stream.read_uint32(),
        "image_size": stream.read_uint32(),
        "image_info": read_hv_image_info(stream),
        "allowed_media_types": stream.read_uint32(),
        "page_descriptor_count": stream.read_uint32()
    }
    output["page_info"] = read_hv_page_info(stream, output["page_descriptor_count"])
    return output

def read_xex_import_table(stream: StreamIO) -> dict:
    output = {
        "table_size": stream.read_uint32(),
        "next_import_digest": stream.read_ubytes(0x14),
        "module_number": stream.read_uint32(),
        "version": [stream.read_uint32(), stream.read_uint32()],
        "unused": stream.read_ubyte(),
        "module_index": stream.read_ubyte(),
        "import_count": stream.read_uint16()
    }
    output["import_stub_data"] = stream.read_ubytes(output["table_size"] - 40)
    print(output["next_import_digest"].hex())
    print(XeCryptSha(output["import_stub_data"]).hex())
    return output

def read_xex_import_descriptor(stream: StreamIO) -> dict:
    output = {
        "size": stream.read_uint32(),
        "name_table_size": stream.read_uint32(),
        "module_count": stream.read_uint32()
    }
    output["names"] = stream.read_bytes(output["name_table_size"])
    output["module_imports"] = [read_xex_import_table(stream) for x in range(output["module_count"])]
    return output

def read_xex_raw_data_descriptor(stream: StreamIO) -> dict:
    output = {
        "data_size": stream.read_uint32(),
        "zero_size": stream.read_uint32(),
    }
    return output

def read_xex_data_descriptor(stream: StreamIO) -> dict:
    output = {
        "size": stream.read_uint32(),
        "data_digest": stream.read(0x14)
    }
    return output

def read_xex_compressed_data_descriptor(stream: StreamIO) -> dict:
    output = {
        "window_size": stream.read_uint32(),
        "first_descriptor": read_xex_data_descriptor(stream)
    }
    return output

def read_xex_file_data_descriptor(stream: StreamIO) -> dict:
    output = {
        "size": stream.read_uint32(),
        "flags": stream.read_uint16(),
        "format": stream.read_uint16()
    }
    if output["format"] == XEX_DATA_FORMAT_DELTA_COMPRESSED:
        output["data_descriptor"] = read_xex_compressed_data_descriptor(stream)
    elif output["format"] == XEX_DATA_FORMAT_COMPRESSED:
        output["data_descriptor"] = read_xex_compressed_data_descriptor(stream)
    elif output["format"] == XEX_DATA_FORMAT_RAW:
        for i in range((output["size"] - 8) // 8):
            read_xex_raw_data_descriptor(stream)
    return output


def read_directory_entries(stream: StreamIO, dir_ent_count: int) -> list:
    output = []
    for i in range(dir_ent_count):
        ent_type = stream.read_uint32() >> 8
        ent_info = stream.read_uint32()
        ent_size = ent_type & 0xFF
        #if ent_type == XEX_HEADER_ENTRY_POINT:
        #    print(stream.tell())
        output.append({"type": ent_type, "info": ent_info, "size": ent_size})
    return output

def main() -> None:
    global PIRS_PUB_KEY_RETAIL, PIRS_PRV_KEY_DEVELOPMENT, PIRS_PUB_KEY_DEVELOPMENT

    # load RSA keys
    PIRS_PUB_KEY_RETAIL = read_file("keys/pirs_pub_retail.bin")
    PIRS_PRV_KEY_DEVELOPMENT = read_file("keys/pirs_prv_dev.bin")
    PIRS_PUB_KEY_DEVELOPMENT = PIRS_PRV_KEY_DEVELOPMENT[:XECRYPT_RSAPUB_2048_SIZE]

    data = read_file("Data/Superior.V")
    with StreamIO(data, Endian.BIG) as sio:
        hdr = read_image_xex_header(sio)
        for ent in read_directory_entries(sio, hdr["header_directory_entry_count"]):
            if ent["type"] == XEX_FILE_DATA_DESCRIPTOR_HEADER:
                sio.seek(ent["info"])
                print(read_xex_file_data_descriptor(sio))
            elif ent["type"] == XEX_HEADER_ORIGINAL_BASE_ADDRESS:
                print("Orig Base Addr: 0x%08x" % (ent["info"]))
            elif ent["type"] == XEX_HEADER_ENTRY_POINT:
                print("Entry Point:    0x%08x" % (ent["info"]))
            elif ent["type"] == XEX_HEADER_PE_MODULE_NAME:
                sio.seek(ent["info"])
                print(read_xex_import_descriptor(sio))

    """
        with open(args.in_file, "r+b") as f:
            with StreamIO(f, Endian.BIG) as sio:
                hdr = read_image_xex_header(sio)
                for ent in read_directory_entries(sio, hdr["header_directory_entry_count"]):
                    if ent["type"] == XEX_FILE_DATA_DESCRIPTOR_HEADER:
                        sio.seek(ent["info"])
                        #print(read_xex_file_data_descriptor(sio))
                    elif ent["type"] == XEX_HEADER_ORIGINAL_BASE_ADDRESS:
                        print("Orig Base Addr: 0x%08x" % (ent["info"]))
                    elif ent["type"] == XEX_HEADER_ENTRY_POINT:
                        print("Entry Point:    0x%08x" % (ent["info"]))
                    elif ent["type"] == XEX_HEADER_PE_MODULE_NAME:
                        sio.seek(ent["info"])
                        #print(read_xex_import_descriptor(sio))

                sio.seek(hdr["security_info_offset"])
                sec_info = read_xex_security_info(sio)

                entry_point_offset = 0x91930950 - 0x91900000
                sio.seek(hdr["security_info_offset"] + 4 + 4 + 0x100 + 4 + 4)  # load address
                #sio.write_uint32(0x91930000)
                sio.seek(44)  # entry point
                #sio.write_uint32(0x91930000 + entry_point_offset)

                #xex_fix_header_hash(sio, hdr, sec_info)
                #xex_fix_signature(sio, hdr, sec_info)
                sio.seek(hdr["size_of_headers"])
                xex_decrypt(sio, sec_info["image_info"]["image_flags"], sec_info["image_info"]["image_key"], sec_info["image_size"])
        """

if __name__ == "__main__":
    #parser = ArgumentParser(description="A tool to extract and modify information about an Xbox 360 executable (xex)")
    #parser.add_argument("-i", "--in-file", required=True, type=str, help="The input filename")
    #args = parser.parse_args()

    #assert isfile(args.in_file), "Input file doesn't exist"

    main()
