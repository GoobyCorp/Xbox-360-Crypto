#!/usr/bin/env python3

# References:
# https://msopenspecs.azureedge.net/files/MS-PATCH/%5bMS-PATCH%5d-210422.pdf

from ctypes import *
from io import BytesIO
from pathlib import Path
from typing import TypeVar
from platform import system
from struct import calcsize
from enum import IntEnum, auto

BinLike = TypeVar("BinLike", bytes, bytearray, memoryview)

# make sure it's 64-bit
if calcsize("P") * 8 != 64:
	print("This only works on 64-bit operating systems!")
	exit(0)

# make sure it's Windows or Linux
os = system()
if os == "Windows":
	COMPRESSION_LIBRARY_PATH = str(Path("bin/LZX/Windows/LZXCompression.dll").absolute())
	DECOMPRESSION_LIBRARY_PATH = str(Path("bin/LZX/Windows/LZXDecompression.dll").absolute())
elif os == "Linux":
	COMPRESSION_LIBRARY_PATH = str(Path("bin/LZX/Linux/liblzxc.so"))
	DECOMPRESSION_LIBRARY_PATH = str(Path("bin/LZX/Linux/liblzxd.so"))
else:
	print("This only works on Windows or Linux!")
	exit(0)

# C constants
LCI_SIGNATURE = 0x4349434C  # LCIC
LDI_SIGNATURE = 0x4349444C  # LDIC
LZX_WINDOW_SIZE = 128 * 1024  # 0x20000
LZX_CHUNK_SIZE = 32 * 1024  # 0x8000
MAX_GROWTH = 0x1800
NUM_REPEATED_OFFSETS = 3
MAIN_TREE_TABLE_BITS = 10
SECONDARY_LEN_TREE_TABLE_BITS = 8
MAX_MAIN_TREE_ELEMENTS = 256 + (8 * 291)
MIN_MATCH = 2
MAX_MATCH = MIN_MATCH + 255
NUM_PRIMARY_LENGTHS = 7
NUM_SECONDARY_LENGTHS = (MAX_MATCH - MIN_MATCH + 1) - NUM_PRIMARY_LENGTHS
ALIGNED_TABLE_BITS = 7
ALIGNED_NUM_ELEMENTS = 8

# C types
NULL = 0
NULLPTR = c_void_p(NULL)
BOOL = c_uint32
BYTE = c_uint8
CHAR = c_int8
SHORT = c_int16
LONG = c_int32
USHORT = c_uint16
ULONG = c_uint32
SIGNATURE = c_uint32
MHANDLE = c_longlong
LDI_CONTEXT_HANDLE = MHANDLE
LCI_CONTEXT_HANDLE = MHANDLE

# C pointers
PVOID = c_void_p
PBYTE = POINTER(c_ubyte)
PLONG = POINTER(LONG)
PUSHORT = POINTER(USHORT)
PULONG = POINTER(ULONG)
PLDI_CONTEXT_HANDLE = POINTER(LDI_CONTEXT_HANDLE)
PLCI_CONTEXT_HANDLE = POINTER(LCI_CONTEXT_HANDLE)

# C function prototypes
FNALLOC = CFUNCTYPE(PVOID, ULONG)
FNFREE = CFUNCTYPE(None, PVOID)
FNCALLBACK = CFUNCTYPE(LONG, PVOID, PBYTE, LONG, LONG)

# C function pointers
PFNALLOC = POINTER(FNALLOC)
PFNFREE = POINTER(FNFREE)
PFNCALLBACK = POINTER(FNCALLBACK)

class lzx_block_type(IntEnum):
	BLOCKTYPE_INVALID = 0
	BLOCKTYPE_VERBATIM = auto()
	BLOCKTYPE_ALIGNED = auto()
	BLOCKTYPE_UNCOMPRESSED = auto()

class decoder_state(IntEnum):
	DEC_STATE_UNKNOWN = 0
	DEC_STATE_START_NEW_BLOCK = auto()
	DEC_STATE_DECODING_DATA = auto()

class LZXCOMPRESS(LittleEndianStructure):
	_pack_ = 2
	_fields_ = [
		("WindowSize", LONG),
		("SecondPartitionSize", LONG)
	]

class LZXDECOMPRESS(LittleEndianStructure):
	_pack_ = 2
	_fields_ = [
		("WindowSize", LONG),
		("fCPUtype", LONG)
	]

class decision_node(LittleEndianStructure):
	_pack_ = 2
	_fields_ = [
		("link", ULONG),
		("path", ULONG),
		("repeated_offset", ULONG * NUM_REPEATED_OFFSETS),
		("numbits", ULONG)
	]

class t_encoder_context(LittleEndianStructure):
	_pack_ = 8
	_fields_ = [
		("enc_MemWindow", PBYTE),
		("enc_window_size", ULONG),
		("enc_tree_root", PULONG),
		("enc_Left", PULONG),
		("enc_Right", PULONG),
		("enc_bitbuf", ULONG),
		("enc_bitcount", CHAR),
		("enc_output_overflow", BOOL),
		("pad1", CHAR * 2),
		("enc_literals", ULONG),
		("enc_distances", ULONG),
		("enc_DistData", PULONG),
		("enc_LitData", PBYTE),
		("enc_ItemType", PBYTE),
		("enc_repeated_offset_at_literal_zero", ULONG * NUM_REPEATED_OFFSETS),
		("enc_last_matchpos_offset", ULONG * NUM_REPEATED_OFFSETS),
		("enc_matchpos_table", ULONG * (MAX_MATCH + 1)),
		("enc_BufPos", ULONG),
		("enc_slot_table", USHORT * 1024),
		("enc_output_buffer_start", PBYTE),
		("enc_output_buffer_curpos", PBYTE),
		("enc_output_buffer_end", PBYTE),
		("enc_input_running_total", ULONG),
		("enc_bufpos_last_output_block", ULONG),
		("enc_num_position_slots", ULONG),
		("enc_file_size_for_translation", ULONG),
		("enc_num_block_splits", BYTE),
		("enc_ones", BYTE * 256),
		("enc_first_block", BYTE),
		("enc_need_to_recalc_stats", BOOL),
		("enc_first_time_this_group", BOOL),
		("enc_encoder_second_partition_size", ULONG),
		("enc_earliest_window_data_remaining", ULONG),
		("enc_bufpos_at_last_block", ULONG),
		("enc_input_ptr", PBYTE),
		("enc_input_left", LONG),
		("enc_instr_pos", ULONG),
		("enc_tree_freq", PUSHORT),
		("enc_tree_sortptr", PUSHORT),
		("enc_len", PBYTE),
		("enc_tree_heap", SHORT * (MAX_MAIN_TREE_ELEMENTS + 2)),
		("enc_tree_leftright", USHORT * (2 * (2 * MAX_MAIN_TREE_ELEMENTS - 1))),
		("enc_tree_len_cnt", USHORT * 17),
		("enc_tree_n", LONG),
		("enc_tree_heapsize", SHORT),
		("enc_depth", CHAR),
		("enc_next_tree_create", ULONG),
		("enc_last_literals", ULONG),
		("enc_last_distances", ULONG),
		("enc_decision_node", POINTER(decision_node)),
		("enc_main_tree_len", BYTE * (MAX_MAIN_TREE_ELEMENTS + 1)),
		("enc_secondary_tree_len", BYTE * (NUM_SECONDARY_LENGTHS + 1)),
		("enc_main_tree_freq", USHORT * (MAX_MAIN_TREE_ELEMENTS * 2)),
		("enc_main_tree_code", USHORT * MAX_MAIN_TREE_ELEMENTS),
		("enc_main_tree_prev_len", BYTE * (MAX_MAIN_TREE_ELEMENTS + 1)),
		("enc_secondary_tree_freq", USHORT * (NUM_SECONDARY_LENGTHS * 2)),
		("enc_secondary_tree_code", USHORT * NUM_SECONDARY_LENGTHS),
		("enc_secondary_tree_prev_len", BYTE * (NUM_SECONDARY_LENGTHS + 1)),
		("enc_aligned_tree_freq", USHORT * (ALIGNED_NUM_ELEMENTS * 2)),
		("enc_aligned_tree_code", USHORT * ALIGNED_NUM_ELEMENTS),
		("enc_aligned_tree_len", BYTE * ALIGNED_NUM_ELEMENTS),
		("enc_aligned_tree_prev_len", BYTE * ALIGNED_NUM_ELEMENTS),
		("enc_RealMemWindow", PBYTE),
		("enc_RealLeft", PULONG),
		("enc_RealRight", PULONG),
		("enc_num_cfdata_frames", ULONG),
		("enc_fci_data", PVOID),
		("enc_malloc", PFNALLOC),
		("enc_free", PFNFREE),
		("enc_inserted_dict_size", ULONG),
		("enc_last_bsearch_bufpos", ULONG),
		("enc_output_callback_function", PFNCALLBACK)
	]

class t_decoder_context(LittleEndianStructure):
	_pack_ = 8
	_fields_ = [
		("dec_mem_window", PBYTE),
		("dec_window_size", ULONG),
		("dec_window_mask", ULONG),
		("dec_last_matchpos_offset", ULONG * NUM_REPEATED_OFFSETS),
		("dec_main_tree_table", SHORT * (1 << MAIN_TREE_TABLE_BITS)),
		("dec_secondary_length_tree_table", SHORT * (1 << SECONDARY_LEN_TREE_TABLE_BITS)),
		("dec_main_tree_len", BYTE * MAX_MAIN_TREE_ELEMENTS),
		("dec_secondary_length_tree_len", BYTE * NUM_SECONDARY_LENGTHS),
		("pad1", BYTE * 3),
		("dec_aligned_table", CHAR * (1 << ALIGNED_TABLE_BITS)),
		("dec_aligned_len", BYTE * ALIGNED_NUM_ELEMENTS),
		("dec_main_tree_left_right", SHORT * (MAX_MAIN_TREE_ELEMENTS * 4)),
		("dec_secondary_length_tree_left_right", SHORT * (NUM_SECONDARY_LENGTHS * 4)),
		("dec_input_curpos", PBYTE),
		("dec_end_input_pos", PBYTE),
		("dec_output_buffer", PBYTE),
		("dec_position_at_start", LONG),
		("dec_main_tree_prev_len", BYTE * MAX_MAIN_TREE_ELEMENTS),
		("dec_secondary_length_tree_prev_len", BYTE * NUM_SECONDARY_LENGTHS),
		("dec_bitbuf", ULONG),
		("dec_bitcount", CHAR),
		("dec_num_position_slots", ULONG),
		("dec_first_time_this_group", BOOL),
		("dec_error_condition", BOOL),
		("dec_bufpos", LONG),
		("dec_current_file_size", ULONG),
		("dec_instr_pos", ULONG),
		("dec_num_cfdata_frames", ULONG),
		("dec_original_block_size", LONG),
		("dec_block_size", LONG),
		("_dec_block_type", LONG),  # lzx_block_type
		("_dec_decoder_state", LONG),  # decoder_state
		("dec_malloc", PFNALLOC),
		("dec_free", PFNFREE)
	]

	@property
	def dec_block_type(self) -> lzx_block_type:
		return lzx_block_type(self._dec_block_type)

	@dec_block_type.setter
	def dec_block_type(self, value: lzx_block_type | int) -> None:
		self._dec_block_type = int(value)

	@property
	def dec_decoder_state(self) -> decoder_state:
		return decoder_state(self._dec_decoder_state)

	@dec_decoder_state.setter
	def dec_decoder_state(self, value: decoder_state | int) -> None:
		self._dec_decoder_state = int(value)

class LCI_CONTEXT(LittleEndianStructure):
	_fields_ = [
		("signature", ULONG),
		("pfnAlloc", PFNALLOC),
		("pfnFree", PFNFREE),
		("cbDataBlockMax", ULONG),
		("file_translation_size", ULONG),
		("encoder_context", POINTER(t_encoder_context))
	]

class LDI_CONTEXT(LittleEndianStructure):
	_fields_ = [
		("signature", ULONG),
		("pfnAlloc", PFNALLOC),
		("pfnFree", PFNFREE),
		("cbDataBlockMax", ULONG),
		("fCPUtype", ULONG),
		("decoder_context", POINTER(t_decoder_context))
	]

class LZXBOX_BLOCK(BigEndianStructure):
	_pack_ = 2
	_fields_ = [
		("CompressedSize", USHORT),
		("UncompressedSize", USHORT)
	]

class LZXCompression:
	dll: CDLL = None
	chunk_size: int = None
	ctx: LCI_CONTEXT_HANDLE = None
	callback: FNCALLBACK = None

	compressed_stream: BytesIO = None

	def __init__(self, chunk_size: int = LZX_CHUNK_SIZE):
		self.compressed_stream = BytesIO()

		self.chunk_size = chunk_size

		self.dll = CDLL(COMPRESSION_LIBRARY_PATH)

		# LONG LCICreateCompression(PULONG pcbDataBlockMax, PVOID pvConfiguration, PULONG pcbDstBufferMin, LCI_CONTEXT_HANDLE* pmchHandle,
		# 	  LONG (*pfnlzx_output_callback)(
		#         PVOID pfol,
		#         PBYTE compressed_data,
		#         LONG compressed_size,
		#         LONG uncompressed_size
		#     ),
		#     PVOID fci_data);
		self.dll.LCICreateCompression.argtypes = [PULONG, PVOID, PULONG, PLCI_CONTEXT_HANDLE, FNCALLBACK, PVOID]
		self.dll.LCICreateCompression.restype = LONG

		# LONG LCICompress(LCI_CONTEXT_HANDLE hmc, PVOID pbSrc, ULONG cbSrc, PVOID pbDst, ULONG cbDst, PULONG pcbResult);
		self.dll.LCICompress.argtypes = [LCI_CONTEXT_HANDLE, PVOID, LONG, PVOID, LONG, PULONG]
		self.dll.LCICompress.restype = LONG

		# LONG LCIFlushCompressorOutput(LCI_CONTEXT_HANDLE hmc);
		self.dll.LCIFlushCompressorOutput.argtypes = [LCI_CONTEXT_HANDLE]
		self.dll.LCIFlushCompressorOutput.restype = LONG

		# LONG LCIResetCompression(LCI_CONTEXT_HANDLE hmc);
		self.dll.LCIResetCompression.argtypes = [LCI_CONTEXT_HANDLE]
		self.dll.LCIResetCompression.restype = LONG

		# LONG LCIDestroyCompression(LCI_CONTEXT_HANDLE hmc);
		self.dll.LCIDestroyCompression.argtypes = [LCI_CONTEXT_HANDLE]
		self.dll.LCIDestroyCompression.restype = LONG

		# LONG LCISetTranslationSize(LCI_CONTEXT_HANDLE hmc, ULONG size);
		self.dll.LCISetTranslationSize.argtypes = [LCI_CONTEXT_HANDLE, LONG]
		self.dll.LCISetTranslationSize.restype = LONG

		# PBYTE LCIGetInputData(LCI_CONTEXT_HANDLE hmc, PULONG input_position, PULONG bytes_available);
		self.dll.LCIGetInputData.argtypes = [LCI_CONTEXT_HANDLE, PULONG, PULONG]
		self.dll.LCIGetInputData.restype = PBYTE

		# LONG LCISetWindowData(LCI_CONTEXT_HANDLE hmd, PBYTE pbWindowData, ULONG pcbWindowData);
		self.dll.LCISetWindowData.argtypes = [LCI_CONTEXT_HANDLE, PBYTE, ULONG]
		self.dll.LCISetWindowData.restype = LONG

		# bool LZX_EncodeInit(
		# 	  t_encoder_context* enc_context,
		#     LONG compression_window_size,
		#     LONG second_partition_size,
		#     LONG (* pfnlzx_output_callback)(
		#         PVOID pfol,
		#         PBYTE compressed_data,
		#         LONG compressed_size,
		#         LONG uncompressed_size
		#     ),
		#     PVOID fci_data);
		self.dll.LZX_EncodeInit.argtypes = [POINTER(t_encoder_context), LONG, LONG, FNCALLBACK, PVOID]
		self.dll.LZX_EncodeInit.restype = BOOL

		# void LZX_EncodeNewGroup(t_encoder_context *context);
		self.dll.LZX_EncodeNewGroup.argtypes = [POINTER(t_encoder_context)]
		self.dll.LZX_EncodeNewGroup.restype = None

		# LONG LZX_Encode(
		#     t_encoder_context* context,
		#     PBYTE input_data,
		#     LONG input_size,
		#     PLONG bytes_compressed,
		#     LONG file_size_for_translation);
		self.dll.LZX_Encode.argtypes = [POINTER(t_encoder_context), PBYTE, LONG, PLONG, LONG]
		self.dll.LZX_Encode.restype = LONG

		# bool LZX_EncodeFlush(t_encoder_context *context);
		self.dll.LZX_EncodeFlush.argtypes = [POINTER(t_encoder_context)]
		self.dll.LZX_EncodeFlush.restype = BOOL

		# bool LZX_EncodeResetState(t_encoder_context *context);
		self.dll.LZX_EncodeResetState.argtypes = [POINTER(t_encoder_context)]
		self.dll.LZX_EncodeResetState.restype = BOOL

		# unsigned char* LZX_GetInputData(
		#     t_encoder_context *context,
		#     PULONG input_position,
		#     PULONG bytes_available);
		self.dll.LZX_GetInputData.argtypes = [POINTER(t_encoder_context), PULONG, PULONG]
		self.dll.LZX_GetInputData.restype = PBYTE

		# bool LZX_EncodeInsertDictionary(
		#     t_encoder_context* context,
		#     PBYTE input_data,
		#     ULONG input_size);
		self.dll.LZX_EncodeInsertDictionary.argtypes = [POINTER(t_encoder_context), PBYTE, ULONG]
		self.dll.LZX_EncodeInsertDictionary.restype = BOOL

		# void LZX_EncodeFree(t_encoder_context* context);
		self.dll.LZX_EncodeFree.argtypes = [POINTER(t_encoder_context)]
		self.dll.LZX_EncodeFree.restype = None

		self.create()

	def __enter__(self):
		return self

	def __exit__(self, exc_type, exc_value, traceback):
		ret = self.destroy()
		assert ret == 0, f"LCIDestroyCompression failed with code 0x{ret:X}!"
		self.compressed_stream.close()

	#def reset(self) -> None:
	#	self.dll: CDLL = None
	#	self.chunk_size = None
	#	self.ctx = None
	#	self.callback = None
	#	self.compressed_stream = BytesIO()

	def create(self) -> int:
		self.ctx = LCI_CONTEXT_HANDLE()

		lzx = LZXCOMPRESS()
		lzx.WindowSize = LZX_WINDOW_SIZE
		lzx.SecondPartitionSize = 32 * 1024

		pcbDataBlockMax = self.chunk_size
		pcbDstBufferMin = 0

		# need to prevent it from be deallocated so we use it as a class variable
		self.callback = FNCALLBACK(self.callback_func)

		ret = self.dll.LCICreateCompression(
			pointer(ULONG(pcbDataBlockMax)),
			pointer(lzx),
			pointer(ULONG(pcbDstBufferMin)),
			pointer(self.ctx),
			self.callback,
			NULLPTR
		)
		assert ret == 0, f"LCICreateCompression failed with code 0x{ret:X}!"

		lci = LCI_CONTEXT.from_address(self.ctx.value)

		a_addr_0 = addressof(lci.pfnAlloc.contents)
		f_addr_0 = addressof(lci.pfnFree.contents)

		a_addr_1 = addressof(lci.encoder_context.contents.enc_malloc.contents)
		f_addr_1 = addressof(lci.encoder_context.contents.enc_free.contents)

		b = 1
		b &= lci.signature == LCI_SIGNATURE
		b &= a_addr_0 == a_addr_1
		b &= f_addr_0 == f_addr_1
		b = bool(b)

		assert b, f"LCI t_encoder_context integrity failed!"

		return ret

	def reset(self) -> int:
		self.compressed_stream.close()
		self.compressed_stream = BytesIO()
		return self.dll.LDIResetCompression(self.ctx)

	def destroy(self) -> int:
		return self.dll.LCIDestroyCompression(self.ctx)

	def callback_func(self, pfol: int | None, compressed_data: PBYTE, compressed_size: int, uncompressed_size: int) -> int:
		pcd = (c_ubyte * compressed_size)()
		memmove(pcd, compressed_data, compressed_size)

		# print("CALLBACK!")

		hdr = LZXBOX_BLOCK()
		hdr.CompressedSize = compressed_size
		hdr.UncompressedSize = uncompressed_size

		self.compressed_stream.write(bytes(hdr))
		self.compressed_stream.write(bytes(pcd))

		return 0

	def compress(self, data: BinLike) -> bytes:
		in_data = (c_ubyte * len(data))()
		memmove(in_data, data, len(data))
		out_size = c_uint32()
		ret = self.dll.LCICompress(self.ctx, pointer(in_data), LONG(len(data)), NULLPTR, LONG(len(data) + MAX_GROWTH), pointer(out_size))
		assert ret == 0, f"LCICompress failed with code 0x{ret:X}!"
		return self.compressed_stream.getvalue()

	def flush(self) -> bytes:
		ret = self.dll.LCIFlushCompressorOutput(self.ctx)
		assert ret == 0, f"LCIFlushCompressorOutput failed with code 0x{ret:X}!"
		return self.compressed_stream.getvalue()

	def compress_continuous(self, data: BinLike) -> bytes:
		size = len(data)
		with BytesIO(data) as bio:
			while (pos := bio.tell()) < size:
				chunk_size = self.chunk_size
				if (size - pos) < chunk_size:
					chunk_size = size - pos
				self.compress(bio.read(chunk_size))
			self.flush()
		return self.compressed_stream.getvalue()

class LZXDecompression:
	dll: CDLL = None
	chunk_size: int = None
	ctx: LDI_CONTEXT_HANDLE = None

	def __init__(self, chunk_size: int = LZX_CHUNK_SIZE):
		# self.reset()

		self.chunk_size = chunk_size

		self.dll = CDLL(DECOMPRESSION_LIBRARY_PATH)

		# int LDICreateDecompression(PULONG pcbDataBlockMax, PVOID pvConfiguration, PULONG pcbSrcBufferMin, LDI_CONTEXT_HANDLE* pmdhHandle);
		self.dll.LDICreateDecompression.argtypes = [PULONG, PVOID, PULONG, PLDI_CONTEXT_HANDLE]
		self.dll.LDICreateDecompression.restype = LONG

		# int LDIDecompress(LDI_CONTEXT_HANDLE hmd, PVOID pbSrc, UINT cbSrc, PVOID pbDst, PULONG pcbResult);
		self.dll.LDIDecompress.argtypes = [LDI_CONTEXT_HANDLE, PVOID, LONG, PVOID, PULONG]
		self.dll.LDIDecompress.restype = LONG

		# int LDIResetDecompression(LDI_CONTEXT_HANDLE hmd);
		self.dll.LDIResetDecompression.argtypes = [LDI_CONTEXT_HANDLE]
		self.dll.LDIResetDecompression.restype = LONG

		# int LDIDestroyDecompression(LDI_CONTEXT_HANDLE hmd);
		self.dll.LDIDestroyDecompression.argtypes = [LDI_CONTEXT_HANDLE]
		self.dll.LDIDestroyDecompression.restype = LONG

		# int LDIGetWindow(LDI_CONTEXT_HANDLE hmd, PBYTE* ppWindow, PLONG pFileOffset, PLONG pWindowOffset, PLONG pcbBytesAvail);
		self.dll.LDIGetWindow.argtypes = [LDI_CONTEXT_HANDLE, POINTER(PBYTE), PLONG, PLONG, PLONG]
		self.dll.LDIGetWindow.restype = LONG

		# int LDISetWindowData(LDI_CONTEXT_HANDLE hmd, PBYTE pbWindowData, ULONG pcbWindowData);
		self.dll.LDISetWindowData.argtypes = [LDI_CONTEXT_HANDLE, PBYTE, ULONG]
		self.dll.LDISetWindowData.restype = LONG

		# bool LZX_DecodeInit(t_decoder_context *context, LONG compression_window_size);
		self.dll.LZX_DecodeInit.argtypes = [POINTER(t_decoder_context), LONG]
		self.dll.LZX_DecodeInit.restype = BOOL

		# void LZX_DecodeNewGroup(t_decoder_context *context);
		self.dll.LZX_DecodeNewGroup.argtypes = [POINTER(t_decoder_context)]
		self.dll.LZX_DecodeNewGroup.restype = None

		# int LZX_Decode(t_decoder_context *context, LONG bytes_to_decode, PBYTE compressed_input_buffer, LONG compressed_input_size, PBYTE uncompressed_output_buffer, LONG uncompressed_output_size, PLONG bytes_decoded);
		self.dll.LZX_Decode.argtypes = [POINTER(t_decoder_context), LONG, PBYTE, LONG, PBYTE, LONG, PLONG]
		self.dll.LZX_Decode.restype = LONG

		# bool LZX_DecodeInsertDictionary(t_decoder_context *context, const PBYTE data, ULONG data_size);
		self.dll.LZX_DecodeInsertDictionary.argtypes = [POINTER(t_decoder_context), PBYTE, ULONG]
		self.dll.LZX_DecodeInsertDictionary.restype = BOOL

		# void LZX_DecodeFree(t_decoder_context* context);
		self.dll.LZX_DecodeFree.argtypes = [POINTER(t_decoder_context)]
		self.dll.LZX_DecodeFree.restype = None

		self.create()

	def __enter__(self):
		return self

	def __exit__(self, exc_type, exc_value, traceback):
		ret = self.destroy()
		assert ret == 0, f"LCIDestroyCompression failed with code 0x{ret:X}!"

	#def reset(self) -> None:
	#	self.dll = None
	#	self.chunk_size = None
	#	self.ctx = None

	def create(self) -> int:
		self.ctx = LDI_CONTEXT_HANDLE()

		lzx = LZXDECOMPRESS()
		lzx.WindowSize = LZX_WINDOW_SIZE
		lzx.fCPUtype = 1

		pcbDataBlockMax = self.chunk_size
		pcbSrcBufferMin = 0

		ret = self.dll.LDICreateDecompression(
			pointer(ULONG(pcbDataBlockMax)),
			pointer(lzx),
			pointer(ULONG(pcbSrcBufferMin)),
			pointer(self.ctx)
		)
		assert ret == 0, f"LDICreateDecompression failed with code 0x{ret:X}!"

		ldi = LDI_CONTEXT.from_address(self.ctx.value)

		a_addr_0 = addressof(ldi.pfnAlloc.contents)
		f_addr_0 = addressof(ldi.pfnFree.contents)

		a_addr_1 = addressof(ldi.decoder_context.contents.dec_malloc.contents)
		f_addr_1 = addressof(ldi.decoder_context.contents.dec_free.contents)

		b = 1
		b &= ldi.signature == LDI_SIGNATURE
		b &= a_addr_0 == a_addr_1
		b &= f_addr_0 == f_addr_1
		b = bool(b)

		assert b, f"LDI t_decoder_context integrity failed!"

		return ret

	def reset(self) -> int:
		return self.dll.LDIResetDecompression(self.ctx)

	def destroy(self) -> int:
		return self.dll.LDIDestroyDecompression(self.ctx)

	def delta_decompress(self, base_data: BinLike, patch_data: BinLike) -> bytes:
		pass

	def decompress(self, data: BinLike, size: int) -> bytes:
		in_data = (c_ubyte * len(data))()
		memmove(in_data, data, len(data))
		out_data = (c_ubyte * size)()
		out_size = ULONG(size)
		ret = self.dll.LDIDecompress(self.ctx, pointer(in_data), LONG(len(data)), pointer(out_data), pointer(out_size))
		assert ret == 0, f"LDIDecompress failed with code 0x{ret:X}!"
		resize(out_data, out_size.value)
		return bytes(out_data)

	def decompress_chunk(self, data: BinLike) -> bytes:
		hdr = LZXBOX_BLOCK.from_buffer_copy(data[:sizeof(LZXBOX_BLOCK)])
		data = data[sizeof(LZXBOX_BLOCK):]
		assert len(data) == hdr.CompressedSize, "data size is invalid!"
		return self.decompress(data, hdr.UncompressedSize)

	def decompress_continuous(self, data: BinLike) -> bytes:
		size = len(data)
		with BytesIO(data) as rbio, BytesIO() as wbio:
			while (pos := rbio.tell()) < size:
				hdr = LZXBOX_BLOCK.from_buffer_copy(rbio.read(sizeof(LZXBOX_BLOCK)))
				block = rbio.read(hdr.CompressedSize)
				block = self.decompress(block, hdr.UncompressedSize)
				assert len(block) == hdr.UncompressedSize, "Decompressed size mismatch!"
				wbio.write(block)
			return wbio.getvalue()

def main() -> int:
	pr = Path("data/bootloader/uncompressed.bin")

	with LZXCompression() as lzxc, pr.open("rb") as fr:
		uncomp_data = fr.read()
		comp_data = lzxc.compress_continuous(uncomp_data)

	with LZXDecompression() as lzxd, BytesIO(comp_data) as fr:
		decomp_data = lzxd.decompress_continuous(fr.read())

	assert uncomp_data == decomp_data, "Files aren't the same!"

	print("Done!")

	return 0

if __name__ == "__main__":
	exit(main())

__all__ = [
	"LZXCompression",
	"LZXDecompression"
]