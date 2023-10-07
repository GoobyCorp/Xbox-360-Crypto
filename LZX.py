#!/usr/bin/env python3

# References:
# https://msopenspecs.azureedge.net/files/MS-PATCH/%5bMS-PATCH%5d-210422.pdf

from ctypes import *
from io import BytesIO
from pathlib import Path
from typing import TypeVar
from platform import system
from struct import calcsize

BinLike = TypeVar("BinLike", bytes, bytearray, memoryview)

# make sure it's 64-bit
if calcsize("P") * 8 != 64:
	print("This only works on 64-bit operating systems!")
	exit(0)

LZX_WINDOW_SIZE = 128 * 1024  # 0x20000
LZX_CHUNK_SIZE = 32 * 1024  # 0x8000
MAX_GROWTH = 0x1800

NULL = 0
NULLPTR = c_void_p(NULL)
LONG = c_int32
USHORT = c_uint16
ULONG = c_uint32

PBYTE = POINTER(c_ubyte)
PLONG = POINTER(LONG)
PULONG = POINTER(ULONG)
SIGNATURE = c_uint32
MHANDLE = c_longlong
LDI_CONTEXT_HANDLE = MHANDLE
LCI_CONTEXT_HANDLE = MHANDLE
PLDI_CONTEXT_HANDLE = POINTER(LDI_CONTEXT_HANDLE)
PLCI_CONTEXT_HANDLE = POINTER(LCI_CONTEXT_HANDLE)

FNCALLBACK = CFUNCTYPE(LONG, c_void_p, PBYTE, LONG, LONG)

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

		self.dll = CDLL(self.compression_library_path)

		self.dll.LCICreateCompression.argtypes = [PULONG, c_void_p, PULONG, PLCI_CONTEXT_HANDLE, FNCALLBACK, c_void_p]
		self.dll.LCICreateCompression.restype = LONG

		self.dll.LCICompress.argtypes = [LCI_CONTEXT_HANDLE, c_void_p, LONG, c_void_p, LONG, PULONG]
		self.dll.LCICompress.restype = LONG

		self.dll.LCIFlushCompressorOutput.argtypes = [LCI_CONTEXT_HANDLE]
		self.dll.LCIFlushCompressorOutput.restype = LONG

		self.dll.LCIResetCompression.argtypes = [LCI_CONTEXT_HANDLE]
		self.dll.LCIResetCompression.restype = LONG

		self.dll.LCIDestroyCompression.argtypes = [LCI_CONTEXT_HANDLE]
		self.dll.LCIDestroyCompression.restype = LONG

		self.dll.LCISetTranslationSize.argtypes = [LCI_CONTEXT_HANDLE, LONG]
		self.dll.LCISetTranslationSize.restype = LONG

		self.dll.LCIGetInputData.argtypes = [LCI_CONTEXT_HANDLE, PULONG, PULONG]
		self.dll.LCIGetInputData.restype = PBYTE

		self.dll.LCISetWindowData.argtypes = [LCI_CONTEXT_HANDLE, PBYTE, ULONG]
		self.dll.LCISetWindowData.restype = LONG

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

	@property
	def compression_library_path(self) -> str | None:
		os = system()
		if os == "Windows":
			return str(Path("bin/LZX/Windows/LZXCompression.dll").absolute())
		elif os == "Linux":
			return str(Path("bin/LZX/Linux/liblzxc.so"))
		else:
			return None

	def create(self) -> int:
		self.ctx = LCI_CONTEXT_HANDLE()

		lzxc = LZXCOMPRESS()
		lzxc.WindowSize = LZX_WINDOW_SIZE
		lzxc.SecondPartitionSize = 32 * 1024

		pcbDataBlockMax = self.chunk_size
		pcbDstBufferMin = 0

		# need to prevent it from be deallocated so we use it as a class variable
		self.callback = FNCALLBACK(self.callback_func)

		ret = self.dll.LCICreateCompression(
			pointer(ULONG(pcbDataBlockMax)),
			pointer(lzxc),
			pointer(ULONG(pcbDstBufferMin)),
			pointer(self.ctx),
			self.callback,
			NULLPTR
		)
		assert ret == 0, f"LCICreateCompression failed with code 0x{ret:X}!"
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

		self.dll = CDLL(self.decompression_library_path)

		self.dll.LDICreateDecompression.argtypes = [PULONG, c_void_p, PULONG, PLDI_CONTEXT_HANDLE]
		self.dll.LDICreateDecompression.restype = LONG

		self.dll.LDIDecompress.argtypes = [LDI_CONTEXT_HANDLE, c_void_p, LONG, c_void_p, PULONG]
		self.dll.LDIDecompress.restype = LONG

		self.dll.LDIResetDecompression.argtypes = [LDI_CONTEXT_HANDLE]
		self.dll.LDIResetDecompression.restype = LONG

		self.dll.LDIDestroyDecompression.argtypes = [LDI_CONTEXT_HANDLE]
		self.dll.LDIDestroyDecompression.restype = LONG

		self.dll.LDIGetWindow.argtypes = [LDI_CONTEXT_HANDLE, POINTER(PBYTE), PLONG, PLONG, PLONG]
		self.dll.LDIGetWindow.restype = LONG

		self.dll.LDISetWindowData.argtypes = [LDI_CONTEXT_HANDLE, PBYTE, ULONG]
		self.dll.LDISetWindowData.restype = LONG

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

	@property
	def decompression_library_path(self) -> str | None:
		os = system()
		if os == "Windows":
			return str(Path("bin/LZX/Windows/LZXDecompression.dll").absolute())
		elif os == "Linux":
			return str(Path("bin/LZX/Linux/liblzxd.so"))
		else:
			return None

	def create(self) -> int:
		self.ctx = LDI_CONTEXT_HANDLE()

		lzxd = LZXDECOMPRESS()
		lzxd.WindowSize = LZX_WINDOW_SIZE
		lzxd.fCPUtype = 1

		pcbDataBlockMax = self.chunk_size
		pcbSrcBufferMin = 0

		ret = self.dll.LDICreateDecompression(
			pointer(ULONG(pcbDataBlockMax)),
			pointer(lzxd),
			pointer(ULONG(pcbSrcBufferMin)),
			pointer(self.ctx)
		)
		assert ret == 0, f"LDICreateDecompression failed with code 0x{ret:X}!"
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