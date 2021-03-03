#!/usr/bin/env python3

from io import BytesIO
from pathlib import Path
from struct import pack, pack_into, unpack_from

SEEK_SET = 0
SEEK_CUR = 1
SEEK_END = 2

MODE_FILE = 0
MODE_FLASH = 1

def calc_page_ecc(data: (bytes, bytearray), spare: (bytes, bytearray)) -> int:
	if type(data) == bytes:
		data = bytearray(data)

	val = 0
	v = 0
	idx = 0
	for bit in range(0x1066):
		if not (bit & 31):
			if bit == 0x1000:
				data = spare
				idx = 0
			(v,) = unpack_from("<I", data, idx)
			v = ~v
			idx += 4
		val ^= v & 1
		v >>= 1
		if val & 1:
			val ^= 0x6954559
		val >>= 1
	return ~val & 0xFFFFFFFF

def fix_page_ecc(data: (bytes, bytearray), spare: (bytes, bytearray)) -> tuple:
	if type(spare) == bytes:
		spare = bytearray(spare)

	val = calc_page_ecc(data, spare)
	spare[12] = (spare[12] & 0x3F) + ((val << 6) & 0xC0)
	spare[13] = (val >> 2) & 0xFF
	spare[14] = (val >> 10) & 0xFF
	spare[15] = (val >> 18) & 0xFF
	return (data, spare)

class NANDImage:
	mode = MODE_FILE
	stream = None
	file_size = 0
	flash_size = 0
	num_pages = 0

	@property
	def file_offset(self) -> int:
		return self._file_offset

	@file_offset.setter
	def file_offset(self, offset: int) -> None:
		self._flash_offset = self.file_to_flash_offset(offset)
		self._file_offset = offset
		self.stream.seek(self._file_offset)

	@property
	def flash_offset(self) -> int:
		return self._flash_offset

	@flash_offset.setter
	def flash_offset(self, offset: int) -> None:
		self._file_offset = self.flash_to_file_offset(offset)
		self._flash_offset = offset
		self.stream.seek(self._file_offset)

	def __init__(self, filename_or_data: (str, bytes, bytearray), mode: int = MODE_FILE):
		self.reset()

		self.mode = mode
		if type(filename_or_data) == str:
			self.stream = open(filename_or_data, "r+b")
		elif type(filename_or_data) in [bytes, bytearray]:
			self.stream = BytesIO(filename_or_data)

		# seek to the end
		self.file_seek(0, SEEK_END)
		# get size with spare data
		self.file_size = self.file_tell()
		# get number of pages
		self.num_pages = self.file_size // 528
		# get size without spare data
		self.flash_size = self.num_pages * 512
		# seek back to the start
		self.file_seek(0)

	def __enter__(self):
		return self

	def __exit__(self, exc_type, exc_val, exc_tb) -> None:
		self.stream.flush()
		self.stream.close()

	def reset(self) -> None:
		self.mode = MODE_FILE
		self.stream = None
		self.file_size = 0
		self.flash_size = 0
		self.num_pages = 0

	# stream primitives
	def seek(self, offset: int, whence: int = SEEK_SET) -> int:
		return getattr(self, ("file" if self.mode == MODE_FILE else "flash") + "_seek")(offset, whence)

	def tell(self) -> int:
		return getattr(self, ("file" if self.mode == MODE_FILE else "flash") + "_tell")()

	def read(self, num: int = 0) -> bytes:
		return getattr(self, ("file" if self.mode == MODE_FILE else "flash") + "_read")(num)

	def write(self, data: (bytes, bytearray)) -> int:
		return getattr(self, ("file" if self.mode == MODE_FILE else "flash") + "_write")(data)

	def flush(self) -> None:
		self.stream.flush()

	# extended I/O functions

	# offset translation functions
	def file_to_flash_offset(self, file_offset: int) -> int:
		"""
		Convert file offset to flash offset
		:param flash_offset:
		:return:
		"""
		if file_offset < 0:
			file_offset = self.flash_size + file_offset
		return ((file_offset // 528) * 512) + (file_offset % 528)

	def flash_to_file_offset(self, flash_offset: int) -> int:
		"""
		Convert flash offset to file offset
		:param file_offset:
		:return:
		"""
		if flash_offset < 0:
			flash_offset = self.file_size + flash_offset
		return ((flash_offset // 512) * 528) + (flash_offset % 512)

	def file_offset_to_page(self, offset: int) -> int:
		"""
		Get the page a file offset lands on
		:param offset:
		:return:
		"""
		return (offset // 528) + 1

	def flash_offset_to_page(self, offset: int) -> int:
		"""
		Get the page a flash offset lands on
		:param offset:
		:return:
		"""
		return (offset // 512) + 1

	def flash_calc_page_offset(self, offset: int) -> int:
		"""
		Calculates the start or end offset for page I/O
		:param offset:
		:return:
		"""
		return offset - ((offset // 512) * 512)

	def calc_page_offset(self, num: int) -> int:
		"""
		Calculates the start offset for a given page number
		:param num: The page number
		:return:
		"""
		return (num - 1) * 528

	def calc_spare_offset(self, num: int) -> int:
		so = ((num - 1) * 528) - 16
		return 512 if (num - 1) == 0 else so

	# file primitives
	def file_tell(self) -> int:
		return self.stream.tell()

	def file_seek(self, offset: int, whence: int = SEEK_SET) -> int:
		no = self.stream.seek(offset, whence)
		self.file_offset = no
		return no

	def file_read(self, num: int = 0) -> bytes:
		if num > 0:
			data = self.stream.read(num)
		else:
			data = self.stream.read()
		self.file_offset = self.file_tell()
		return data

	def file_write(self, data: (bytes, bytearray)) -> int:
		nw = self.stream.write(data)
		self.file_offset = self.file_tell()
		return nw

	# flash primitives
	def flash_tell(self) -> int:
		return self.file_to_flash_offset(self.file_tell())

	def flash_seek(self, offset: int, whence: int = SEEK_SET) -> int:
		no = 0  # promise
		if whence == SEEK_SET:
			if offset >= 0:
				# no = self.file_seek(self.flash_to_file_offset(offset), SEEK_SET)
				self.flash_offset = offset
				no = self.flash_tell()
			elif offset < 0:
				no = self.file_seek(self.flash_to_file_offset(self.flash_size - offset), SEEK_SET)
		elif whence == SEEK_CUR:
			if offset >= 0:
				# no = self.file_seek(self.flash_to_file_offset(offset), SEEK_CUR)
				self.flash_offset += offset
				no = self.flash_tell()
			elif offset < 0:
				no = self.file_seek(self.flash_to_file_offset(self.flash_offset - offset), SEEK_CUR)
		elif whence == SEEK_END:
			if offset == 0:
				no = self.file_seek(0, SEEK_END)
			elif offset < 0:
				no = self.file_seek(self.flash_to_file_offset(self.flash_size - offset), SEEK_END)
		# self.file_offset = no
		return self.file_to_flash_offset(no)

	def flash_read(self, num: int = 0) -> bytes:
		strt_page = self.flash_offset_to_page(self.flash_offset)
		strt_offs = self.flash_calc_page_offset(self.flash_offset)
		stop_page = self.flash_offset_to_page(self.flash_offset + num)
		stop_offs = self.flash_calc_page_offset(self.flash_offset + num)

		#print("\nFlash Read:")
		#print(f"\tFlash Size:   0x{self.flash_size:04X}")
		#print(f"\tStart Page:   {strt_page}")
		#print(f"\tStart Offset: {strt_offs}")
		#print(f"\tStop Page:    {stop_page}")
		#print(f"\tStop Offset:  {stop_offs}")

		with BytesIO() as bio:
			if strt_page == stop_page:  # only one page
				bio.write(self.get_page(strt_page)[strt_offs:stop_offs])

			for page_num in range(strt_page, stop_page):
				tmp_page = self.get_page(page_num)
				if page_num == strt_page:  # first page
					bio.write(tmp_page[strt_offs:])
				elif page_num == stop_page:  # last page
					bio.write(tmp_page[:stop_offs])
				else:  # between first and last
					bio.write(tmp_page)
			data = bio.getvalue()
		# self.flash_offset = self.flash_tell()
		return data

	def flash_write(self, data: (bytes, bytearray)) -> int:
		strt_page = self.flash_offset_to_page(self.flash_offset)
		strt_offs = self.flash_calc_page_offset(self.flash_offset)
		stop_page = self.flash_offset_to_page(self.flash_offset + len(data))
		stop_offs = self.flash_calc_page_offset(self.flash_offset + len(data))

		# print("\nFlash Write:")
		# print(f"\tFlash Size:   0x{self.flash_size:04X}")
		# print(f"\tStart Page:   {strt_page}")
		# print(f"\tStart Offset: {strt_offs}")
		# print(f"\tStop Page:    {stop_page}")
		# print(f"\tStop Offset:  {stop_offs}")

		nw = 0
		with BytesIO(data) as bio:
			if strt_page == stop_page:  # only one page
				chunk_size = stop_offs - strt_offs
				tmp_page = bytearray(self.get_page(strt_page))
				pack_into(f"{chunk_size}s", tmp_page, strt_offs, bio.read(chunk_size))

			for page_num in range(strt_page, stop_page):
				tmp_page = bytearray(self.get_page(page_num))
				if page_num == strt_page:  # first page
					chunk_size = 512 - strt_offs
					pack_into(f"{chunk_size}s", tmp_page, strt_offs, bio.read(512 - strt_offs))
				elif page_num == stop_page:  # last page
					chunk_size = 512 - stop_offs
					pack_into(f"{chunk_size}s", tmp_page, 0, bio.read(chunk_size))
				else:  # between first and last
					pack_into(f"512s", tmp_page, 0, bio.read(512))
				nw += self.set_page(page_num, tmp_page)
		# self.flash_offset = self.flash_tell()
		return nw

	# page I/O
	def get_page(self, num: int) -> bytes:
		"""
		Get a page by page number
		:param num:
		:return:
		"""
		self.file_seek(self.calc_page_offset(num))
		return self.file_read(512)

	def get_spare(self, num: int) -> bytes:
		"""
		Get a spare by page number
		:param num:
		:return:
		"""
		self.file_seek(self.calc_spare_offset(num))
		return self.file_read(16)

	def set_page(self, num: int, data: (bytes, bytearray)) -> int:
		"""
		Set a page by page number
		:param num:
		:param data:
		:return:
		"""
		assert 1 <= num <= self.num_pages, "Page number out of range"
		assert len(data) == 512, "Invalid page size"
		spare_data = self.get_spare(num)
		self.file_seek(self.calc_page_offset(num))
		(page_data, spare_data) = fix_page_ecc(data, spare_data)
		nw = self.file_write(page_data)
		nw += self.file_write(spare_data)
		return nw

	def set_spare(self, num: int, data: (bytes, bytearray)) -> int:
		"""
		Set a spare by spare number
		:param num:
		:param data:
		:return:
		"""
		assert 1 <= num <= self.num_pages, "Page number out of range"
		assert len(data) == 16, "Invalid spare size"
		self.file_seek(self.calc_spare_offset(num))
		return self.file_write(data)

def main() -> None:
	# p0 = Path(r"C:\Users\John\Desktop\xeBuild_1.21_zero\zero_rgl.bin")
	p0 = Path(r"Z:/Xbox 360/xeBuild_1.21_zero/zero_rgl.bin")
	with NANDImage(p0.read_bytes(), MODE_FLASH) as ni:
		# magic
		ni.seek(0x80)
		ni.write(pack(">H", 0xCA4A))
		# data offset, data size, and enabled
		ni.seek(0x88)
		ni.write(pack(">3I", 16, 72, 1))
		# target MAC
		ni.seek(0x98)
		ni.write(pack("6s", bytes.fromhex("0022485B4E17")))
		# host port
		ni.write(pack(">H", 50010))
		# host address
		ni.write(pack("4B", 192, 168, 1, 37))

		# ni.seek(0)
		# print(ni.read(512).hex().upper())

if __name__ == "__main__":
	main()