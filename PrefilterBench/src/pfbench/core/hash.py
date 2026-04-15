"""CRC32 and CRC32C hash functions for 8-byte anchor hashing."""

import zlib

import crcmod


_crc32c_fn = crcmod.predefined.mkCrcFun("crc-32c")


def crc32(data: bytes) -> int:
    return zlib.crc32(data) & 0xFFFFFFFF


def crc32c(data: bytes) -> int:
    return _crc32c_fn(data)
