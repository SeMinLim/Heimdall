from pfbench.core.hash import crc32, crc32c


def test_crc32_check_value():
    """ITU-T V.42 check value: CRC32 of ASCII "123456789"."""
    assert crc32(b"123456789") == 0xCBF43926


def test_crc32c_check_value():
    """RFC 3720 §B.4 check value: CRC32C of ASCII "123456789"."""
    assert crc32c(b"123456789") == 0xE3069283


def test_crc32_empty():
    assert crc32(b"") == 0x00000000


def test_crc32c_empty():
    assert crc32c(b"") == 0x00000000


def test_crc32_single_byte():
    # CRC32 of b"\x00" = 0xD202EF8D
    assert crc32(b"\x00") == 0xD202EF8D


def test_crc32c_single_byte():
    # CRC32C of b"\x00" = 0x527D5351
    assert crc32c(b"\x00") == 0x527D5351


def test_crc32_8bytes():
    """8-byte input — the anchor size used by the prefilter."""
    data = bytes([0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE])
    result = crc32(data)
    assert isinstance(result, int)
    assert 0 <= result < 2**32


def test_crc32c_8bytes():
    data = bytes([0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE])
    result = crc32c(data)
    assert isinstance(result, int)
    assert 0 <= result < 2**32
