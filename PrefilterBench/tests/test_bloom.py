from pfbench.core.bloom import BloomFilter
from pfbench.core.hash import crc32
from pfbench.core.reduce import truncate


def _make_filter(bits=19):
    return BloomFilter(hash_fn=crc32, reduce_fn=truncate, address_bits=bits)


def test_empty_filter_query_false():
    bf = _make_filter()
    assert bf.query(b"\x00" * 8) is False
    assert bf.query(b"\xff" * 8) is False


def test_insert_and_query():
    bf = _make_filter()
    pattern = b"\xde\xad\xbe\xef\xca\xfe\xba\xbe"
    bf.insert(pattern)
    assert bf.query(pattern) is True


def test_query_different_pattern():
    bf = _make_filter()
    bf.insert(b"\xde\xad\xbe\xef\xca\xfe\xba\xbe")
    assert bf.query(b"\x01\x02\x03\x04\x05\x06\x07\x08") is False


def test_fill_rate_empty():
    bf = _make_filter(bits=10)
    assert bf.fill_rate() == 0.0


def test_fill_rate_after_insert():
    bf = _make_filter(bits=10)  # 1024 addresses
    bf.insert(b"\x01" * 8)
    assert bf.fill_rate() == 1.0 / 1024


def test_multiple_rules():
    bf = _make_filter(bits=10)
    bf.insert(b"\x01" * 8)
    bf.insert(b"\x02" * 8)
    rate = bf.fill_rate()
    # 2 distinct addresses set (unless collision)
    assert rate >= 1.0 / 1024
    assert rate <= 2.0 / 1024


def test_duplicate_insert_idempotent():
    bf = _make_filter(bits=10)
    bf.insert(b"\x01" * 8)
    bf.insert(b"\x01" * 8)
    assert bf.fill_rate() == 1.0 / 1024
