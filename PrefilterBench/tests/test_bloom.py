from pfbench.core.bloom import LaneBloomFilter
from pfbench.core.hash import crc32
from pfbench.core.reduce import truncate


def _make_filter(bits=19):
    return LaneBloomFilter(hash_fn=crc32, reduce_fn=truncate, address_bits=bits)


def test_empty_filter_query_false():
    bf = _make_filter()
    assert bf.query(0, b"\x00" * 8) is False
    assert bf.query(56, b"\xff" * 8) is False


def test_insert_and_query_correct_lane():
    bf = _make_filter()
    pattern = b"\xde\xad\xbe\xef\xca\xfe\xba\xbe"
    bf.insert(offset=3, pattern=pattern)
    assert bf.query(3, pattern) is True


def test_query_wrong_lane():
    bf = _make_filter()
    pattern = b"\xde\xad\xbe\xef\xca\xfe\xba\xbe"
    bf.insert(offset=3, pattern=pattern)
    # same pattern but queried on lane 0 — should be False
    assert bf.query(0, pattern) is False


def test_fill_rate_empty():
    bf = _make_filter(bits=10)
    rates = bf.fill_rates()
    assert len(rates) == 57
    assert all(r == 0.0 for r in rates)


def test_fill_rate_after_insert():
    bf = _make_filter(bits=10)  # 1024 addresses per lane
    bf.insert(offset=5, pattern=b"\x01" * 8)
    rates = bf.fill_rates()
    assert rates[5] == 1.0 / 1024
    # other lanes untouched
    assert rates[0] == 0.0
    assert rates[56] == 0.0


def test_multiple_rules_same_lane():
    bf = _make_filter(bits=10)
    bf.insert(offset=0, pattern=b"\x01" * 8)
    bf.insert(offset=0, pattern=b"\x02" * 8)
    rates = bf.fill_rates()
    # 2 distinct addresses set (unless collision)
    assert rates[0] >= 1.0 / 1024
    assert rates[0] <= 2.0 / 1024


def test_multiple_lanes():
    bf = _make_filter(bits=10)
    for lane in range(57):
        bf.insert(offset=lane, pattern=bytes([lane]) * 8)
    rates = bf.fill_rates()
    assert all(r > 0.0 for r in rates)
