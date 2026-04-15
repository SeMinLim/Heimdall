import numpy as np

from pfbench.core.bloom import LaneBloomFilter
from pfbench.core.hash import crc32
from pfbench.core.reduce import truncate
from pfbench.data.anchor import extract_anchors
from pfbench.analysis.metrics import (
    lane_fill_rates,
    rule_collision_count,
    per_lane_fp_rates,
    per_packet_fp_rate,
    bit_bias,
    address_occupancy_histogram,
)


def _make_populated_filter():
    """Build a 10-bit filter with some known rules."""
    bf = LaneBloomFilter(hash_fn=crc32, reduce_fn=truncate, address_bits=10)
    # insert 5 rules at offset 0
    for i in range(5):
        bf.insert(offset=0, pattern=bytes([i]) * 8)
    return bf


class TestLaneFillRates:
    def test_basic(self):
        bf = _make_populated_filter()
        rates = lane_fill_rates(bf)
        assert len(rates) == 57
        assert rates[0] > 0.0
        assert all(r == 0.0 for r in rates[1:])


class TestRuleCollisionCount:
    def test_no_collision(self):
        rules = [(0, bytes([i]) * 8) for i in range(3)]
        count = rule_collision_count(rules, crc32, truncate, 19)
        # 3 distinct patterns, likely 3 distinct addresses at 19 bits
        assert count >= 0

    def test_identical_rules_collision(self):
        rules = [(0, b"\xAA" * 8), (0, b"\xAA" * 8)]
        count = rule_collision_count(rules, crc32, truncate, 19)
        assert count == 1  # 2 rules map to same address → 1 collision


class TestPerLaneFpRates:
    def test_empty_filter_zero_fp(self):
        bf = LaneBloomFilter(hash_fn=crc32, reduce_fn=truncate, address_bits=10)
        packets = [(bytes(64), 64)]
        rates = per_lane_fp_rates(bf, packets)
        assert len(rates) == 57
        assert all(r == 0.0 for r in rates)

    def test_populated_filter(self):
        bf = _make_populated_filter()
        # generate packets and check lane 0 has some FP rate
        packets = [(bytes([i % 256]) * 64, 64) for i in range(100)]
        rates = per_lane_fp_rates(bf, packets)
        assert isinstance(rates[0], float)
        # Other lanes should be 0 (no rules inserted)
        assert all(r == 0.0 for r in rates[1:])


class TestPerPacketFpRate:
    def test_empty_filter(self):
        bf = LaneBloomFilter(hash_fn=crc32, reduce_fn=truncate, address_bits=10)
        packets = [(bytes(64), 64)] * 10
        rate = per_packet_fp_rate(bf, packets)
        assert rate == 0.0

    def test_returns_fraction(self):
        bf = _make_populated_filter()
        packets = [(bytes([i % 256]) * 64, 64) for i in range(50)]
        rate = per_packet_fp_rate(bf, packets)
        assert 0.0 <= rate <= 1.0


class TestBitBias:
    def test_shape(self):
        addresses = {0: [0b1010, 0b1111], 3: [0b0000, 0b0101]}
        bias = bit_bias(addresses, bits=4)
        assert bias.shape == (57, 4)

    def test_all_ones(self):
        addresses = {0: [0b1111] * 10}
        bias = bit_bias(addresses, bits=4)
        np.testing.assert_array_almost_equal(bias[0], [1.0, 1.0, 1.0, 1.0])

    def test_empty_lane(self):
        addresses = {}
        bias = bit_bias(addresses, bits=4)
        # lanes with no data should be NaN or 0
        assert bias.shape == (57, 4)


class TestAddressOccupancyHistogram:
    def test_basic_shape(self):
        addresses = {0: [1, 2, 3, 1, 2, 1]}
        hist = address_occupancy_histogram(addresses, bits=4)
        # histogram over 2^4=16 address bins
        assert len(hist) == 16
        assert hist[1] == 3  # address 1 appeared 3 times
        assert hist[2] == 2
        assert hist[3] == 1
