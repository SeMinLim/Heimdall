from pfbench.data.synthetic import uniform_packets, ascii_packets, mixed_length_packets


class TestUniformPackets:
    def test_count_and_shape(self):
        pkts = list(uniform_packets(count=10, seed=42))
        assert len(pkts) == 10
        for payload, length in pkts:
            assert len(payload) == 64
            assert length == 64

    def test_deterministic(self):
        a = list(uniform_packets(count=5, seed=42))
        b = list(uniform_packets(count=5, seed=42))
        assert a == b

    def test_different_seeds(self):
        a = list(uniform_packets(count=5, seed=1))
        b = list(uniform_packets(count=5, seed=2))
        assert a != b


class TestAsciiPackets:
    def test_all_printable(self):
        pkts = list(ascii_packets(count=20, seed=42))
        for payload, length in pkts:
            assert len(payload) == 64
            assert length == 64
            assert all(0x20 <= b <= 0x7E for b in payload)

    def test_deterministic(self):
        a = list(ascii_packets(count=5, seed=42))
        b = list(ascii_packets(count=5, seed=42))
        assert a == b


class TestMixedLengthPackets:
    def test_short_long_ratio(self):
        pkts = list(mixed_length_packets(count=100, short_ratio=0.5, seed=42))
        assert len(pkts) == 100
        short_count = sum(1 for _, l in pkts if l < 32)
        # with 50% ratio, expect roughly half short
        assert 30 <= short_count <= 70

    def test_payload_padding(self):
        pkts = list(mixed_length_packets(count=10, short_ratio=1.0, seed=42))
        for payload, length in pkts:
            assert len(payload) == 64
            assert length < 64
            # bytes beyond length should be zero
            assert all(b == 0 for b in payload[length:])

    def test_deterministic(self):
        a = list(mixed_length_packets(count=5, short_ratio=0.5, seed=42))
        b = list(mixed_length_packets(count=5, short_ratio=0.5, seed=42))
        assert a == b
