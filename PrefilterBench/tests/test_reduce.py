import pytest

from pfbench.core.reduce import truncate, xor_fold_overlap, xor_fold_kway, xor_fold_16


class TestTruncate:
    def test_basic_19bit(self):
        # 0xDEADBEEF = 0b1101_1110_1010_1101_1011_1110_1110_1111
        # lower 19 bits =         0b101_1011_1110_1110_1111 = 0x5BEEF
        assert truncate(0xDEADBEEF, 19) == 0xDEADBEEF & 0x7FFFF

    def test_identity_32bit(self):
        assert truncate(0xDEADBEEF, 32) == 0xDEADBEEF

    def test_16bit(self):
        assert truncate(0xDEADBEEF, 16) == 0xBEEF

    def test_1bit(self):
        assert truncate(0xDEADBEEF, 1) == 1
        assert truncate(0xDEADBEE0, 1) == 0


class TestXorFoldOverlap:
    def test_19bit(self):
        val = 0xDEADBEEF
        lo = val & 0x7FFFF  # bits [0:19]
        hi = (val >> 13) & 0x7FFFF  # bits [13:32]
        assert xor_fold_overlap(val, 19) == lo ^ hi

    def test_16bit_clean(self):
        val = 0xDEADBEEF
        lo = val & 0xFFFF
        hi = (val >> 16) & 0xFFFF
        assert xor_fold_overlap(val, 16) == lo ^ hi

    def test_32bit_identity(self):
        # overlap with itself → 0
        assert xor_fold_overlap(0xDEADBEEF, 32) == 0


class TestXorFoldKway:
    def test_16bit_2way(self):
        val = 0xDEADBEEF
        assert xor_fold_kway(val, 16) == (0xBEEF ^ 0xDEAD)

    def test_8bit_4way(self):
        val = 0xDEADBEEF
        assert xor_fold_kway(val, 8) == (0xEF ^ 0xBE ^ 0xAD ^ 0xDE)

    def test_19bit(self):
        val = 0xDEADBEEF
        # chunk0 = bits[0:19], chunk1 = bits[19:32] zero-padded to 19 bits
        c0 = val & 0x7FFFF
        c1 = (val >> 19) & 0x7FFFF  # 13 bits, zero-padded
        assert xor_fold_kway(val, 19) == c0 ^ c1

    def test_32bit_identity(self):
        assert xor_fold_kway(0xDEADBEEF, 32) == 0xDEADBEEF


class TestXorFold16:
    def test_basic(self):
        val = 0xDEADBEEF
        folded = (val & 0xFFFF) ^ ((val >> 16) & 0xFFFF)
        # then truncate to requested bits
        assert xor_fold_16(val, 12) == folded & 0xFFF

    def test_16bit(self):
        val = 0xDEADBEEF
        assert xor_fold_16(val, 16) == (0xBEEF ^ 0xDEAD)

    def test_rejects_over_16(self):
        with pytest.raises(ValueError):
            xor_fold_16(0xDEADBEEF, 17)
