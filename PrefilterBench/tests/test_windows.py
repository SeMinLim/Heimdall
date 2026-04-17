"""Tests for packet → 64B window decomposition."""

import pytest

from pfbench.data.windows import windowize


class TestFirstModel:
    def test_truncates_to_64(self):
        payload = bytes(range(100))
        windows = windowize(payload, 100, "first")
        assert len(windows) == 1
        buf, length = windows[0]
        assert len(buf) == 64
        assert length == 64
        assert buf == payload[:64]

    def test_short_payload_zero_padded(self):
        payload = b"Hi"
        windows = windowize(payload, 2, "first")
        assert len(windows) == 1
        buf, length = windows[0]
        assert length == 2
        assert buf[:2] == b"Hi"
        assert buf[2:] == bytes(62)

    def test_zero_length_returns_empty(self):
        assert windowize(bytes(64), 0, "first") == []


class TestTile64Model:
    def test_exact_multiple(self):
        payload = bytes(range(128)) * 2  # 256 B
        windows = windowize(payload, 256, "tile64")
        assert len(windows) == 4
        for i, (buf, length) in enumerate(windows):
            assert length == 64
            assert buf == payload[i * 64 : (i + 1) * 64]

    def test_partial_last_tile(self):
        payload = bytes(range(100)) + bytes(28)  # 128 bytes raw buffer, but len=100
        windows = windowize(payload, 100, "tile64")
        assert len(windows) == 2
        assert windows[0][1] == 64
        assert windows[0][0] == payload[:64]
        # Second tile: 36 valid bytes, zero-padded
        assert windows[1][1] == 36
        assert windows[1][0][:36] == payload[64:100]
        assert windows[1][0][36:] == bytes(28)

    def test_single_tile_below_64(self):
        payload = b"abcdefghij" + bytes(54)
        windows = windowize(payload, 10, "tile64")
        assert len(windows) == 1
        assert windows[0] == (payload[:64], 10)

    def test_zero_length(self):
        assert windowize(bytes(64), 0, "tile64") == []


class TestSlide57Model:
    def test_exactly_64(self):
        payload = bytes(range(64))
        windows = windowize(payload, 64, "slide57")
        # One window suffices: last_start = 64-8 = 56, first start=0 → done after +57
        assert len(windows) == 1
        assert windows[0] == (payload, 64)

    def test_covers_cross_boundary_anchors(self):
        # 128 B payload: tile64 would miss anchors starting at offsets 57..63
        # (they straddle the 64-byte boundary). slide57 must cover them.
        payload = bytes(range(128))
        windows = windowize(payload, 128, "slide57")
        # starts: 0, 57, 114; last_start = 128-8 = 120 ≥ 114, so 3 windows.
        assert len(windows) == 3
        assert windows[0][0] == payload[0:64]
        assert windows[1][0] == payload[57:121].ljust(64, b"\x00")
        # Third window starts at 114, only 14 valid bytes
        assert windows[2][1] == 14
        assert windows[2][0][:14] == payload[114:128]

    def test_skips_payload_below_anchor_size(self):
        assert windowize(b"abcdefg" + bytes(57), 7, "slide57") == []

    def test_min_payload_for_one_window(self):
        payload = bytes(range(8)) + bytes(56)
        windows = windowize(payload, 8, "slide57")
        assert len(windows) == 1
        assert windows[0][1] == 8


class TestUnknownModel:
    def test_raises(self):
        with pytest.raises(ValueError, match="Unknown window_model"):
            windowize(bytes(64), 64, "bogus")
