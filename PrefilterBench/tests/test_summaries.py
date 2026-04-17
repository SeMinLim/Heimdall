"""Tests for analysis.summaries helpers."""

from pfbench.analysis.summaries import (
    summarize_lane_fp,
    summarize_occupancy,
    theoretical_fp_lower_bound,
)


class TestSummarizeLaneFp:
    def test_basic(self):
        data = [0.01, 0.02, 0.03, 0.04, 0.05]
        s = summarize_lane_fp(data)
        assert abs(s["mean"] - 0.03) < 1e-9
        assert s["min"] == 0.01
        assert s["max"] == 0.05
        assert s["argmax_lane"] == 4
        assert s["top3_lanes"][0] == (4, 0.05)
        assert s["top3_lanes"][1] == (3, 0.04)

    def test_empty(self):
        s = summarize_lane_fp([])
        assert s["mean"] == 0.0
        assert s["argmax_lane"] is None
        assert s["top3_lanes"] == []

    def test_all_zero(self):
        s = summarize_lane_fp([0.0] * 57)
        assert s["max"] == 0.0
        assert s["std"] == 0.0


class TestSummarizeOccupancy:
    def test_basic(self):
        hist = [0, 3, 0, 1, 5, 0, 2]
        s = summarize_occupancy(hist, top_k=3)
        assert s["total_slots"] == 7
        assert s["nonzero_slots"] == 4
        assert s["max_hits"] == 5
        assert s["total_hits"] == 11
        assert s["top_k_addrs"] == [(4, 5), (1, 3), (6, 2)]

    def test_all_zero(self):
        s = summarize_occupancy([0, 0, 0, 0])
        assert s["nonzero_slots"] == 0
        assert s["max_hits"] == 0
        assert s["top_k_addrs"] == []

    def test_top_k_honored(self):
        hist = list(range(10))
        s = summarize_occupancy(hist, top_k=2)
        assert len(s["top_k_addrs"]) == 2
        assert s["top_k_addrs"][0] == (9, 9)


class TestTheoreticalFpLowerBound:
    def test_zero_fill(self):
        assert theoretical_fp_lower_bound(0.0) == 0.0

    def test_full_fill(self):
        assert theoretical_fp_lower_bound(1.0) == 1.0

    def test_small_fill(self):
        # fill=0.001, 57 lanes → 1 - 0.999^57 ≈ 0.0554
        assert abs(theoretical_fp_lower_bound(0.001) - 0.0554) < 0.001

    def test_custom_num_lanes(self):
        # fill=0.01, 10 lanes → 1 - 0.99^10 ≈ 0.0956
        assert abs(theoretical_fp_lower_bound(0.01, num_lanes=10) - 0.0956) < 0.001
