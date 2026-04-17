"""Summary statistics for human-interpretable reporting."""

from __future__ import annotations

import numpy as np

from pfbench.constants import NUM_LANES


def summarize_lane_fp(per_lane_fp: list[float]) -> dict:
    """Summarize 57-lane FP rate list into headline statistics.

    Returns ``mean``, ``median``, ``std``, ``min``, ``max``, ``argmax``,
    and the top-3 worst lanes as ``(lane, rate)`` pairs.
    """
    if not per_lane_fp:
        return {
            "mean": 0.0,
            "median": 0.0,
            "std": 0.0,
            "min": 0.0,
            "max": 0.0,
            "argmax_lane": None,
            "top3_lanes": [],
        }
    arr = np.asarray(per_lane_fp, dtype=np.float64)
    top3_idx = np.argsort(arr)[::-1][:3]
    return {
        "mean": float(arr.mean()),
        "median": float(np.median(arr)),
        "std": float(arr.std()),
        "min": float(arr.min()),
        "max": float(arr.max()),
        "argmax_lane": int(arr.argmax()),
        "top3_lanes": [(int(i), float(arr[i])) for i in top3_idx],
    }


def summarize_occupancy(histogram: list[int], top_k: int = 10) -> dict:
    """Summarize address-occupancy histogram.

    The raw histogram is typically 2^N entries where only a tiny fraction are
    non-zero. This compresses it to ``nonzero_count``, ``max``, selected
    percentiles, and the top-K most-hit addresses.
    """
    arr = np.asarray(histogram, dtype=np.int64)
    nonzero = arr[arr > 0]
    if nonzero.size == 0:
        return {
            "total_slots": int(arr.size),
            "nonzero_slots": 0,
            "max_hits": 0,
            "mean_hits_nonzero": 0.0,
            "p50_hits_nonzero": 0,
            "p95_hits_nonzero": 0,
            "p99_hits_nonzero": 0,
            "total_hits": 0,
            "top_k_addrs": [],
        }

    top_idx = np.argsort(arr)[::-1][:top_k]
    return {
        "total_slots": int(arr.size),
        "nonzero_slots": int(nonzero.size),
        "max_hits": int(nonzero.max()),
        "mean_hits_nonzero": float(nonzero.mean()),
        "p50_hits_nonzero": int(np.percentile(nonzero, 50)),
        "p95_hits_nonzero": int(np.percentile(nonzero, 95)),
        "p99_hits_nonzero": int(np.percentile(nonzero, 99)),
        "total_hits": int(arr.sum()),
        "top_k_addrs": [(int(i), int(arr[i])) for i in top_idx if arr[i] > 0],
    }


def theoretical_fp_lower_bound(fill_rate: float, num_lanes: int = NUM_LANES) -> float:
    """Naive lower-bound estimate for per-packet FP rate.

    Assumes independent lane queries over uniform address space:
    ``P(at least one lane hits) = 1 - (1 - fill_rate)^num_lanes``.
    Real rates exceed this when packet anchors cluster in high-hit addresses.
    """
    if fill_rate <= 0.0:
        return 0.0
    if fill_rate >= 1.0:
        return 1.0
    return 1.0 - (1.0 - fill_rate) ** num_lanes
