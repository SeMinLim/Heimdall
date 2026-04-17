"""Prefilter metrics: fill rates, collision counts, FP rates, bit bias.

All per-traffic metrics operate on a two-level structure:
``packets: list[list[Window]]``: the outer list is wire packets, the inner
is the 64 B HW windows that packet decomposes into. ``Window`` is a
``(padded_64B_bytes, valid_len)`` tuple.

This lets us report both:
- **per-window FP rate**: the rate at which a single HW beat triggers
  at least one anchor hit. This is what the prefilter lane sees each cycle.
- **per-packet FP rate**: the rate at which a wire packet has *any*
  window trigger a hit. This is what IPS throughput ultimately sees.
"""

from collections import Counter
from typing import Callable

import numpy as np

from pfbench.constants import NUM_LANES, Window
from pfbench.core.bloom import BloomFilter
from pfbench.data.anchor import extract_anchors


def fill_rate(bf: BloomFilter) -> float:
    return bf.fill_rate()


def rule_collision_count(
    patterns: list[bytes],
    hash_fn: Callable[[bytes], int],
    reduce_fn: Callable[[int, int], int],
    bits: int,
) -> int:
    seen: dict[int, int] = Counter()
    for pattern in patterns:
        addr = reduce_fn(hash_fn(pattern), bits)
        seen[addr] += 1
    return sum(c - 1 for c in seen.values() if c > 1)


def _window_hits(bf: BloomFilter, window: Window) -> tuple[list[bool], int]:
    """Return (per-lane hit booleans for this window, anchor_count)."""
    payload, length = window
    anchors = extract_anchors(payload, length)
    return [bf.query(a) for a in anchors], len(anchors)


def per_lane_fp_rates(
    bf: BloomFilter,
    packets: list[list[Window]],
) -> list[float]:
    """FP rate per extraction-lane (0..56), aggregated over every window of every packet."""
    hits = [0] * NUM_LANES
    counts = [0] * NUM_LANES
    for windows in packets:
        for window in windows:
            lane_hits, _ = _window_hits(bf, window)
            for lane, h in enumerate(lane_hits):
                counts[lane] += 1
                if h:
                    hits[lane] += 1
    return [h / c if c > 0 else 0.0 for h, c in zip(hits, counts)]


def per_window_fp_rate(
    bf: BloomFilter,
    packets: list[list[Window]],
) -> float:
    """Fraction of 64 B windows where at least one of the 57 lanes hits."""
    total = 0
    fp = 0
    for windows in packets:
        for window in windows:
            lane_hits, n_anchors = _window_hits(bf, window)
            if n_anchors == 0:
                continue
            total += 1
            if any(lane_hits):
                fp += 1
    return fp / total if total else 0.0


def per_packet_fp_rate(
    bf: BloomFilter,
    packets: list[list[Window]],
) -> float:
    """Fraction of wire packets where *any* window triggers at least one hit."""
    if not packets:
        return 0.0
    fp = 0
    for windows in packets:
        if any(any(bf.query(a) for a in extract_anchors(p, n)) for p, n in windows):
            fp += 1
    return fp / len(packets)


def bit_bias(
    addresses_by_lane: dict[int, list[int]],
    bits: int,
) -> np.ndarray:
    result = np.full((NUM_LANES, bits), np.nan)
    for lane, addrs in addresses_by_lane.items():
        if not addrs:
            continue
        arr = np.array(addrs, dtype=np.uint32)
        for b in range(bits):
            result[lane, b] = np.mean((arr >> b) & 1)
    # fill NaN lanes with 0
    result = np.nan_to_num(result, nan=0.0)
    return result


def address_occupancy_histogram(
    addresses_by_lane: dict[int, list[int]],
    bits: int,
) -> list[int]:
    size = 1 << bits
    hist = [0] * size
    for addrs in addresses_by_lane.values():
        for addr in addrs:
            hist[addr] += 1
    return hist
