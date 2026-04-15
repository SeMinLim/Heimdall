"""Prefilter metrics: fill rates, collision counts, FP rates, bit bias."""

from collections import Counter
from typing import Callable

import numpy as np

from pfbench.core.bloom import LaneBloomFilter, NUM_LANES
from pfbench.data.anchor import extract_anchors


Packet = tuple[bytes, int]


def lane_fill_rates(bf: LaneBloomFilter) -> list[float]:
    return bf.fill_rates()


def rule_collision_count(
    rules: list[tuple[int, bytes]],
    hash_fn: Callable[[bytes], int],
    reduce_fn: Callable[[int, int], int],
    bits: int,
) -> int:
    seen: dict[tuple[int, int], int] = Counter()
    for offset, pattern in rules:
        addr = reduce_fn(hash_fn(pattern), bits)
        seen[(offset, addr)] += 1
    return sum(c - 1 for c in seen.values() if c > 1)


def per_lane_fp_rates(
    bf: LaneBloomFilter,
    packets: list[Packet],
) -> list[float]:
    hits = [0] * NUM_LANES
    counts = [0] * NUM_LANES
    for payload, length in packets:
        anchors = extract_anchors(payload, length)
        for lane, anchor in enumerate(anchors):
            counts[lane] += 1
            if bf.query(lane, anchor):
                hits[lane] += 1
    return [h / c if c > 0 else 0.0 for h, c in zip(hits, counts)]


def per_packet_fp_rate(
    bf: LaneBloomFilter,
    packets: list[Packet],
) -> float:
    if not packets:
        return 0.0
    fp_packets = 0
    for payload, length in packets:
        anchors = extract_anchors(payload, length)
        if any(bf.query(lane, anchor) for lane, anchor in enumerate(anchors)):
            fp_packets += 1
    return fp_packets / len(packets)


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
