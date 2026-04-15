"""Synthetic traffic generators for offline prefilter benchmarking."""

import random
from collections.abc import Iterator

Packet = tuple[bytes, int]  # (payload_64B, payload_len)

PAYLOAD_SIZE = 64


def uniform_packets(count: int, seed: int) -> Iterator[Packet]:
    rng = random.Random(seed)
    for _ in range(count):
        payload = bytes(rng.getrandbits(8) for _ in range(PAYLOAD_SIZE))
        yield payload, PAYLOAD_SIZE


def ascii_packets(count: int, seed: int) -> Iterator[Packet]:
    rng = random.Random(seed)
    for _ in range(count):
        payload = bytes(rng.randint(0x20, 0x7E) for _ in range(PAYLOAD_SIZE))
        yield payload, PAYLOAD_SIZE


def mixed_length_packets(count: int, short_ratio: float, seed: int) -> Iterator[Packet]:
    rng = random.Random(seed)
    for _ in range(count):
        if rng.random() < short_ratio:
            length = rng.randint(1, 31)
        else:
            length = rng.randint(32, PAYLOAD_SIZE)
        raw = bytes(rng.getrandbits(8) for _ in range(length))
        payload = raw + bytes(PAYLOAD_SIZE - length)
        yield payload, length
