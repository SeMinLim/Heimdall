"""Per-lane bloom filter model for offline prefilter analysis."""

from typing import Callable

from pfbench.constants import NUM_LANES


class LaneBloomFilter:
    def __init__(
        self,
        hash_fn: Callable[[bytes], int],
        reduce_fn: Callable[[int, int], int],
        address_bits: int,
    ):
        self._hash_fn = hash_fn
        self._reduce_fn = reduce_fn
        self._bits = address_bits
        self._size = 1 << address_bits
        self._arrays: list[bytearray] = [
            bytearray(self._size) for _ in range(NUM_LANES)
        ]

    def _address(self, pattern: bytes) -> int:
        return self._reduce_fn(self._hash_fn(pattern), self._bits)

    def insert(self, offset: int, pattern: bytes) -> None:
        addr = self._address(pattern)
        self._arrays[offset][addr] = 1

    def query(self, lane: int, anchor: bytes) -> bool:
        addr = self._address(anchor)
        return self._arrays[lane][addr] == 1

    def fill_rates(self) -> list[float]:
        return [sum(arr) / self._size for arr in self._arrays]
