"""Shared bloom filter model for offline prefilter analysis."""

from typing import Callable


class BloomFilter:
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
        self._array = bytearray(self._size)

    def _address(self, pattern: bytes) -> int:
        return self._reduce_fn(self._hash_fn(pattern), self._bits)

    def insert(self, pattern: bytes) -> None:
        addr = self._address(pattern)
        self._array[addr] = 1

    def query(self, anchor: bytes) -> bool:
        addr = self._address(anchor)
        return self._array[addr] == 1

    def fill_rate(self) -> float:
        return sum(self._array) / self._size
