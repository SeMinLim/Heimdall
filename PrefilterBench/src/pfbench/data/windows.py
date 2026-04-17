"""Packet → 64 B window decomposition (HW beat model).

Heimdall's Pattern Matcher consumes packets as a stream of 512-bit beats
(``i_rx_data`` = 64 bytes per cycle). Prefilter queries are made per beat:
from each 64 B window, 57 overlapping 8-byte anchors (offsets 0..56) are
extracted and looked up in the shared bloom filter.

The choice of *how* to decompose a longer payload into 64 B windows is a
modeling parameter for offline analysis:

``first``
    Legacy PrefilterBench behaviour — take only the first 64 B of the
    application-layer payload. Underestimates FP for packets longer than 64 B.

``tile64``
    Non-overlapping 64 B tiles. Closest to a HW pipeline that processes each
    beat independently (no cross-beat anchor extraction). **Default.**

``slide57``
    Overlap each window by 7 bytes (stride = 64 − 7 = 57) so every possible
    8-byte anchor in the payload is observed, including those that would
    straddle a tile boundary. Closest to a HW pipeline that buffers the last
    7 bytes of each beat to feed anchor-extraction across boundaries.
"""

from __future__ import annotations

from pfbench.constants import ANCHOR_SIZE, PAYLOAD_SIZE, Packet

WindowModel = str  # "first" | "tile64" | "slide57"
WINDOW_MODELS: tuple[str, ...] = ("first", "tile64", "slide57")


def _pad(chunk: bytes) -> bytes:
    return chunk.ljust(PAYLOAD_SIZE, b"\x00")


def windowize(payload: bytes, length: int, model: str) -> list[Packet]:
    """Decompose *payload[:length]* into 64 B windows per *model*.

    ``payload`` may be longer than ``length``; only the first ``length`` bytes
    are treated as valid. Each returned window is a fixed-size 64 B byte
    string (zero-padded) and a valid-byte count in ``[0, 64]``.

    Returns an empty list when ``length == 0`` (no observable anchors).
    """
    if length <= 0:
        return []
    raw = payload[:length]

    if model == "first":
        return [(_pad(raw[:PAYLOAD_SIZE]), min(length, PAYLOAD_SIZE))]

    if model == "tile64":
        out: list[Packet] = []
        for start in range(0, length, PAYLOAD_SIZE):
            chunk = raw[start : start + PAYLOAD_SIZE]
            out.append((_pad(chunk), len(chunk)))
        return out

    if model == "slide57":
        # A window only contributes anchors if it has ≥ 8 valid bytes.
        if length < ANCHOR_SIZE:
            return []
        out = []
        stride = PAYLOAD_SIZE - (ANCHOR_SIZE - 1)  # 57
        last_start = length - ANCHOR_SIZE  # last start that still yields ≥1 anchor
        start = 0
        while start <= last_start:
            chunk = raw[start : start + PAYLOAD_SIZE]
            out.append((_pad(chunk), len(chunk)))
            start += stride
        return out

    raise ValueError(f"Unknown window_model: {model!r} (expected one of {WINDOW_MODELS})")
