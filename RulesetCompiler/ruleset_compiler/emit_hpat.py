"""HPAT v1 writer"""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Iterable

from ruleset_compiler.ir import LiteralPattern, RulesetIR


HPAT_MAGIC = b"HPAT"
HPAT_VERSION = 1
HEADER_STRUCT = struct.Struct("<4sHHHI")
ENTRY_HEADER_STRUCT = struct.Struct("<H")


def write_hpat(
    ir: RulesetIR,
    output_path: Path,
    *,
    record_size: int = 64,
    window_size: int = 8,
    normalize_nocase: bool = True,
) -> int:
    records = list(
        _iter_hpat_records(
            ir.patterns,
            record_size=record_size,
            window_size=window_size,
            normalize_nocase=normalize_nocase,
        )
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)

    payload = bytearray(
        HEADER_STRUCT.pack(
            HPAT_MAGIC, HPAT_VERSION, record_size, window_size, len(records)
        )
    )
    for pattern_len, record in records:
        payload += ENTRY_HEADER_STRUCT.pack(pattern_len)
        payload += record

    output_path.write_bytes(payload)
    return len(records)


def _iter_hpat_records(
    patterns: Iterable[LiteralPattern],
    *,
    record_size: int,
    window_size: int,
    normalize_nocase: bool,
) -> Iterable[tuple[int, bytes]]:
    for pattern in patterns:
        data = pattern.normalized_data() if normalize_nocase else pattern.data
        if len(data) < window_size:
            continue
        clipped = data[:record_size]
        yield len(clipped), clipped.ljust(record_size, b"\x00")


def read_hpat_header(path: Path) -> dict[str, int | bytes]:
    data = path.read_bytes()
    magic, version, record_size, window_size, num_records = HEADER_STRUCT.unpack_from(
        data
    )
    return {
        "magic": magic,
        "version": version,
        "record_size": record_size,
        "window_size": window_size,
        "num_records": num_records,
    }
