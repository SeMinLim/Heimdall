#!/usr/bin/env python3
"""Generate a positive-hit fixture for the current prefilter loader."""

from __future__ import annotations

import argparse
import json
import struct
from pathlib import Path


PACKET_BYTES = 64
RECORD_BYTES = 64
WINDOW_BYTES = 8
PREFILTER_ADDR_BITS = 19
PREFILTER_ADDR_MASK = (1 << PREFILTER_ADDR_BITS) - 1
CRC32_POLY_REFLECTED = 0xEDB88320
CRC_INIT = 0xFFFFFFFF
DEFAULT_ANCHOR = b"HEIMDALL"


def crc32_update_32_reflected(crc: int, word: int) -> int:
    for bit_index in range(32):
        feedback = ((crc ^ (word >> bit_index)) & 1) != 0
        crc >>= 1
        if feedback:
            crc ^= CRC32_POLY_REFLECTED
        crc &= 0xFFFFFFFF
    return crc


def crc64_hw_compatible(anchor: bytes) -> int:
    if len(anchor) != WINDOW_BYTES:
        raise ValueError(f"anchor must be exactly {WINDOW_BYTES} bytes")
    lo32 = int.from_bytes(anchor[:4], byteorder="little")
    hi32 = int.from_bytes(anchor[4:], byteorder="little")
    return crc32_update_32_reflected(
        crc32_update_32_reflected(CRC_INIT, lo32), hi32
    )


def reduce_crc_to_prefilter_addr(hash_value: int) -> int:
    lower = hash_value & PREFILTER_ADDR_MASK
    upper = (hash_value >> 13) & PREFILTER_ADDR_MASK
    return lower ^ upper


def make_packet(anchor: bytes) -> bytes:
    filler_len = PACKET_BYTES - len(anchor)
    filler = bytes(((0xA5 + 29 * offset) & 0xFF) for offset in range(filler_len))
    return anchor + filler


def make_hpat(anchor: bytes) -> bytes:
    header = struct.pack("<4sHHHI", b"HPAT", 1, RECORD_BYTES, WINDOW_BYTES, 1)
    record = anchor.ljust(RECORD_BYTES, b"\x00")
    return header + struct.pack("<H", len(anchor)) + record


def packet_matching_offsets(packet: bytes, prefilter_addr: int) -> list[int]:
    offsets: list[int] = []
    for offset in range(PACKET_BYTES - WINDOW_BYTES + 1):
        anchor = packet[offset : offset + WINDOW_BYTES]
        hash_value = crc64_hw_compatible(anchor)
        addr = reduce_crc_to_prefilter_addr(hash_value)
        if addr == prefilter_addr:
            offsets.append(offset)
    return offsets


def parse_anchor(raw: str) -> bytes:
    anchor = raw.encode("ascii")
    if len(anchor) != WINDOW_BYTES:
        raise argparse.ArgumentTypeError(
            f"anchor must be exactly {WINDOW_BYTES} ASCII bytes"
        )
    return anchor


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate HPAT and packet files with a known CRC32 prefilter hit."
    )
    parser.add_argument(
        "out_dir",
        nargs="?",
        default="prefilter_smoke",
        type=Path,
        help="output directory for positive.hpat, positive_packets.bin, expected.json",
    )
    parser.add_argument(
        "--anchor",
        default=DEFAULT_ANCHOR.decode("ascii"),
        type=parse_anchor,
        help="8-byte ASCII anchor inserted into both HPAT and packet",
    )
    args = parser.parse_args()

    out_dir: Path = args.out_dir
    anchor: bytes = args.anchor
    out_dir.mkdir(parents=True, exist_ok=True)

    packet = make_packet(anchor)
    hash_value = crc64_hw_compatible(anchor)
    prefilter_addr = reduce_crc_to_prefilter_addr(hash_value)
    matching_offsets = packet_matching_offsets(packet, prefilter_addr)

    hpat_path = out_dir / "positive.hpat"
    packet_path = out_dir / "positive_packets.bin"
    expected_path = out_dir / "expected.json"

    hpat_path.write_bytes(make_hpat(anchor))
    packet_path.write_bytes(packet)
    expected_path.write_text(
        json.dumps(
            {
                "anchor_ascii": anchor.decode("ascii"),
                "crc32_no_final_xor": f"0x{hash_value:08x}",
                "prefilter_addr": prefilter_addr,
                "expected_packet0_hit_count": len(matching_offsets),
                "matching_packet_offsets": matching_offsets,
                "host_expectations": {
                    "packets_with_hits": 1 if matching_offsets else 0,
                    "total_lane_hits": len(matching_offsets),
                },
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    print("[Heimdall Prefilter Positive Fixture]")
    print(f"  HPAT:      {hpat_path}")
    print(f"  Packets:   {packet_path}")
    print(f"  Expected:  {expected_path}")
    print(f"  Address:   {prefilter_addr}")
    print(f"  Hit count: {len(matching_offsets)}")
    print(f"  Offsets:   {matching_offsets}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
