#!/usr/bin/env python3

from __future__ import annotations

import argparse
from pathlib import Path

CRC32_POLY_REFLECTED = 0xEDB88320
CRC32C_POLY_REFLECTED = 0x82F63B78
PACKET_BYTES = 64
ANCHOR_BYTES = 8
LANE_COUNT = PACKET_BYTES - ANCHOR_BYTES + 1


def build_table(poly: int) -> list[int]:
    table: list[int] = []
    for value in range(256):
        crc = value
        for _ in range(8):
            crc = (crc >> 1) ^ poly if (crc & 1) else (crc >> 1)
        table.append(crc & 0xFFFFFFFF)
    return table


CRC32_TABLE = build_table(CRC32_POLY_REFLECTED)
CRC32C_TABLE = build_table(CRC32C_POLY_REFLECTED)


def crc_update(data: bytes, table: list[int]) -> int:
    crc = 0xFFFFFFFF
    for byte in data:
        crc = ((crc >> 8) ^ table[(crc ^ byte) & 0xFF]) & 0xFFFFFFFF
    return crc ^ 0xFFFFFFFF


def crc32(data: bytes) -> int:
    return crc_update(data, CRC32_TABLE)


def crc32c(data: bytes) -> int:
    return crc_update(data, CRC32C_TABLE)


def encode_lane_hex(anchor: bytes) -> str:
    return "".join(f"{byte:02x}" for byte in reversed(anchor))


def generate_vectors() -> list[tuple[str, int, int]]:
    packet = bytes(range(PACKET_BYTES))
    vectors: list[tuple[str, int, int]] = []

    for pos in range(LANE_COUNT):
        anchor = packet[pos : pos + ANCHOR_BYTES]
        vectors.append((encode_lane_hex(anchor), crc32(anchor), crc32c(anchor)))

    zeros = bytes([0x00] * ANCHOR_BYTES)
    ones = bytes([0xFF] * ANCHOR_BYTES)
    vectors.append((encode_lane_hex(zeros), crc32(zeros), crc32c(zeros)))
    vectors.append((encode_lane_hex(ones), crc32(ones), crc32c(ones)))
    return vectors


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate CRC32/CRC32C test vectors for BSV testbenches."
    )
    parser.add_argument(
        "--output",
        default="testvec.hex",
        help="Output file path. Default: testvec.hex",
    )
    args = parser.parse_args()

    output_path = Path(args.output)
    vectors = generate_vectors()
    output_path.write_text(
        "".join(
            f"{lane_hex} {crc_a:08x} {crc_b:08x}\n"
            for lane_hex, crc_a, crc_b in vectors
        ),
        encoding="ascii",
    )

    print(f"Generated {output_path} with {len(vectors)} test vectors")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
