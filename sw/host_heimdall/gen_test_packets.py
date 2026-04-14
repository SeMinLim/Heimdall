#!/usr/bin/env python3
"""Generate a binary file with N x 64-byte test packets."""
import struct
import sys
import os

def main():
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 16
    out = sys.argv[2] if len(sys.argv) > 2 else "test_packets.bin"

    with open(out, "wb") as f:
        for i in range(n):
            # Fill each 64-byte packet with a recognizable pattern
            pkt = bytes([(i + j) & 0xFF for j in range(64)])
            f.write(pkt)

    print(f"Generated {n} packets ({n * 64} bytes) -> {out}")

if __name__ == "__main__":
    main()
