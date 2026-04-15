"""Long Engine anchor extraction: 8-byte overlapping windows from 64-byte payloads."""

MAX_LANES = 57
ANCHOR_SIZE = 8


def extract_anchors(payload: bytes, payload_len: int) -> list[bytes]:
    valid_count = max(0, min(MAX_LANES, payload_len - ANCHOR_SIZE + 1))
    return [payload[i : i + ANCHOR_SIZE] for i in range(valid_count)]
