"""Hardware architecture constants for Heimdall Long Engine prefilter."""

NUM_LANES = 57
ANCHOR_SIZE = 8
PAYLOAD_SIZE = 64

Packet = tuple[bytes, int]  # (payload_64B, payload_len)
