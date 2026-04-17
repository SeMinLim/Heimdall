"""Hardware architecture constants for Heimdall Long Engine prefilter."""

NUM_LANES = 57
ANCHOR_SIZE = 8
PAYLOAD_SIZE = 64

# A Window is one 64-byte HW beat (i_rx_data = 512b) plus its valid byte count.
# It is *not* a wire packet: a single L7 payload decomposes into one or more
# Windows (see pfbench.data.windows.windowize).
Window = tuple[bytes, int]  # (payload_64B, valid_len)
