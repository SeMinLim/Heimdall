from pfbench.data.anchor import extract_anchors


def test_full_64byte_payload():
    payload = bytes(range(64))
    anchors = extract_anchors(payload, 64)
    assert len(anchors) == 57
    for i, anchor in enumerate(anchors):
        assert anchor == payload[i : i + 8]


def test_15byte_payload():
    payload = bytes(range(15))
    anchors = extract_anchors(payload, 15)
    # valid offsets: 0..7 (i+8 <= 15 → i <= 7)
    assert len(anchors) == 8
    for i, anchor in enumerate(anchors):
        assert anchor == payload[i : i + 8]


def test_8byte_payload():
    payload = bytes(range(8)) + bytes(56)
    anchors = extract_anchors(payload, 8)
    assert len(anchors) == 1
    assert anchors[0] == bytes(range(8))


def test_7byte_payload():
    payload = bytes(range(7)) + bytes(57)
    anchors = extract_anchors(payload, 7)
    assert len(anchors) == 0


def test_zero_length():
    payload = bytes(64)
    anchors = extract_anchors(payload, 0)
    assert len(anchors) == 0


def test_payload_zero_padded():
    """Short payload is zero-padded to 64 bytes but anchors respect actual length."""
    raw = b"\xff" * 20
    payload = raw + bytes(44)  # zero-padded to 64
    anchors = extract_anchors(payload, 20)
    assert len(anchors) == 13  # max(0, min(57, 20-7))
    # first anchor is all 0xff
    assert anchors[0] == b"\xff" * 8
    # last valid anchor at offset 12: 8 bytes from offset 12
    assert anchors[12] == raw[12:20]
