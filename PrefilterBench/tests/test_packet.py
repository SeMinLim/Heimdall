import struct
from pathlib import Path

from pfbench.data.packet import load_pcap, load_pcap_dir


def _write_pcap(path: Path, packets: list[bytes]):
    """Write a minimal pcap file with raw Ethernet frames."""
    # pcap global header: magic, version 2.4, thiszone=0, sigfigs=0, snaplen=65535, network=1 (Ethernet)
    header = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    with open(path, "wb") as f:
        f.write(header)
        for pkt in packets:
            # packet header: ts_sec, ts_usec, incl_len, orig_len
            f.write(struct.pack("<IIII", 0, 0, len(pkt), len(pkt)))
            f.write(pkt)


def _make_eth_ip_tcp(payload: bytes) -> bytes:
    """Build a minimal Ethernet/IPv4/TCP frame with given payload."""
    # Ethernet: 14 bytes (dst=6 + src=6 + type=0x0800)
    eth = b"\x00" * 12 + b"\x08\x00"
    # IPv4: 20 bytes minimal, protocol=6 (TCP)
    ip_hdr = bytes(
        [
            0x45,
            0x00,  # version/IHL, DSCP/ECN
            0x00,
            0x00,  # total length (fill later)
            0x00,
            0x00,
            0x00,
            0x00,  # ID, flags, fragment
            0x40,
            0x06,  # TTL=64, proto=TCP
            0x00,
            0x00,  # checksum (skip)
            0x0A,
            0x00,
            0x00,
            0x01,  # src IP
            0x0A,
            0x00,
            0x00,
            0x02,  # dst IP
        ]
    )
    total_len = 20 + 20 + len(payload)
    ip_hdr = ip_hdr[:2] + struct.pack(">H", total_len) + ip_hdr[4:]
    # TCP: 20 bytes minimal (data offset = 5 words)
    tcp_hdr = bytes(
        [
            0x00,
            0x50,
            0x1F,
            0x90,  # src port 80, dst port 8080
            0x00,
            0x00,
            0x00,
            0x01,  # seq
            0x00,
            0x00,
            0x00,
            0x00,  # ack
            0x50,
            0x02,  # data offset=5, flags=SYN
            0xFF,
            0xFF,  # window
            0x00,
            0x00,  # checksum
            0x00,
            0x00,  # urgent
        ]
    )
    return eth + ip_hdr + tcp_hdr + payload


class TestLoadPcap:
    def test_basic_payload(self, tmp_path):
        payload = b"Hello, World! This is a test payload for PCAP parsing."
        frame = _make_eth_ip_tcp(payload)
        pcap_path = tmp_path / "test.pcap"
        _write_pcap(pcap_path, [frame])

        payloads = list(load_pcap(pcap_path))
        assert payloads == [payload]

    def test_long_payload_returned_intact(self, tmp_path):
        payload = bytes(range(256)) * 2  # 512 bytes
        frame = _make_eth_ip_tcp(payload)
        pcap_path = tmp_path / "test.pcap"
        _write_pcap(pcap_path, [frame])

        payloads = list(load_pcap(pcap_path))
        assert payloads == [payload]  # no truncation at the IO layer

    def test_zero_length_payload_skipped(self, tmp_path):
        frame = _make_eth_ip_tcp(b"")
        pcap_path = tmp_path / "test.pcap"
        _write_pcap(pcap_path, [frame])

        assert list(load_pcap(pcap_path)) == []

    def test_multiple_packets(self, tmp_path):
        frames = [_make_eth_ip_tcp(bytes([i]) * 30) for i in range(5)]
        pcap_path = tmp_path / "test.pcap"
        _write_pcap(pcap_path, frames)

        payloads = list(load_pcap(pcap_path))
        assert len(payloads) == 5
        for i, p in enumerate(payloads):
            assert p == bytes([i]) * 30


class TestLoadPcapDir:
    def test_yields_per_file(self, tmp_path):
        for name in ["alpha", "beta", "gamma"]:
            frame = _make_eth_ip_tcp(name.encode().ljust(20, b"\x00"))
            _write_pcap(tmp_path / f"{name}.pcap", [frame])

        entries = list(load_pcap_dir(tmp_path))
        assert len(entries) == 3
        stems = [stem for stem, _ in entries]
        assert stems == ["alpha", "beta", "gamma"]  # sorted
        for _, payloads in entries:
            assert len(payloads) == 1

    def test_empty_dir(self, tmp_path):
        assert list(load_pcap_dir(tmp_path)) == []

    def test_ignores_non_pcap(self, tmp_path):
        (tmp_path / "readme.txt").write_text("not a pcap")
        frame = _make_eth_ip_tcp(b"real data here!!!!!!")
        _write_pcap(tmp_path / "capture.pcap", [frame])

        entries = list(load_pcap_dir(tmp_path))
        assert len(entries) == 1
        assert entries[0][0] == "capture"
