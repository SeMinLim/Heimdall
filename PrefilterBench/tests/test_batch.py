"""Tests for batch experiment modes: per_pcap and merged."""

import struct
from pathlib import Path

from pfbench.experiment import BatchConfig, run_batch_experiment


def _write_pcap(path: Path, packets: list[bytes]):
    header = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    with open(path, "wb") as f:
        f.write(header)
        for pkt in packets:
            f.write(struct.pack("<IIII", 0, 0, len(pkt), len(pkt)))
            f.write(pkt)


def _make_eth_ip_tcp(payload: bytes) -> bytes:
    eth = b"\x00" * 12 + b"\x08\x00"
    ip_hdr = bytes(
        [
            0x45, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x40, 0x06, 0x00, 0x00,
            0x0A, 0x00, 0x00, 0x01,
            0x0A, 0x00, 0x00, 0x02,
        ]
    )
    total_len = 20 + 20 + len(payload)
    ip_hdr = ip_hdr[:2] + struct.pack(">H", total_len) + ip_hdr[4:]
    tcp_hdr = bytes(
        [
            0x00, 0x50, 0x1F, 0x90,
            0x00, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00,
            0x50, 0x02, 0xFF, 0xFF,
            0x00, 0x00, 0x00, 0x00,
        ]
    )
    return eth + ip_hdr + tcp_hdr + payload


def _make_pcap_dir(tmp_path: Path, n_files: int = 3, pkts_per_file: int = 2):
    rules_file = tmp_path / "rules.txt"
    lines = [f"{i} {f'{i:02x}' * 8}" for i in range(5)]
    rules_file.write_text("\n".join(lines))

    pcap_dir = tmp_path / "pcaps"
    pcap_dir.mkdir()
    for f_idx in range(n_files):
        frames = [
            _make_eth_ip_tcp(bytes([f_idx * 10 + p]) * 30)
            for p in range(pkts_per_file)
        ]
        _write_pcap(pcap_dir / f"capture_{f_idx:03d}.pcap", frames)

    return rules_file, pcap_dir


class TestBatchPerPcap:
    def test_returns_per_pcap_results(self, tmp_path):
        rules_file, pcap_dir = _make_pcap_dir(tmp_path, n_files=3)
        config = BatchConfig(
            hash_fn="crc32",
            reduce_fn="truncate",
            address_bits=10,
            rules_path=rules_file,
            rules_format="hex_list",
            pcap_dir=pcap_dir,
            output_dir=tmp_path / "out",
            batch_mode="per_pcap",
        )

        summary = run_batch_experiment(config)

        assert summary["batch_mode"] == "per_pcap"
        assert summary["total_pcaps"] == 3
        assert len(summary["per_pcap"]) == 3
        assert "mean_fp_rate" in summary
        assert "max_fp_rate" in summary
        # summary.json written
        assert (tmp_path / "out" / "summary.json").exists()

    def test_per_pcap_subdirectories(self, tmp_path):
        rules_file, pcap_dir = _make_pcap_dir(tmp_path, n_files=2)
        config = BatchConfig(
            hash_fn="crc32",
            reduce_fn="truncate",
            address_bits=10,
            rules_path=rules_file,
            rules_format="hex_list",
            pcap_dir=pcap_dir,
            output_dir=tmp_path / "out",
            batch_mode="per_pcap",
        )

        run_batch_experiment(config)

        # Each PCAP gets its own subdirectory with metrics + plots
        for stem in ["capture_000", "capture_001"]:
            sub = tmp_path / "out" / stem
            assert sub.exists()
            assert (sub / "metrics.json").exists()
            assert any(sub.glob("*.png"))

    def test_fill_rate_same_across_pcaps(self, tmp_path):
        rules_file, pcap_dir = _make_pcap_dir(tmp_path, n_files=3)
        config = BatchConfig(
            hash_fn="crc32",
            reduce_fn="truncate",
            address_bits=10,
            rules_path=rules_file,
            rules_format="hex_list",
            pcap_dir=pcap_dir,
            output_dir=tmp_path / "out",
            batch_mode="per_pcap",
        )

        summary = run_batch_experiment(config)

        fill_rates = {r["fill_rate"] for r in summary["per_pcap"]}
        assert len(fill_rates) == 1  # same bloom filter → same fill rate


class TestBatchMerged:
    def test_merged_returns_single_result(self, tmp_path):
        rules_file, pcap_dir = _make_pcap_dir(tmp_path, n_files=3, pkts_per_file=4)
        config = BatchConfig(
            hash_fn="crc32",
            reduce_fn="truncate",
            address_bits=10,
            rules_path=rules_file,
            rules_format="hex_list",
            pcap_dir=pcap_dir,
            output_dir=tmp_path / "out",
            batch_mode="merged",
        )

        result = run_batch_experiment(config)

        assert result["total_pcaps"] == 3
        assert result["total_packets"] == 12  # 3 files × 4 packets
        assert isinstance(result["per_packet_fp_rate"], float)
        assert isinstance(result["fill_rate"], float)

    def test_merged_writes_metrics(self, tmp_path):
        rules_file, pcap_dir = _make_pcap_dir(tmp_path)
        config = BatchConfig(
            hash_fn="crc32",
            reduce_fn="truncate",
            address_bits=10,
            rules_path=rules_file,
            rules_format="hex_list",
            pcap_dir=pcap_dir,
            output_dir=tmp_path / "out",
            batch_mode="merged",
        )

        run_batch_experiment(config)

        assert (tmp_path / "out" / "metrics.json").exists()
        assert any((tmp_path / "out").glob("*.png"))

    def test_merged_packet_count_matches_sum(self, tmp_path):
        """Merged packet count == sum of all per-file packets."""
        rules_file, pcap_dir = _make_pcap_dir(tmp_path, n_files=5, pkts_per_file=3)
        config = BatchConfig(
            hash_fn="crc32",
            reduce_fn="truncate",
            address_bits=10,
            rules_path=rules_file,
            rules_format="hex_list",
            pcap_dir=pcap_dir,
            output_dir=tmp_path / "out",
            batch_mode="merged",
        )

        result = run_batch_experiment(config)
        assert result["total_packets"] == 15


class TestBatchEmpty:
    def test_empty_dir_per_pcap(self, tmp_path):
        rules_file = tmp_path / "rules.txt"
        rules_file.write_text("0 DEADBEEFCAFEBABE\n")
        pcap_dir = tmp_path / "empty_pcaps"
        pcap_dir.mkdir()

        config = BatchConfig(
            hash_fn="crc32",
            reduce_fn="truncate",
            address_bits=10,
            rules_path=rules_file,
            rules_format="hex_list",
            pcap_dir=pcap_dir,
            output_dir=tmp_path / "out",
            batch_mode="per_pcap",
        )

        summary = run_batch_experiment(config)
        assert summary["total_pcaps"] == 0
        assert summary["per_pcap"] == []

    def test_empty_dir_merged(self, tmp_path):
        rules_file = tmp_path / "rules.txt"
        rules_file.write_text("0 DEADBEEFCAFEBABE\n")
        pcap_dir = tmp_path / "empty_pcaps"
        pcap_dir.mkdir()

        config = BatchConfig(
            hash_fn="crc32",
            reduce_fn="truncate",
            address_bits=10,
            rules_path=rules_file,
            rules_format="hex_list",
            pcap_dir=pcap_dir,
            output_dir=tmp_path / "out",
            batch_mode="merged",
        )

        result = run_batch_experiment(config)
        assert result["total_pcaps"] == 0
        assert result["total_packets"] == 0
        assert result["per_packet_fp_rate"] == 0.0
