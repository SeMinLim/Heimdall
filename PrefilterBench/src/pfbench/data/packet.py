"""PCAP ingestion: strip L2/L3/L4 headers, extract application-layer payload."""

from collections.abc import Iterator
from pathlib import Path

import dpkt

from pfbench.constants import PAYLOAD_SIZE, Window


def load_pcap_dir(
    directory: Path,
) -> Iterator[tuple[str, list[Window]]]:
    """Yield ``(stem, packets)`` for each ``.pcap`` file in *directory*."""
    for pcap_path in sorted(directory.glob("*.pcap")):
        yield pcap_path.stem, list(load_pcap(pcap_path))


def load_pcap(path: Path) -> Iterator[Window]:
    with open(path, "rb") as f:
        reader = dpkt.pcap.Reader(f)
        for _, buf in reader:
            try:
                eth = dpkt.ethernet.Ethernet(buf)
            except dpkt.NeedData:
                continue

            if not isinstance(eth.data, dpkt.ip.IP):
                continue
            ip = eth.data

            transport = ip.data
            if isinstance(transport, (dpkt.tcp.TCP, dpkt.udp.UDP)):
                app_payload = transport.data
            else:
                continue

            if isinstance(app_payload, bytes):
                raw = app_payload
            else:
                raw = bytes(app_payload)

            length = min(len(raw), PAYLOAD_SIZE)
            padded = raw[:PAYLOAD_SIZE].ljust(PAYLOAD_SIZE, b"\x00")
            yield padded, length
