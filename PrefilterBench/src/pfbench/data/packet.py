"""PCAP ingestion: strip L2/L3/L4 headers, yield raw L7 payload bytes.

Frames that are not IPv4 + TCP/UDP and frames with zero-length L7 payloads
are skipped silently.
"""

from collections.abc import Iterator
from pathlib import Path

import dpkt


MAX_PAYLOAD_BYTES = 9018  # jumbo-frame ceiling; guards against pathological captures


def load_pcap_dir(directory: Path) -> Iterator[tuple[str, list[bytes]]]:
    """Yield ``(stem, payloads)`` for each ``.pcap`` file in *directory*.

    ``payloads`` is the list of raw L7 payload byte-strings, one per wire packet.
    """
    for pcap_path in sorted(directory.glob("*.pcap")):
        yield pcap_path.stem, list(load_pcap(pcap_path))


def load_pcap(path: Path) -> Iterator[bytes]:
    """Yield one raw L7 payload (``bytes``) per TCP/UDP-over-IPv4 frame."""
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
            if not isinstance(transport, (dpkt.tcp.TCP, dpkt.udp.UDP)):
                continue

            app_payload = transport.data
            raw = app_payload if isinstance(app_payload, bytes) else bytes(app_payload)
            if not raw:
                continue

            if len(raw) > MAX_PAYLOAD_BYTES:
                raw = raw[:MAX_PAYLOAD_BYTES]

            yield raw
