"""Experiment orchestrator: configure, run, and record prefilter benchmarks."""

import json
from dataclasses import dataclass
from pathlib import Path

from pfbench.core import hash as hash_mod
from pfbench.core import reduce as reduce_mod
from pfbench.core.bloom import LaneBloomFilter
from pfbench.data.pattern import load_hex_list, load_json_export
from pfbench.data.anchor import extract_anchors
from pfbench.data.synthetic import uniform_packets, ascii_packets, mixed_length_packets
from pfbench.analysis.metrics import (
    lane_fill_rates,
    rule_collision_count,
    per_lane_fp_rates,
    per_packet_fp_rate,
    bit_bias,
    address_occupancy_histogram,
)
from pfbench.analysis.viz import (
    plot_bit_bias_heatmap,
    plot_occupancy_stripe,
    plot_mi_matrix,
)

HASH_FNS = {
    "crc32": hash_mod.crc32,
    "crc32c": hash_mod.crc32c,
}

REDUCE_FNS = {
    "truncate": reduce_mod.truncate,
    "xor_fold_overlap": reduce_mod.xor_fold_overlap,
    "xor_fold_kway": reduce_mod.xor_fold_kway,
    "xor_fold_16": reduce_mod.xor_fold_16,
}


@dataclass
class ExperimentConfig:
    hash_fn: str
    reduce_fn: str
    address_bits: int
    rules_path: Path
    rules_format: str  # "hex_list" or "json"
    packet_source: (
        str  # "synthetic_uniform", "synthetic_ascii", "synthetic_mixed", or pcap path
    )
    output_dir: Path
    packet_count: int = 100
    packet_seed: int = 42
    short_ratio: float = 0.5


def run_experiment(config: ExperimentConfig) -> dict:
    hash_fn = HASH_FNS[config.hash_fn]
    reduce_fn = REDUCE_FNS[config.reduce_fn]
    bits = config.address_bits

    # Load rules
    if config.rules_format == "hex_list":
        rules = load_hex_list(config.rules_path)
    elif config.rules_format == "json":
        rules = load_json_export(config.rules_path)
    else:
        raise ValueError(f"Unknown rules format: {config.rules_format}")

    # Build per-lane bloom filter
    bf = LaneBloomFilter(hash_fn=hash_fn, reduce_fn=reduce_fn, address_bits=bits)
    for rule in rules:
        bf.insert(offset=rule.offset, pattern=rule.pattern)

    # Load packets
    if config.packet_source == "synthetic_uniform":
        packets = list(uniform_packets(config.packet_count, config.packet_seed))
    elif config.packet_source == "synthetic_ascii":
        packets = list(ascii_packets(config.packet_count, config.packet_seed))
    elif config.packet_source == "synthetic_mixed":
        packets = list(
            mixed_length_packets(
                config.packet_count, config.short_ratio, config.packet_seed
            )
        )
    else:
        from pfbench.data.packet import load_pcap

        packets = list(load_pcap(Path(config.packet_source)))

    # Compute addresses for analysis
    addresses_by_lane: dict[int, list[int]] = {}
    for payload, length in packets:
        anchors = extract_anchors(payload, length)
        for lane, anchor in enumerate(anchors):
            addr = reduce_fn(hash_fn(anchor), bits)
            addresses_by_lane.setdefault(lane, []).append(addr)

    # Compute metrics
    result = {
        "lane_fill_rates": lane_fill_rates(bf),
        "rule_collisions": rule_collision_count(
            [(r.offset, r.pattern) for r in rules], hash_fn, reduce_fn, bits
        ),
        "per_lane_fp_rates": per_lane_fp_rates(bf, packets),
        "per_packet_fp_rate": per_packet_fp_rate(bf, packets),
        "address_occupancy": address_occupancy_histogram(addresses_by_lane, bits),
    }

    # Generate plots
    out_dir = config.output_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    bias = bit_bias(addresses_by_lane, bits)
    plot_bit_bias_heatmap(bias, out_dir / "bit_bias.png")
    plot_occupancy_stripe(addresses_by_lane, bits, out_dir / "occupancy_stripe.png")
    plot_mi_matrix(addresses_by_lane, bits, out_dir / "mi_matrix.png")

    # Save metrics
    serializable = {
        k: v
        if not isinstance(v, list) or not v or not isinstance(v[0], float)
        else [round(x, 8) for x in v]
        for k, v in result.items()
    }
    serializable["per_packet_fp_rate"] = round(result["per_packet_fp_rate"], 8)
    with open(out_dir / "metrics.json", "w") as f:
        json.dump(serializable, f, indent=2)

    return result
