"""Experiment orchestrator: configure, run, and record prefilter benchmarks."""

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from pfbench.constants import Packet
from pfbench.core import hash as hash_mod
from pfbench.core import reduce as reduce_mod
from pfbench.core.bloom import BloomFilter
from pfbench.data.pattern import RulePattern, load_hex_list, load_json_export
from pfbench.data.anchor import extract_anchors
from pfbench.data.synthetic import uniform_packets, ascii_packets, mixed_length_packets
from pfbench.analysis.metrics import (
    fill_rate,
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


@dataclass
class BatchConfig:
    hash_fn: str
    reduce_fn: str
    address_bits: int
    rules_path: Path
    rules_format: str
    pcap_dir: Path
    output_dir: Path
    batch_mode: str = "per_pcap"  # "per_pcap" or "merged"


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _load_rules(path: Path, fmt: str) -> list[RulePattern]:
    if fmt == "hex_list":
        return load_hex_list(path)
    elif fmt == "json":
        return load_json_export(path)
    raise ValueError(f"Unknown rules format: {fmt}")


def _build_bloom_filter(
    rules: list[RulePattern],
    hash_fn: Callable[[bytes], int],
    reduce_fn: Callable[[int, int], int],
    bits: int,
) -> BloomFilter:
    bf = BloomFilter(hash_fn=hash_fn, reduce_fn=reduce_fn, address_bits=bits)
    for rule in rules:
        bf.insert(pattern=rule.pattern)
    return bf


def _compute_metrics(
    bf: BloomFilter,
    rules: list[RulePattern],
    packets: list[Packet],
    hash_fn: Callable[[bytes], int],
    reduce_fn: Callable[[int, int], int],
    bits: int,
) -> dict:
    addresses_by_lane: dict[int, list[int]] = {}
    for payload, length in packets:
        anchors = extract_anchors(payload, length)
        for lane, anchor in enumerate(anchors):
            addr = reduce_fn(hash_fn(anchor), bits)
            addresses_by_lane.setdefault(lane, []).append(addr)

    return {
        "fill_rate": fill_rate(bf),
        "rule_collisions": rule_collision_count(
            [r.pattern for r in rules], hash_fn, reduce_fn, bits
        ),
        "per_lane_fp_rates": per_lane_fp_rates(bf, packets),
        "per_packet_fp_rate": per_packet_fp_rate(bf, packets),
        "address_occupancy": address_occupancy_histogram(addresses_by_lane, bits),
        "_addresses_by_lane": addresses_by_lane,
    }


def _save_metrics(result: dict, out_dir: Path, bits: int) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)

    # Plots
    addresses_by_lane = result.pop("_addresses_by_lane")
    bias = bit_bias(addresses_by_lane, bits)
    plot_bit_bias_heatmap(bias, out_dir / "bit_bias.png")
    plot_occupancy_stripe(addresses_by_lane, bits, out_dir / "occupancy_stripe.png")
    plot_mi_matrix(addresses_by_lane, bits, out_dir / "mi_matrix.png")

    # JSON
    serializable = {
        k: v
        if not isinstance(v, list) or not v or not isinstance(v[0], float)
        else [round(x, 8) for x in v]
        for k, v in result.items()
    }
    serializable["fill_rate"] = round(result["fill_rate"], 8)
    serializable["per_packet_fp_rate"] = round(result["per_packet_fp_rate"], 8)
    with open(out_dir / "metrics.json", "w") as f:
        json.dump(serializable, f, indent=2)


# ---------------------------------------------------------------------------
# Single-PCAP / synthetic experiment (unchanged API)
# ---------------------------------------------------------------------------


def run_experiment(config: ExperimentConfig) -> dict:
    hash_fn = HASH_FNS[config.hash_fn]
    reduce_fn = REDUCE_FNS[config.reduce_fn]
    bits = config.address_bits

    rules = _load_rules(config.rules_path, config.rules_format)
    bf = _build_bloom_filter(rules, hash_fn, reduce_fn, bits)

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

    result = _compute_metrics(bf, rules, packets, hash_fn, reduce_fn, bits)
    _save_metrics(result, config.output_dir, bits)
    return result


# ---------------------------------------------------------------------------
# Batch experiment: per-PCAP or merged
# ---------------------------------------------------------------------------


def run_batch_experiment(config: BatchConfig) -> dict:
    from pfbench.data.packet import load_pcap_dir

    hash_fn = HASH_FNS[config.hash_fn]
    reduce_fn = REDUCE_FNS[config.reduce_fn]
    bits = config.address_bits

    rules = _load_rules(config.rules_path, config.rules_format)
    bf = _build_bloom_filter(rules, hash_fn, reduce_fn, bits)

    pcap_entries = list(load_pcap_dir(config.pcap_dir))

    if config.batch_mode == "merged":
        all_packets: list[Packet] = []
        for _, pkts in pcap_entries:
            all_packets.extend(pkts)
        result = _compute_metrics(bf, rules, all_packets, hash_fn, reduce_fn, bits)
        _save_metrics(result, config.output_dir, bits)
        result["total_pcaps"] = len(pcap_entries)
        result["total_packets"] = len(all_packets)
        return result

    # per_pcap mode
    per_pcap_results: list[dict] = []
    for stem, pkts in pcap_entries:
        r = _compute_metrics(bf, rules, pkts, hash_fn, reduce_fn, bits)
        _save_metrics(r, config.output_dir / stem, bits)
        per_pcap_results.append(
            {
                "pcap": stem,
                "fill_rate": r["fill_rate"],
                "per_packet_fp_rate": r["per_packet_fp_rate"],
                "rule_collisions": r["rule_collisions"],
            }
        )

    fp_rates = [r["per_packet_fp_rate"] for r in per_pcap_results]
    summary = {
        "batch_mode": "per_pcap",
        "total_pcaps": len(per_pcap_results),
        "fill_rate": per_pcap_results[0]["fill_rate"] if per_pcap_results else 0.0,
        "rule_collisions": (
            per_pcap_results[0]["rule_collisions"] if per_pcap_results else 0
        ),
        "mean_fp_rate": sum(fp_rates) / len(fp_rates) if fp_rates else 0.0,
        "max_fp_rate": max(fp_rates) if fp_rates else 0.0,
        "nonzero_fp_count": sum(1 for fp in fp_rates if fp > 0),
        "per_pcap": per_pcap_results,
    }

    config.output_dir.mkdir(parents=True, exist_ok=True)
    with open(config.output_dir / "summary.json", "w") as f:
        json.dump(
            {
                k: round(v, 8) if isinstance(v, float) else v
                for k, v in summary.items()
            },
            f,
            indent=2,
        )

    return summary
