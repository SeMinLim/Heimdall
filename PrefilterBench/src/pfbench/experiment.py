"""Experiment orchestrator: configure, run, and record prefilter benchmarks."""

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable

from pfbench.constants import Packet
from pfbench.core import hash as hash_mod
from pfbench.core import reduce as reduce_mod
from pfbench.core.bloom import BloomFilter
from pfbench.data.pattern import RulePattern, load_hex_list, load_json_export
from pfbench.data.anchor import extract_anchors
from pfbench.data.synthetic import uniform_packets, ascii_packets, mixed_length_packets
from pfbench.provenance import provenance
from pfbench.analysis.metrics import (
    fill_rate,
    rule_collision_count,
    per_lane_fp_rates,
    per_packet_fp_rate,
    bit_bias,
    address_occupancy_histogram,
)
from pfbench.analysis.summaries import (
    summarize_lane_fp,
    summarize_occupancy,
    theoretical_fp_lower_bound,
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


def _config_to_dict(config) -> dict:
    """Serialize dataclass config to a JSON-safe dict (Path → str)."""
    d = asdict(config)
    return {k: str(v) if isinstance(v, Path) else v for k, v in d.items()}


def _compute_metrics(
    bf: BloomFilter,
    rules: list[RulePattern],
    packets: list[Packet],
    hash_fn: Callable[[bytes], int],
    reduce_fn: Callable[[int, int], int],
    bits: int,
) -> tuple[dict, dict[int, list[int]]]:
    """Compute all metrics. Returns (metrics_dict, addresses_by_lane)."""
    addresses_by_lane: dict[int, list[int]] = {}
    for payload, length in packets:
        anchors = extract_anchors(payload, length)
        for lane, anchor in enumerate(anchors):
            addr = reduce_fn(hash_fn(anchor), bits)
            addresses_by_lane.setdefault(lane, []).append(addr)

    metrics = {
        "fill_rate": fill_rate(bf),
        "rule_collisions": rule_collision_count(
            [r.pattern for r in rules], hash_fn, reduce_fn, bits
        ),
        "per_lane_fp_rates": per_lane_fp_rates(bf, packets),
        "per_packet_fp_rate": per_packet_fp_rate(bf, packets),
        "address_occupancy": address_occupancy_histogram(addresses_by_lane, bits),
    }
    return metrics, addresses_by_lane


def _build_report(
    config,
    rules: list[RulePattern],
    packets: list[Packet],
    metrics: dict,
    inputs_extra: dict | None = None,
) -> dict:
    """Assemble a self-describing JSON report from metrics + config."""
    fr = metrics["fill_rate"]
    ppfp = metrics["per_packet_fp_rate"]
    lower = theoretical_fp_lower_bound(fr)

    inputs = {
        "rules_count": len(rules),
        "packets_count": len(packets),
    }
    if inputs_extra:
        inputs.update(inputs_extra)

    return {
        "config": _config_to_dict(config),
        "provenance": provenance(),
        "inputs": inputs,
        "headline": {
            "fill_rate": round(fr, 10),
            "per_packet_fp_rate": round(ppfp, 8),
            "theoretical_fp_lower_bound": round(lower, 8),
            "fp_overhead_vs_theoretical": (
                round(ppfp / lower, 4) if lower > 0 else None
            ),
            "rule_collisions": metrics["rule_collisions"],
        },
        "metrics": {
            "fill_rate": round(fr, 10),
            "rule_collisions": metrics["rule_collisions"],
            "per_packet_fp_rate": round(ppfp, 8),
            "per_lane_fp_rates": [round(x, 8) for x in metrics["per_lane_fp_rates"]],
        },
        "summary": {
            "per_lane_fp": summarize_lane_fp(metrics["per_lane_fp_rates"]),
            "occupancy": summarize_occupancy(metrics["address_occupancy"]),
        },
    }


def _save_report(
    report: dict,
    addresses_by_lane: dict[int, list[int]],
    out_dir: Path,
    bits: int,
) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)

    bias = bit_bias(addresses_by_lane, bits)
    plot_bit_bias_heatmap(bias, out_dir / "bit_bias.png")
    plot_occupancy_stripe(addresses_by_lane, bits, out_dir / "occupancy_stripe.png")
    plot_mi_matrix(addresses_by_lane, bits, out_dir / "mi_matrix.png")

    with open(out_dir / "metrics.json", "w") as f:
        json.dump(report, f, indent=2)


# ---------------------------------------------------------------------------
# Single-PCAP / synthetic experiment
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

    metrics, addresses_by_lane = _compute_metrics(
        bf, rules, packets, hash_fn, reduce_fn, bits
    )
    report = _build_report(
        config,
        rules,
        packets,
        metrics,
        inputs_extra={"packet_source": config.packet_source},
    )
    _save_report(report, addresses_by_lane, config.output_dir, bits)
    return report


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
        metrics, addresses_by_lane = _compute_metrics(
            bf, rules, all_packets, hash_fn, reduce_fn, bits
        )
        report = _build_report(
            config,
            rules,
            all_packets,
            metrics,
            inputs_extra={
                "pcap_count": len(pcap_entries),
                "batch_mode": "merged",
            },
        )
        _save_report(report, addresses_by_lane, config.output_dir, bits)
        return report

    # per_pcap mode
    per_pcap_results: list[dict] = []
    per_pcap_summaries: list[dict] = []
    total_packets = 0

    for stem, pkts in pcap_entries:
        metrics, addresses_by_lane = _compute_metrics(
            bf, rules, pkts, hash_fn, reduce_fn, bits
        )
        report = _build_report(
            config,
            rules,
            pkts,
            metrics,
            inputs_extra={"pcap_stem": stem, "batch_mode": "per_pcap"},
        )
        _save_report(report, addresses_by_lane, config.output_dir / stem, bits)
        per_pcap_results.append(report)
        per_pcap_summaries.append(
            {
                "pcap": stem,
                "packets": len(pkts),
                "per_packet_fp_rate": round(metrics["per_packet_fp_rate"], 8),
                "max_lane_fp": round(max(metrics["per_lane_fp_rates"]), 8)
                if metrics["per_lane_fp_rates"]
                else 0.0,
            }
        )
        total_packets += len(pkts)

    # Aggregate stats
    fp_rates = [s["per_packet_fp_rate"] for s in per_pcap_summaries]
    pkt_counts = [s["packets"] for s in per_pcap_summaries]
    weighted_mean = (
        sum(fp * n for fp, n in zip(fp_rates, pkt_counts)) / total_packets
        if total_packets
        else 0.0
    )
    arithmetic_mean = sum(fp_rates) / len(fp_rates) if fp_rates else 0.0

    fill_rate_val = (
        per_pcap_results[0]["metrics"]["fill_rate"] if per_pcap_results else 0.0
    )
    batch_summary = {
        "config": _config_to_dict(config),
        "provenance": provenance(),
        "inputs": {
            "rules_count": len(rules),
            "pcap_count": len(pcap_entries),
            "total_packets": total_packets,
            "batch_mode": "per_pcap",
        },
        "headline": {
            "fill_rate": fill_rate_val,
            "packet_weighted_mean_fp_rate": round(weighted_mean, 8),
            "arithmetic_mean_fp_rate": round(arithmetic_mean, 8),
            "max_fp_rate": round(max(fp_rates), 8) if fp_rates else 0.0,
            "min_fp_rate": round(min(fp_rates), 8) if fp_rates else 0.0,
            "nonzero_fp_pcap_count": sum(1 for fp in fp_rates if fp > 0),
            "theoretical_fp_lower_bound": round(
                theoretical_fp_lower_bound(fill_rate_val), 8
            ),
        },
        "per_pcap": per_pcap_summaries,
    }

    config.output_dir.mkdir(parents=True, exist_ok=True)
    with open(config.output_dir / "summary.json", "w") as f:
        json.dump(batch_summary, f, indent=2)

    # Per-PCAP FP histogram plot
    from pfbench.analysis.viz import plot_per_pcap_fp_histogram

    plot_per_pcap_fp_histogram(fp_rates, config.output_dir / "per_pcap_fp_hist.png")

    return batch_summary
