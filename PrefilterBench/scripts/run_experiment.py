#!/usr/bin/env python3
"""CLI entry point for running a prefilter benchmark experiment."""

import argparse
from pathlib import Path

from pfbench.data.windows import WINDOW_MODELS
from pfbench.experiment import (
    ExperimentConfig,
    BatchConfig,
    run_experiment,
    run_batch_experiment,
)


def main():
    parser = argparse.ArgumentParser(description="Run a prefilter benchmark experiment")
    parser.add_argument("--hash", choices=["crc32", "crc32c"], required=True)
    parser.add_argument(
        "--reduce",
        choices=["truncate", "xor_fold_overlap", "xor_fold_kway", "xor_fold_16"],
        required=True,
    )
    parser.add_argument("--bits", type=int, required=True)
    parser.add_argument("--rules", type=Path, required=True)
    parser.add_argument(
        "--rules-format", choices=["hex_list", "json"], default="hex_list"
    )
    parser.add_argument(
        "--packets",
        default="synthetic_uniform",
        help="synthetic_uniform, synthetic_ascii, synthetic_mixed, path to .pcap, or directory of .pcap files",
    )
    parser.add_argument("--packet-count", type=int, default=1000)
    parser.add_argument("--packet-seed", type=int, default=42)
    parser.add_argument("--short-ratio", type=float, default=0.5)
    parser.add_argument(
        "--batch-mode",
        choices=["per_pcap", "merged"],
        default="per_pcap",
        help="Batch mode when --packets is a directory (default: per_pcap)",
    )
    parser.add_argument(
        "--window-model",
        choices=list(WINDOW_MODELS),
        default="tile64",
        help=(
            "How to decompose packet payload into 64B HW windows: "
            "'first' (legacy, first 64B only), 'tile64' (non-overlap, default), "
            "'slide57' (57B stride overlap to cover cross-beat 8B anchors)."
        ),
    )
    parser.add_argument(
        "--output", type=Path, default=Path("experiments/results/default")
    )
    args = parser.parse_args()

    packets_path = (
        Path(args.packets)
        if args.packets
        not in {"synthetic_uniform", "synthetic_ascii", "synthetic_mixed"}
        else None
    )

    # Directory of PCAPs → batch mode
    if packets_path and packets_path.is_dir():
        config = BatchConfig(
            hash_fn=args.hash,
            reduce_fn=args.reduce,
            address_bits=args.bits,
            rules_path=args.rules,
            rules_format=args.rules_format,
            pcap_dir=packets_path,
            output_dir=args.output,
            batch_mode=args.batch_mode,
            window_model=args.window_model,
        )

        print(
            f"Batch experiment ({args.batch_mode}): {args.hash} + {args.reduce} @ {args.bits} bits  [window={args.window_model}]"
        )
        print(f"PCAP directory: {packets_path}")
        result = run_batch_experiment(config)

        if args.batch_mode == "merged":
            inp = result["inputs"]
            h = result["headline"]
            print(f"Total PCAPs: {inp['pcap_count']}, packets: {inp['packets_count']}")
            print(f"Fill rate: {h['fill_rate']:.6f}")
            print(f"Per-window FP rate: {h['per_window_fp_rate']:.6f}")
            print(f"Per-packet FP rate: {h['per_packet_fp_rate']:.6f}")
            print(
                f"Theoretical lower bound: {h['theoretical_fp_lower_bound']:.6f}  "
                f"(overhead ×{h['fp_overhead_vs_theoretical']})"
                if h.get("fp_overhead_vs_theoretical") is not None
                else f"Theoretical lower bound: {h['theoretical_fp_lower_bound']:.6f}"
            )
        else:
            inp = result["inputs"]
            h = result["headline"]
            print(f"Total PCAPs: {inp['pcap_count']}, packets: {inp['total_packets']}")
            print(f"Fill rate: {h['fill_rate']:.6f}")
            print(
                f"Packet-weighted mean FP rate: {h['packet_weighted_mean_fp_rate']:.6f}"
            )
            print(f"Arithmetic mean FP rate:      {h['arithmetic_mean_fp_rate']:.6f}")
            print(f"Max FP rate: {h['max_fp_rate']:.6f}")
            print(f"Nonzero FP PCAPs: {h['nonzero_fp_pcap_count']}/{inp['pcap_count']}")
            print(f"Theoretical lower bound: {h['theoretical_fp_lower_bound']:.6f}")
        print(f"Results saved to: {args.output}")
        return

    # Single PCAP or synthetic
    config = ExperimentConfig(
        hash_fn=args.hash,
        reduce_fn=args.reduce,
        address_bits=args.bits,
        rules_path=args.rules,
        rules_format=args.rules_format,
        packet_source=args.packets,
        packet_count=args.packet_count,
        packet_seed=args.packet_seed,
        short_ratio=args.short_ratio,
        output_dir=args.output,
        window_model=args.window_model,
    )

    print(
        f"Running experiment: {args.hash} + {args.reduce} @ {args.bits} bits  [window={args.window_model}]"
    )
    result = run_experiment(config)
    h = result["headline"]
    print(f"Fill rate: {h['fill_rate']:.6f}")
    print(f"Per-window FP rate: {h['per_window_fp_rate']:.6f}")
    print(f"Per-packet FP rate: {h['per_packet_fp_rate']:.6f}")
    print(f"Theoretical lower bound: {h['theoretical_fp_lower_bound']:.6f}")
    if h.get("fp_overhead_vs_theoretical") is not None:
        print(f"  overhead factor: ×{h['fp_overhead_vs_theoretical']}")
    print(f"Rule collisions: {h['rule_collisions']}")
    print(f"Results saved to: {args.output}")


if __name__ == "__main__":
    main()
