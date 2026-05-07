"""Command line interface for the Heimdall RulesetCompiler."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

from ruleset_compiler.anchor_select import ScoreWeights, select_anchors
from ruleset_compiler.emit_hpat import write_hpat
from ruleset_compiler.emit_manifest import write_manifest
from ruleset_compiler.ir import RulesetIR
from ruleset_compiler.parsers.ips_workbook import parse_ips_workbook


@dataclass(frozen=True, slots=True)
class CompileResult:
    rules: int
    literal_patterns: int
    selected_anchors: int
    hpat_records: int | None


def compile_ir(
    ir: RulesetIR,
    *,
    manifest_path: Path | None = None,
    hpat_path: Path | None = None,
    record_size: int = 64,
    window_size: int = 8,
    allow_overlap: bool = True,
    deduplicate: bool = True,
    normalize_nocase: bool = True,
    weights: ScoreWeights = ScoreWeights(),
) -> CompileResult:
    if manifest_path is None and hpat_path is None:
        raise ValueError("at least one output path is required")
    if record_size <= 0:
        raise ValueError("record_size must be positive")
    if window_size <= 0:
        raise ValueError("window_size must be positive")
    if window_size > record_size:
        raise ValueError("window_size must be less than or equal to record_size")

    select_anchors(
        ir,
        window_size=window_size,
        allow_overlap=allow_overlap,
        deduplicate=deduplicate,
        weights=weights,
    )

    compiler_options = {
        "record_size": record_size,
        "window_size": window_size,
        "allow_overlap": allow_overlap,
        "deduplicate": deduplicate,
        "normalize_nocase": normalize_nocase,
        "weights": {
            "rarity": weights.rarity,
            "position_rarity": weights.position_rarity,
            "entropy": weights.entropy,
            "local_uniqueness": weights.local_uniqueness,
        },
    }

    hpat_records = None
    if hpat_path is not None:
        hpat_records = write_hpat(
            ir,
            hpat_path,
            record_size=record_size,
            window_size=window_size,
            normalize_nocase=normalize_nocase,
        )
    if manifest_path is not None:
        write_manifest(ir, manifest_path, compiler_options=compiler_options)

    return CompileResult(
        rules=len(ir.rules),
        literal_patterns=len(ir.patterns),
        selected_anchors=len(ir.selected_anchors),
        hpat_records=hpat_records,
    )


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ruleset_compiler",
        description="Compile source rulesets into Heimdall prefilter artifacts.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    workbook = subparsers.add_parser(
        "compile-ips-workbook",
        help="Compile from IPS workbook.",
    )
    workbook.add_argument("workbook", type=Path, help="Path to the IPS workbook XLSX")
    workbook.add_argument("--manifest", type=Path, help="Manifest JSON output path")
    workbook.add_argument("--hpat", type=Path, help="HPAT v1 binary output path")
    workbook.add_argument("--record-size", type=_positive_int, default=64)
    workbook.add_argument("--window-size", type=_positive_int, default=8)
    workbook.add_argument(
        "--non-overlap",
        action="store_true",
        help="Use non-overlapping window offsets.",
    )
    workbook.add_argument(
        "--allow-duplicate-anchors",
        action="store_true",
        help="Disable context-scoped anchor deduplication.",
    )
    workbook.add_argument(
        "--case-sensitive-hpat",
        action="store_true",
        help="Do not lowercase nocase literal bytes in HPAT records.",
    )
    workbook.set_defaults(func=_run_compile_ips_workbook)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    if args.manifest is None and args.hpat is None:
        parser.error("at least one of --manifest or --hpat is required")
    if args.window_size > args.record_size:
        parser.error("--window-size must be less than or equal to --record-size")

    return args.func(args)


def _run_compile_ips_workbook(args: argparse.Namespace) -> int:
    ir = parse_ips_workbook(args.workbook)
    result = compile_ir(
        ir,
        manifest_path=args.manifest,
        hpat_path=args.hpat,
        record_size=args.record_size,
        window_size=args.window_size,
        allow_overlap=not args.non_overlap,
        deduplicate=not args.allow_duplicate_anchors,
        normalize_nocase=not args.case_sensitive_hpat,
    )

    print(
        "compiled "
        f"rules={result.rules} "
        f"patterns={result.literal_patterns} "
        f"anchors={result.selected_anchors} "
        f"hpat_records={result.hpat_records if result.hpat_records is not None else 0}"
    )
    return 0


def _positive_int(raw: str) -> int:
    value = int(raw)
    if value <= 0:
        raise argparse.ArgumentTypeError("value must be positive")
    return value


if __name__ == "__main__":
    raise SystemExit(main())
