"""Human-readable JSON manifest emitter for compiled rulesets."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ruleset_compiler.ir import RulesetIR


def manifest_dict(
    ir: RulesetIR, *, compiler_options: dict[str, Any] | None = None
) -> dict[str, Any]:
    data = ir.to_json(include_pattern_bytes=True)
    data["compiler_options"] = compiler_options or {}
    data["summary"] = {
        "sources": len(ir.sources),
        "contexts": len(ir.contexts),
        "rules": len(ir.rules),
        "literal_patterns": len(ir.patterns),
        "selected_anchors": len(ir.selected_anchors),
    }
    return data


def write_manifest(
    ir: RulesetIR,
    output_path: Path,
    *,
    compiler_options: dict[str, Any] | None = None,
) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(
            manifest_dict(ir, compiler_options=compiler_options),
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
