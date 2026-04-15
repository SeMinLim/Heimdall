"""Rule-pattern loading from JSON export and hex-list formats."""

import json
from dataclasses import dataclass
from pathlib import Path


EXPECTED_PATTERN_LEN = 8


@dataclass(frozen=True, slots=True)
class RulePattern:
    offset: int
    pattern: bytes


def load_hex_list(path: Path) -> list[RulePattern]:
    patterns: list[RulePattern] = []
    for line in path.read_text().splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        offset_str, hex_str = stripped.split()
        raw = bytes.fromhex(hex_str)
        if len(raw) != EXPECTED_PATTERN_LEN:
            raise ValueError(
                f"Pattern must be {EXPECTED_PATTERN_LEN} bytes, got {len(raw)}: {hex_str}"
            )
        patterns.append(RulePattern(offset=int(offset_str), pattern=raw))
    return patterns


def load_json_export(path: Path) -> list[RulePattern]:
    data = json.loads(path.read_text())
    patterns: list[RulePattern] = []
    for record in data:
        raw = bytes.fromhex(record["pattern_hex"])
        if len(raw) != EXPECTED_PATTERN_LEN:
            raise ValueError(
                f"Pattern must be {EXPECTED_PATTERN_LEN} bytes, got {len(raw)}"
            )
        patterns.append(RulePattern(offset=record["offset"], pattern=raw))
    return patterns
