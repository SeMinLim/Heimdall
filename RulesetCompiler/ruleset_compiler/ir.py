"""Source-neutral IR for Heimdall prefilter rule compilation."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


JsonObject = dict[str, Any]


def empty_json_object() -> JsonObject:
    return {}


def empty_str_list() -> list[str]:
    return []


def empty_rule_sources() -> list["RuleSource"]:
    return []


def empty_match_contexts() -> list["MatchContext"]:
    return []


def empty_rules() -> list["Rule"]:
    return []


def empty_literal_patterns() -> list["LiteralPattern"]:
    return []


def empty_selected_anchors() -> list["SelectedAnchor"]:
    return []


def bytes_to_hex(data: bytes) -> str:
    return data.hex()


def hex_to_bytes(data: str) -> bytes:
    return bytes.fromhex(data)


@dataclass(slots=True)
class RuleSource:
    source_id: int
    source_type: str
    uri: str
    native_engine: str = "custom"
    checksum: str | None = None
    metadata: JsonObject = field(default_factory=empty_json_object)

    def to_json(self) -> JsonObject:
        return {
            "source_id": self.source_id,
            "source_type": self.source_type,
            "uri": self.uri,
            "native_engine": self.native_engine,
            "checksum": self.checksum,
            "metadata": self.metadata,
        }


@dataclass(slots=True)
class MatchContext:
    context_id: int
    protocol: str = "any"
    buffer_kind: str = "payload"
    normalization: str = "raw"
    direction: str = "either"
    stream_scope: str = "packet"
    transform_chain: list[str] = field(default_factory=empty_str_list)
    metadata: JsonObject = field(default_factory=empty_json_object)

    def to_json(self) -> JsonObject:
        return {
            "context_id": self.context_id,
            "protocol": self.protocol,
            "buffer_kind": self.buffer_kind,
            "normalization": self.normalization,
            "direction": self.direction,
            "stream_scope": self.stream_scope,
            "transform_chain": self.transform_chain,
            "metadata": self.metadata,
        }


@dataclass(slots=True)
class Rule:
    rule_uid: int
    source_id: int
    native_id: str
    native_engine: str
    action: str = "alert"
    enabled: bool = True
    severity: str | None = None
    message: str | None = None
    source_line: int | None = None
    metadata: JsonObject = field(default_factory=empty_json_object)

    def to_json(self) -> JsonObject:
        return {
            "rule_uid": self.rule_uid,
            "source_id": self.source_id,
            "native_id": self.native_id,
            "native_engine": self.native_engine,
            "action": self.action,
            "enabled": self.enabled,
            "severity": self.severity,
            "message": self.message,
            "source_line": self.source_line,
            "metadata": self.metadata,
        }


@dataclass(slots=True)
class LiteralPattern:
    pattern_uid: int
    rule_uid: int
    context_id: int
    data: bytes
    nocase: bool = False
    offset: int | None = None
    depth: int | None = None
    pattern_type: str = "TEXT"
    source_line: int | None = None
    metadata: JsonObject = field(default_factory=empty_json_object)

    @property
    def length(self) -> int:
        return len(self.data)

    def normalized_data(self) -> bytes:
        if not self.nocase:
            return self.data
        return bytes(byte + 32 if 65 <= byte <= 90 else byte for byte in self.data)

    def to_json(self, include_bytes: bool = True) -> JsonObject:
        obj: JsonObject = {
            "pattern_uid": self.pattern_uid,
            "rule_uid": self.rule_uid,
            "context_id": self.context_id,
            "length": self.length,
            "nocase": self.nocase,
            "offset": self.offset,
            "depth": self.depth,
            "pattern_type": self.pattern_type,
            "source_line": self.source_line,
            "metadata": self.metadata,
        }
        if include_bytes:
            obj["bytes_hex"] = bytes_to_hex(self.data)
        return obj


@dataclass(slots=True)
class AnchorCandidate:
    candidate_id: int
    pattern_uid: int
    rule_uid: int
    context_id: int
    anchor_offset: int
    data: bytes
    score: float = 0.0
    rarity: float = 0.0
    position_rarity: float = 0.0
    entropy: float = 0.0
    local_uniqueness: float = 0.0

    def to_json(self) -> JsonObject:
        return {
            "candidate_id": self.candidate_id,
            "pattern_uid": self.pattern_uid,
            "rule_uid": self.rule_uid,
            "context_id": self.context_id,
            "anchor_offset": self.anchor_offset,
            "bytes_hex": bytes_to_hex(self.data),
            "score": self.score,
            "rarity": self.rarity,
            "position_rarity": self.position_rarity,
            "entropy": self.entropy,
            "local_uniqueness": self.local_uniqueness,
        }


@dataclass(slots=True)
class SelectedAnchor:
    anchor_id: int
    candidate: AnchorCandidate
    select_reason: str = "best_score"

    def to_json(self) -> JsonObject:
        obj = self.candidate.to_json()
        obj["anchor_id"] = self.anchor_id
        obj["select_reason"] = self.select_reason
        return obj


@dataclass(slots=True)
class RulesetIR:
    sources: list[RuleSource] = field(default_factory=empty_rule_sources)
    contexts: list[MatchContext] = field(default_factory=empty_match_contexts)
    rules: list[Rule] = field(default_factory=empty_rules)
    patterns: list[LiteralPattern] = field(default_factory=empty_literal_patterns)
    selected_anchors: list[SelectedAnchor] = field(
        default_factory=empty_selected_anchors
    )

    def to_json(self, include_pattern_bytes: bool = True) -> JsonObject:
        return {
            "format": "heimdall-ruleset-ir",
            "version": 1,
            "sources": [source.to_json() for source in self.sources],
            "contexts": [context.to_json() for context in self.contexts],
            "rules": [rule.to_json() for rule in self.rules],
            "patterns": [
                pattern.to_json(include_bytes=include_pattern_bytes)
                for pattern in self.patterns
            ],
            "selected_anchors": [anchor.to_json() for anchor in self.selected_anchors],
        }

    def next_source_id(self) -> int:
        return len(self.sources) + 1

    def next_context_id(self) -> int:
        return len(self.contexts) + 1

    def next_rule_uid(self) -> int:
        return len(self.rules) + 1

    def next_pattern_uid(self) -> int:
        return len(self.patterns) + 1
