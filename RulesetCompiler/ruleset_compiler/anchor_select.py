"""Anchor selection for Heimdall prefilter inputs."""

from __future__ import annotations

import heapq
from collections import Counter
from dataclasses import dataclass
from math import log2
from typing import Sequence

from ruleset_compiler.ir import (
    AnchorCandidate,
    LiteralPattern,
    RulesetIR,
    SelectedAnchor,
)


BytesLike = bytes | bytearray | memoryview


@dataclass(frozen=True, slots=True)
class ScoreWeights:
    rarity: float = 0.45
    position_rarity: float = 0.25
    entropy: float = 0.20
    local_uniqueness: float = 0.10


@dataclass(frozen=True, slots=True)
class CandidateScore:
    offset: int
    pattern: bytes
    score: float
    rarity: float
    position_rarity: float
    entropy: float
    local_uniqueness: float


@dataclass(frozen=True, slots=True)
class RepresentativePattern:
    record_index: int
    offset: int
    pattern: bytes
    score: float
    candidate_scores: tuple[CandidateScore, ...]


@dataclass(frozen=True, slots=True)
class CorpusStats:
    total_records: int
    record_size: int
    window_size: int
    allow_overlap: bool
    document_frequency: Counter[bytes]
    positional_document_frequency: Counter[tuple[int, bytes]]


@dataclass(frozen=True, slots=True)
class _AnchorInput:
    pattern: LiteralPattern
    record: bytes
    pattern_len: int


def normalize_record(record: BytesLike | str) -> bytes:
    if isinstance(record, str):
        return record.encode("latin-1")
    return bytes(record)


def candidate_offsets(
    record_size: int, window_size: int, allow_overlap: bool = True
) -> tuple[int, ...]:
    if window_size <= 0:
        raise ValueError("window_size must be positive")
    if record_size < window_size:
        return ()

    stride = 1 if allow_overlap else window_size
    return tuple(range(0, record_size - window_size + 1, stride))


def build_corpus_stats(
    records: Sequence[BytesLike | str],
    record_size: int = 64,
    window_size: int = 8,
    allow_overlap: bool = True,
    pattern_lens: Sequence[int] | None = None,
) -> CorpusStats:
    normalized_records = [normalize_record(record) for record in records]
    if pattern_lens is None:
        valid_lens = [len(record) for record in normalized_records]
    else:
        valid_lens = list(pattern_lens)

    document_frequency: Counter[bytes] = Counter()
    positional_document_frequency: Counter[tuple[int, bytes]] = Counter()

    for record, valid_len in zip(normalized_records, valid_lens):
        _validate_record(record, record_size, valid_len, window_size)
        offsets = candidate_offsets(
            record_size=valid_len,
            window_size=window_size,
            allow_overlap=allow_overlap,
        )
        seen_patterns: set[bytes] = set()
        seen_position_patterns: set[tuple[int, bytes]] = set()
        for offset in offsets:
            pattern = record[offset : offset + window_size]
            seen_patterns.add(pattern)
            seen_position_patterns.add((offset, pattern))

        document_frequency.update(seen_patterns)
        positional_document_frequency.update(seen_position_patterns)

    return CorpusStats(
        total_records=len(normalized_records),
        record_size=record_size,
        window_size=window_size,
        allow_overlap=allow_overlap,
        document_frequency=document_frequency,
        positional_document_frequency=positional_document_frequency,
    )


def score_record(
    record: BytesLike | str,
    stats: CorpusStats,
    weights: ScoreWeights | None = None,
    pattern_len: int | None = None,
) -> tuple[CandidateScore, ...]:
    normalized_record = normalize_record(record)
    valid_len = pattern_len if pattern_len is not None else len(normalized_record)
    _validate_record(normalized_record, stats.record_size, valid_len, stats.window_size)
    weights = weights or ScoreWeights()

    offsets = candidate_offsets(
        record_size=valid_len,
        window_size=stats.window_size,
        allow_overlap=stats.allow_overlap,
    )
    if not offsets:
        return ()

    patterns = [
        (offset, normalized_record[offset : offset + stats.window_size])
        for offset in offsets
    ]
    local_counts = Counter(pattern for _, pattern in patterns)

    return tuple(
        _score_candidate(
            offset=offset,
            pattern=pattern,
            total_records=stats.total_records,
            document_frequency=stats.document_frequency[pattern],
            positional_document_frequency=stats.positional_document_frequency[
                (offset, pattern)
            ],
            local_count=local_counts[pattern],
            weights=weights,
        )
        for offset, pattern in patterns
    )


def select_representative_patterns(
    records: Sequence[BytesLike | str],
    record_size: int = 64,
    window_size: int = 8,
    allow_overlap: bool = True,
    weights: ScoreWeights | None = None,
    deduplicate: bool = True,
    pattern_lens: Sequence[int] | None = None,
) -> list[RepresentativePattern]:
    stats = build_corpus_stats(
        records=records,
        record_size=record_size,
        window_size=window_size,
        allow_overlap=allow_overlap,
        pattern_lens=pattern_lens,
    )
    weights = weights or ScoreWeights()

    resolved_lens = (
        list(pattern_lens)
        if pattern_lens is not None
        else [len(normalize_record(record)) for record in records]
    )

    all_candidate_scores: list[tuple[CandidateScore, ...]] = []
    for record, pattern_len in zip(records, resolved_lens):
        all_candidate_scores.append(
            score_record(
                record=record,
                stats=stats,
                weights=weights,
                pattern_len=pattern_len,
            )
        )

    if deduplicate:
        return _greedy_deduplicate(all_candidate_scores)

    representatives: list[RepresentativePattern] = []
    for record_index, candidate_scores in enumerate(all_candidate_scores):
        best = _pick_best_candidate(candidate_scores)
        representatives.append(
            RepresentativePattern(
                record_index=record_index,
                offset=best.offset,
                pattern=best.pattern,
                score=best.score,
                candidate_scores=candidate_scores,
            )
        )
    return representatives


def select_anchors(
    ir: RulesetIR,
    *,
    record_size: int = 64,
    window_size: int = 8,
    allow_overlap: bool = True,
    deduplicate: bool = True,
    weights: ScoreWeights = ScoreWeights(),
) -> list[SelectedAnchor]:
    anchor_inputs = _build_anchor_inputs(
        ir.patterns,
        record_size=record_size,
        window_size=window_size,
    )
    if not anchor_inputs:
        ir.selected_anchors = []
        return []

    representatives = select_representative_patterns(
        [item.record for item in anchor_inputs],
        record_size=record_size,
        window_size=window_size,
        allow_overlap=allow_overlap,
        weights=weights,
        deduplicate=deduplicate,
        pattern_lens=[item.pattern_len for item in anchor_inputs],
    )

    selected: list[SelectedAnchor] = []
    for anchor_id, representative in enumerate(representatives, start=1):
        literal = anchor_inputs[representative.record_index].pattern
        candidate = AnchorCandidate(
            candidate_id=anchor_id,
            pattern_uid=literal.pattern_uid,
            rule_uid=literal.rule_uid,
            context_id=literal.context_id,
            anchor_offset=representative.offset,
            data=representative.pattern,
            score=representative.score,
            rarity=_candidate_metric(representative, "rarity"),
            position_rarity=_candidate_metric(representative, "position_rarity"),
            entropy=_candidate_metric(representative, "entropy"),
            local_uniqueness=_candidate_metric(representative, "local_uniqueness"),
        )
        selected.append(
            SelectedAnchor(
                anchor_id=anchor_id,
                candidate=candidate,
                select_reason="reference_deduplicate" if deduplicate else "best_score",
            )
        )

    ir.selected_anchors = selected
    return selected


def _build_anchor_inputs(
    patterns: Sequence[LiteralPattern], *, record_size: int, window_size: int
) -> list[_AnchorInput]:
    items: list[_AnchorInput] = []
    for pattern in patterns:
        data = pattern.data
        if len(data) > record_size:
            items.append(
                _AnchorInput(
                    pattern=pattern,
                    record=data[:record_size],
                    pattern_len=record_size,
                )
            )
        elif len(data) >= window_size:
            items.append(
                _AnchorInput(
                    pattern=pattern,
                    record=data.ljust(record_size, b"\x00"),
                    pattern_len=len(data),
                )
            )
    return items


def _candidate_metric(representative: RepresentativePattern, field_name: str) -> float:
    for candidate in representative.candidate_scores:
        if (
            candidate.offset == representative.offset
            and candidate.pattern == representative.pattern
        ):
            return float(getattr(candidate, field_name))
    return 0.0


def _candidate_sort_key(
    candidate: CandidateScore,
) -> tuple[float, float, float, float, int]:
    return (
        candidate.score,
        candidate.rarity,
        candidate.position_rarity,
        candidate.entropy,
        -candidate.offset,
    )


def _pick_best_candidate(candidates: tuple[CandidateScore, ...]) -> CandidateScore:
    return max(candidates, key=_candidate_sort_key)


def _greedy_deduplicate(
    all_candidate_scores: list[tuple[CandidateScore, ...]],
) -> list[RepresentativePattern]:
    total = len(all_candidate_scores)
    sorted_candidates = [
        sorted(candidates, key=_candidate_sort_key, reverse=True)
        for candidates in all_candidate_scores
    ]

    heap: list[tuple[float, int, int]] = []
    for record_index, candidates in enumerate(sorted_candidates):
        if candidates:
            heapq.heappush(heap, (-candidates[0].score, record_index, 0))

    assigned: dict[int, CandidateScore] = {}
    taken_patterns: set[bytes] = set()

    while heap and len(assigned) < total:
        _neg_score, record_index, rank = heapq.heappop(heap)
        if record_index in assigned:
            continue

        candidate = sorted_candidates[record_index][rank]
        if candidate.pattern not in taken_patterns:
            assigned[record_index] = candidate
            taken_patterns.add(candidate.pattern)
            continue

        next_rank = rank + 1
        if next_rank < len(sorted_candidates[record_index]):
            next_candidate = sorted_candidates[record_index][next_rank]
            heapq.heappush(heap, (-next_candidate.score, record_index, next_rank))
        else:
            assigned[record_index] = sorted_candidates[record_index][0]

    results: list[RepresentativePattern] = []
    for record_index in range(total):
        best = assigned.get(record_index, sorted_candidates[record_index][0])
        results.append(
            RepresentativePattern(
                record_index=record_index,
                offset=best.offset,
                pattern=best.pattern,
                score=best.score,
                candidate_scores=all_candidate_scores[record_index],
            )
        )
    return results


def _score_candidate(
    *,
    offset: int,
    pattern: bytes,
    total_records: int,
    document_frequency: int,
    positional_document_frequency: int,
    local_count: int,
    weights: ScoreWeights,
) -> CandidateScore:
    rarity = _normalized_inverse_document_frequency(document_frequency, total_records)
    position_rarity = _normalized_inverse_document_frequency(
        positional_document_frequency, total_records
    )
    entropy = _normalized_entropy(pattern)
    local_uniqueness = 1.0 / local_count

    score = (
        weights.rarity * rarity
        + weights.position_rarity * position_rarity
        + weights.entropy * entropy
        + weights.local_uniqueness * local_uniqueness
    )

    return CandidateScore(
        offset=offset,
        pattern=pattern,
        score=score,
        rarity=rarity,
        position_rarity=position_rarity,
        entropy=entropy,
        local_uniqueness=local_uniqueness,
    )


def _normalized_inverse_document_frequency(
    document_frequency: int, total_records: int
) -> float:
    if total_records <= 1:
        return 1.0

    raw_idf = log2((total_records + 1) / (document_frequency + 1))
    max_idf = log2(total_records + 1)
    return raw_idf / max_idf if max_idf else 0.0


def _normalized_entropy(pattern: bytes) -> float:
    if len(pattern) <= 1:
        return 0.0

    counts = Counter(pattern)
    entropy = 0.0
    pattern_length = len(pattern)
    for count in counts.values():
        probability = count / pattern_length
        entropy -= probability * log2(probability)

    return entropy / log2(pattern_length)


def _validate_record(
    record: bytes, slot_size: int, valid_len: int, window_size: int
) -> None:
    if len(record) != slot_size:
        raise ValueError(f"record length must be {slot_size} bytes, got {len(record)}")
    if valid_len < 0 or valid_len > slot_size:
        raise ValueError(f"pattern_len must be 0..{slot_size}, got {valid_len}")
    if valid_len > 0 and valid_len < window_size:
        raise ValueError(
            f"pattern_len ({valid_len}) must be >= window_size ({window_size}) "
            f"or 0 (skip)"
        )


__all__ = [
    "CandidateScore",
    "CorpusStats",
    "RepresentativePattern",
    "ScoreWeights",
    "build_corpus_stats",
    "candidate_offsets",
    "normalize_record",
    "score_record",
    "select_anchors",
    "select_representative_patterns",
]
