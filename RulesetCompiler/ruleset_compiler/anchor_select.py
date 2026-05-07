"""Anchor selection for Heimdall prefilter inputs."""

from __future__ import annotations

import heapq
import math
from collections import Counter, defaultdict
from dataclasses import dataclass

from ruleset_compiler.ir import AnchorCandidate, RulesetIR, SelectedAnchor


@dataclass(frozen=True, slots=True)
class ScoreWeights:
    rarity: float = 0.45
    position_rarity: float = 0.25
    entropy: float = 0.20
    local_uniqueness: float = 0.10


def select_anchors(
    ir: RulesetIR,
    *,
    window_size: int = 8,
    allow_overlap: bool = True,
    deduplicate: bool = True,
    weights: ScoreWeights = ScoreWeights(),
) -> list[SelectedAnchor]:
    """Select one representative anchor per eligible literal pattern.

    The scoring model follows the reference heimdall-pattern-extractor:
    rarity, positional rarity, entropy, and local uniqueness are combined, then
    a max-heap assigns globally high-scoring anchors first. Deduplication is
    scoped by match context because the same bytes in different buffers do not
    mean the same thing to the hardware pipeline.
    """
    if window_size <= 0:
        raise ValueError("window_size must be positive")

    offsets_by_pattern: dict[int, list[int]] = {}
    pattern_windows: dict[int, list[tuple[int, bytes]]] = {}
    document_frequency: Counter[tuple[int, bytes]] = Counter()
    positional_document_frequency: Counter[tuple[int, int, bytes]] = Counter()
    total_patterns_by_context: Counter[int] = Counter()

    for pattern in ir.patterns:
        data = pattern.normalized_data()
        offsets = _candidate_offsets(len(data), window_size, allow_overlap)
        offsets_by_pattern[pattern.pattern_uid] = offsets
        windows = [(offset, data[offset : offset + window_size]) for offset in offsets]
        pattern_windows[pattern.pattern_uid] = windows
        if offsets:
            total_patterns_by_context[pattern.context_id] += 1

        seen_windows = {(pattern.context_id, window) for _, window in windows}
        seen_pos_windows = {
            (pattern.context_id, offset, window) for offset, window in windows
        }
        document_frequency.update(seen_windows)
        positional_document_frequency.update(seen_pos_windows)

    candidates_by_pattern: dict[int, list[AnchorCandidate]] = defaultdict(list)
    candidate_id = 1

    for pattern in ir.patterns:
        windows = pattern_windows[pattern.pattern_uid]
        local_counts = Counter(window for _, window in windows)
        total_patterns = total_patterns_by_context[pattern.context_id]
        for offset, window in windows:
            rarity = _normalized_idf(
                document_frequency[(pattern.context_id, window)], total_patterns
            )
            position_rarity = _normalized_idf(
                positional_document_frequency[(pattern.context_id, offset, window)],
                total_patterns,
            )
            entropy = _normalized_entropy(window)
            local_uniqueness = 1.0 / local_counts[window]
            score = (
                weights.rarity * rarity
                + weights.position_rarity * position_rarity
                + weights.entropy * entropy
                + weights.local_uniqueness * local_uniqueness
            )

            candidates_by_pattern[pattern.pattern_uid].append(
                AnchorCandidate(
                    candidate_id=candidate_id,
                    pattern_uid=pattern.pattern_uid,
                    rule_uid=pattern.rule_uid,
                    context_id=pattern.context_id,
                    anchor_offset=offset,
                    data=window,
                    score=score,
                    rarity=rarity,
                    position_rarity=position_rarity,
                    entropy=entropy,
                    local_uniqueness=local_uniqueness,
                )
            )
            candidate_id += 1

    eligible_pattern_ids = [
        pattern.pattern_uid
        for pattern in ir.patterns
        if candidates_by_pattern[pattern.pattern_uid]
    ]
    sorted_candidates = {
        pattern_uid: sorted(
            candidates_by_pattern[pattern_uid], key=_candidate_sort_key, reverse=True
        )
        for pattern_uid in eligible_pattern_ids
    }

    if deduplicate:
        chosen_by_pattern = _greedy_deduplicate(sorted_candidates)
    else:
        chosen_by_pattern = {
            pattern_uid: (candidates[0], "best_score")
            for pattern_uid, candidates in sorted_candidates.items()
        }

    selected: list[SelectedAnchor] = []
    anchor_id = 1
    for pattern in ir.patterns:
        choice = chosen_by_pattern.get(pattern.pattern_uid)
        if choice is None:
            continue
        chosen, reason = choice
        selected.append(
            SelectedAnchor(anchor_id=anchor_id, candidate=chosen, select_reason=reason)
        )
        anchor_id += 1

    ir.selected_anchors = selected
    return selected


def _candidate_offsets(length: int, window_size: int, allow_overlap: bool) -> list[int]:
    if length < window_size:
        return []
    stride = 1 if allow_overlap else window_size
    return list(range(0, length - window_size + 1, stride))


def _greedy_deduplicate(
    sorted_candidates: dict[int, list[AnchorCandidate]],
) -> dict[int, tuple[AnchorCandidate, str]]:
    heap: list[tuple[float, int, int]] = []
    pattern_ids = list(sorted_candidates)
    for pattern_uid in pattern_ids:
        candidates = sorted_candidates[pattern_uid]
        if candidates:
            heapq.heappush(heap, (-candidates[0].score, pattern_uid, 0))

    assigned: dict[int, tuple[AnchorCandidate, str]] = {}
    taken: set[tuple[int, bytes]] = set()

    while heap and len(assigned) < len(pattern_ids):
        _neg_score, pattern_uid, rank = heapq.heappop(heap)
        if pattern_uid in assigned:
            continue

        candidate = sorted_candidates[pattern_uid][rank]
        key = (candidate.context_id, candidate.data)
        if key not in taken:
            assigned[pattern_uid] = (candidate, "best_unique_score")
            taken.add(key)
            continue

        next_rank = rank + 1
        if next_rank < len(sorted_candidates[pattern_uid]):
            next_candidate = sorted_candidates[pattern_uid][next_rank]
            heapq.heappush(heap, (-next_candidate.score, pattern_uid, next_rank))
        else:
            assigned[pattern_uid] = (
                sorted_candidates[pattern_uid][0],
                "fallback_duplicate",
            )

    for pattern_uid in pattern_ids:
        assigned.setdefault(
            pattern_uid, (sorted_candidates[pattern_uid][0], "fallback_duplicate")
        )

    return assigned


def _normalized_idf(document_count: int, total_documents: int) -> float:
    if total_documents <= 1:
        return 1.0
    raw_idf = math.log2((total_documents + 1.0) / (document_count + 1.0))
    max_idf = math.log2(total_documents + 1.0)
    return raw_idf / max_idf if max_idf > 0 else 0.0


def _normalized_entropy(data: bytes) -> float:
    if len(data) <= 1:
        return 0.0
    counts = Counter(data)
    entropy = 0.0
    for count in counts.values():
        probability = count / len(data)
        entropy -= probability * math.log2(probability)
    return entropy / math.log2(len(data))


def _candidate_sort_key(
    candidate: AnchorCandidate,
) -> tuple[float, float, float, float, int]:
    return (
        candidate.score,
        candidate.rarity,
        candidate.position_rarity,
        candidate.entropy,
        -candidate.anchor_offset,
    )
