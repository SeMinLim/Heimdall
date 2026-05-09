"""Ruleset compiler utilities for Heimdall prefilter inputs."""

from .ir import (
    AnchorCandidate,
    LiteralPattern,
    MatchContext,
    Rule,
    RuleSource,
    RulesetIR,
    SelectedAnchor,
)
from .anchor_select import (
    CandidateScore,
    CorpusStats,
    RepresentativePattern,
    ScoreWeights,
    build_corpus_stats,
    candidate_offsets,
    normalize_record,
    score_record,
    select_anchors,
    select_representative_patterns,
)
from .emit_hpat import write_hpat
from .emit_manifest import write_manifest

__all__ = [
    "AnchorCandidate",
    "CandidateScore",
    "CorpusStats",
    "LiteralPattern",
    "MatchContext",
    "RepresentativePattern",
    "Rule",
    "RuleSource",
    "RulesetIR",
    "ScoreWeights",
    "SelectedAnchor",
    "build_corpus_stats",
    "candidate_offsets",
    "normalize_record",
    "score_record",
    "select_anchors",
    "select_representative_patterns",
    "write_hpat",
    "write_manifest",
]
