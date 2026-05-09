import unittest

from ruleset_compiler.anchor_select import (
    candidate_offsets,
    select_anchors,
    select_representative_patterns,
)
from ruleset_compiler.ir import (
    LiteralPattern,
    MatchContext,
    Rule,
    RuleSource,
    RulesetIR,
)


class AnchorSelectTest(unittest.TestCase):
    def test_overlapping_offsets_match_reference(self):
        self.assertEqual(
            candidate_offsets(record_size=64, window_size=8), tuple(range(57))
        )

    def test_selects_one_anchor_per_long_pattern(self):
        ir = RulesetIR(
            sources=[RuleSource(1, "unit", "unit")],
            contexts=[MatchContext(1)],
            rules=[
                Rule(1, 1, "r1", "unit"),
                Rule(2, 1, "r2", "unit"),
                Rule(3, 1, "short", "unit"),
            ],
            patterns=[
                LiteralPattern(1, 1, 1, b"COMMON00SIGA0001"),
                LiteralPattern(2, 2, 1, b"COMMON00SIGB0002"),
                LiteralPattern(3, 3, 1, b"short"),
            ],
        )

        selected = select_anchors(ir, window_size=8)

        self.assertEqual(len(selected), 2)
        self.assertEqual([anchor.anchor_id for anchor in selected], [1, 2])
        self.assertEqual({anchor.candidate.rule_uid for anchor in selected}, {1, 2})
        self.assertEqual(len({anchor.candidate.data for anchor in selected}), 2)
        self.assertIs(ir.selected_anchors, selected)

    def test_prefers_distinctive_tail_over_shared_prefix(self):
        shared = b"COMMON00"
        ir = _ir_from_patterns(
            [
                shared * 7 + b"SIGA0001",
                shared * 7 + b"SIGB0002",
                shared * 7 + b"SIGC0003",
                shared * 7 + b"SIGD0004",
            ]
        )

        selected = select_anchors(ir, window_size=8)

        self.assertEqual(len(selected), 4)
        self.assertEqual(len({anchor.candidate.data for anchor in selected}), 4)
        for anchor in selected:
            self.assertGreaterEqual(anchor.candidate.anchor_offset, 48)

    def test_identical_patterns_fallback_gracefully(self):
        ir = _ir_from_patterns([b"A" * 64, b"A" * 64])

        selected = select_anchors(ir, window_size=8)

        self.assertEqual(len(selected), 2)
        self.assertEqual(selected[0].candidate.data, selected[1].candidate.data)

    def test_ir_adapter_matches_reference_records(self):
        patterns = [
            b"ATTACK_A" + b"PAYLOAD1",
            b"ATTACK_B" + b"PAYLOAD2" + b"EXTRA123",
            b"ATTACK_C" * 8,
        ]
        ir = _ir_from_patterns(patterns)
        records = [
            patterns[0].ljust(64, b"\x00"),
            patterns[1].ljust(64, b"\x00"),
            patterns[2],
        ]
        pattern_lens = [16, 24, 64]

        expected = select_representative_patterns(
            records,
            record_size=64,
            window_size=8,
            pattern_lens=pattern_lens,
        )
        selected = select_anchors(ir, record_size=64, window_size=8)

        self.assertEqual(
            [
                (anchor.candidate.anchor_offset, anchor.candidate.data)
                for anchor in selected
            ],
            [(result.offset, result.pattern) for result in expected],
        )

    def test_selector_does_not_scope_dedup_by_context(self):
        ir = RulesetIR(
            sources=[RuleSource(1, "unit", "unit")],
            contexts=[
                MatchContext(1, buffer_kind="payload"),
                MatchContext(2, buffer_kind="uri"),
            ],
            rules=[Rule(1, 1, "r1", "unit"), Rule(2, 1, "r2", "unit")],
            patterns=[
                LiteralPattern(1, 1, 1, b"SAMEBYTE"),
                LiteralPattern(2, 2, 2, b"SAMEBYTE"),
            ],
        )

        selected = select_anchors(ir, window_size=8)

        self.assertEqual(len(selected), 2)
        self.assertEqual(selected[0].candidate.data, selected[1].candidate.data)


def _ir_from_patterns(patterns: list[bytes]) -> RulesetIR:
    return RulesetIR(
        sources=[RuleSource(1, "unit", "unit")],
        contexts=[MatchContext(1)],
        rules=[
            Rule(index + 1, 1, f"r{index + 1}", "unit")
            for index in range(len(patterns))
        ],
        patterns=[
            LiteralPattern(index + 1, index + 1, 1, pattern)
            for index, pattern in enumerate(patterns)
        ],
    )


if __name__ == "__main__":
    unittest.main()
