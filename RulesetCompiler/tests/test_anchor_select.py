import unittest

from ruleset_compiler.anchor_select import select_anchors
from ruleset_compiler.ir import (
    LiteralPattern,
    MatchContext,
    Rule,
    RuleSource,
    RulesetIR,
)


class AnchorSelectTest(unittest.TestCase):
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
        self.assertEqual(selected[1].select_reason, "fallback_duplicate")

    def test_same_anchor_bytes_in_different_contexts_are_distinct(self):
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
        self.assertEqual(
            [anchor.select_reason for anchor in selected],
            ["best_unique_score", "best_unique_score"],
        )


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
