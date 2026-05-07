import json
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

from ruleset_compiler.cli import compile_ir, main
from ruleset_compiler.ir import (
    LiteralPattern,
    MatchContext,
    Rule,
    RuleSource,
    RulesetIR,
)


class CliTest(unittest.TestCase):
    def test_compile_ir_writes_requested_outputs(self):
        ir = RulesetIR(
            sources=[RuleSource(1, "unit", "unit")],
            contexts=[MatchContext(1)],
            rules=[Rule(1, 1, "r1", "unit"), Rule(2, 1, "short", "unit")],
            patterns=[
                LiteralPattern(1, 1, 1, b"ABCDEFGH"),
                LiteralPattern(2, 2, 1, b"short"),
            ],
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            manifest_path = tmp / "manifest.json"
            hpat_path = tmp / "rules.hpat"
            result = compile_ir(
                ir,
                manifest_path=manifest_path,
                hpat_path=hpat_path,
            )

            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

        self.assertEqual(result.rules, 2)
        self.assertEqual(result.literal_patterns, 2)
        self.assertEqual(result.selected_anchors, 1)
        self.assertEqual(result.hpat_records, 1)
        self.assertEqual(manifest["summary"]["selected_anchors"], 1)
        self.assertEqual(manifest["compiler_options"]["window_size"], 8)

    def test_compile_ir_requires_an_output(self):
        with self.assertRaisesRegex(ValueError, "at least one output"):
            compile_ir(RulesetIR())

    def test_compile_snort_cli_writes_outputs(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            rules_path = tmp / "local.rules"
            manifest_path = tmp / "manifest.json"
            hpat_path = tmp / "rules.hpat"
            rules_path.write_text(
                'alert tcp any any -> any any (content:"ABCDEFGH"; '
                'content:"IJKLMNOP"; sid:1;)\n',
                encoding="utf-8",
            )

            stdout = StringIO()
            with redirect_stdout(stdout):
                exit_code = main(
                    [
                        "compile-snort",
                        str(rules_path),
                        "--manifest",
                        str(manifest_path),
                        "--hpat",
                        str(hpat_path),
                    ]
                )
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

        self.assertEqual(exit_code, 0)
        self.assertIn("compiled rules=1", stdout.getvalue())
        self.assertEqual(manifest["summary"]["rules"], 1)
        self.assertEqual(manifest["summary"]["literal_patterns"], 1)
        self.assertEqual(manifest["summary"]["selected_anchors"], 1)
        self.assertEqual(manifest["patterns"][0]["pattern_type"], "SNORT_RULE_ANCHOR")


if __name__ == "__main__":
    unittest.main()
