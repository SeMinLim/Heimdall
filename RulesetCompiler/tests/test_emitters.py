import json
import tempfile
import unittest
from pathlib import Path

from ruleset_compiler.anchor_select import select_anchors
from ruleset_compiler.emit_hpat import read_hpat_header, write_hpat
from ruleset_compiler.emit_manifest import write_manifest
from ruleset_compiler.ir import (
    LiteralPattern,
    MatchContext,
    Rule,
    RuleSource,
    RulesetIR,
)


class EmitterTest(unittest.TestCase):
    def test_write_hpat_and_manifest(self):
        ir = RulesetIR(
            sources=[RuleSource(1, "unit", "unit")],
            contexts=[MatchContext(1)],
            rules=[Rule(1, 1, "r1", "unit")],
            patterns=[LiteralPattern(1, 1, 1, b"AbCdEfGh", nocase=True)],
        )
        select_anchors(ir, window_size=8)

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            hpat_path = tmp / "rules.hpat"
            manifest_path = tmp / "manifest.json"

            written = write_hpat(ir, hpat_path, record_size=64, window_size=8)
            write_manifest(ir, manifest_path, compiler_options={"window_size": 8})

            self.assertEqual(written, 1)
            header = read_hpat_header(hpat_path)
            self.assertEqual(header["magic"], b"HPAT")
            self.assertEqual(header["version"], 1)
            self.assertEqual(header["record_size"], 64)
            self.assertEqual(header["window_size"], 8)
            self.assertEqual(header["num_records"], 1)

            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            self.assertEqual(manifest["summary"]["selected_anchors"], 1)
            self.assertEqual(
                manifest["selected_anchors"][0]["bytes_hex"], "4162436445664768"
            )


if __name__ == "__main__":
    unittest.main()
