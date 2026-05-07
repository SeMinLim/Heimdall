import tempfile
import unittest
from pathlib import Path

from ruleset_compiler.parsers.snort import (
    normalize_content,
    parse_snort_rules,
    parse_snort_statements,
    tokenize_body,
)


class SnortParserTest(unittest.TestCase):
    def test_normalize_content_decodes_hex_blocks_and_escapes(self):
        self.assertEqual(normalize_content(r"GET|20 2f|admin\"x"), b'GET /admin"x')

    def test_tokenize_body_keeps_semicolons_inside_quotes(self):
        tokens = tokenize_body('msg:"a;b"; content:"abc;def"; nocase;')

        self.assertEqual(tokens, ['msg:"a;b"', 'content:"abc;def"', "nocase"])

    def test_parse_statement_extracts_positive_content_metadata(self):
        ir = parse_snort_statements(
            [
                'alert tcp any any -> any any (msg:"demo"; service:http; '
                'http_uri; content:"/admin|2f|panel",fast_pattern; nocase; '
                'offset:0; depth:12; content:!"skipme"; http_header; '
                'content:"User-Agent|3a|"; pcre:"/demo/"; sid:1001; rev:2;)'
            ]
        )

        self.assertEqual(len(ir.sources), 1)
        self.assertEqual(len(ir.rules), 1)
        self.assertEqual(ir.rules[0].native_id, "1:1001:2")
        self.assertTrue(ir.rules[0].metadata["has_pcre"])
        self.assertEqual(ir.rules[0].metadata["content_count"], 3)
        self.assertEqual(ir.rules[0].metadata["positive_content_count"], 2)
        self.assertEqual(ir.rules[0].metadata["negated_content_count"], 1)

        self.assertEqual(len(ir.patterns), 2)
        self.assertEqual(ir.patterns[0].data, b"/admin/panel")
        self.assertTrue(ir.patterns[0].nocase)
        self.assertEqual(ir.patterns[0].offset, 0)
        self.assertEqual(ir.patterns[0].depth, 12)
        self.assertTrue(ir.patterns[0].metadata["fast_pattern"])
        self.assertEqual(ir.contexts[0].buffer_kind, "http_uri")

        self.assertEqual(ir.patterns[1].data, b"User-Agent:")
        self.assertEqual(ir.contexts[1].buffer_kind, "http_header")

    def test_parse_statement_can_include_negated_content(self):
        ir = parse_snort_statements(
            ['alert tcp any any -> any any (content:!"ABCDEFGH"; sid:7;)'],
            include_negated=True,
        )

        self.assertEqual(len(ir.patterns), 1)
        self.assertTrue(ir.patterns[0].metadata["negated"])

    def test_parse_rules_reads_snapshot_directories(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            rules_dir = root / "rules"
            rules_dir.mkdir()
            (rules_dir / "local.rules").write_text(
                'alert udp any any -> any any (dns_query; content:"example.com"; sid:9;)\n',
                encoding="utf-8",
            )

            ir = parse_snort_rules(root)

        self.assertEqual(len(ir.sources), 1)
        self.assertEqual(len(ir.rules), 1)
        self.assertEqual(len(ir.patterns), 1)
        self.assertEqual(ir.contexts[0].protocol, "udp")
        self.assertEqual(ir.contexts[0].buffer_kind, "dns_query")


if __name__ == "__main__":
    unittest.main()
