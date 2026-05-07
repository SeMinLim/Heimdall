import unittest

from ruleset_compiler.parsers.ips_workbook import (
    IPSWorkbookSchema,
    decode_pattern,
    parse_ips_rows,
)


class IPSWorkbookParserTest(unittest.TestCase):
    def test_decode_bin_pattern(self):
        self.assertEqual(decode_pattern("%41%42 43", "BIN"), b"ABC")

    def test_parse_rows_to_ir(self):
        schema = IPSWorkbookSchema()
        rows = [
            [
                schema.code_column,
                schema.name_column,
                schema.protocol_column,
                schema.port_column,
                schema.pattern_type_column,
                schema.pattern_column,
                schema.offset_column,
                schema.offset_cmp_column,
                schema.case_sensitive_column,
                schema.priority_column,
            ],
            [
                "R-1",
                "Example attack",
                "TCP",
                "80",
                "TEXT",
                "AbCdEfGh",
                "4",
                "eq",
                "N",
                "high",
            ],
            [
                "R-2",
                "Binary attack",
                "UDP",
                "53",
                "BIN",
                "%de%ad%be%ef",
                "",
                "",
                "Y",
                "medium",
            ],
        ]

        ir = parse_ips_rows(rows, source_uri="unit.xlsx")

        self.assertEqual(len(ir.sources), 1)
        self.assertEqual(len(ir.contexts), 1)
        self.assertEqual(len(ir.rules), 2)
        self.assertEqual(len(ir.patterns), 2)
        self.assertEqual(ir.rules[0].native_id, "R-1")
        self.assertEqual(ir.patterns[0].data, b"AbCdEfGh")
        self.assertTrue(ir.patterns[0].nocase)
        self.assertEqual(ir.patterns[0].normalized_data(), b"abcdefgh")
        self.assertEqual(ir.patterns[0].offset, 4)
        self.assertEqual(ir.patterns[1].data, bytes.fromhex("deadbeef"))
        self.assertFalse(ir.patterns[1].nocase)


if __name__ == "__main__":
    unittest.main()
