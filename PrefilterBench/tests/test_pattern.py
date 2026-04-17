import json

import pytest

from pfbench.data.pattern import load_hex_list, load_json_export, RulePattern


class TestLoadHexList:
    def test_basic(self, tmp_path):
        f = tmp_path / "rules.txt"
        f.write_text("3 DEADBEEFCAFEBABE\n0 0102030405060708\n")
        patterns = load_hex_list(f)
        assert len(patterns) == 2
        assert patterns[0] == RulePattern(
            offset=3, pattern=bytes.fromhex("DEADBEEFCAFEBABE")
        )
        assert patterns[1] == RulePattern(
            offset=0, pattern=bytes.fromhex("0102030405060708")
        )

    def test_skips_blank_and_comments(self, tmp_path):
        f = tmp_path / "rules.txt"
        f.write_text("# comment\n\n3 DEADBEEFCAFEBABE\n  \n")
        patterns = load_hex_list(f)
        assert len(patterns) == 1

    def test_wrong_pattern_length(self, tmp_path):
        f = tmp_path / "rules.txt"
        f.write_text("0 DEADBEEF\n")  # 4 bytes, not 8
        with pytest.raises(ValueError, match="8 bytes"):
            load_hex_list(f)


class TestLoadJsonExport:
    def test_basic(self, tmp_path):
        data = [
            {"index": 0, "offset": 5, "pattern_hex": "DEADBEEFCAFEBABE"},
            {"index": 1, "offset": 10, "pattern_hex": "0102030405060708"},
        ]
        f = tmp_path / "rules.json"
        f.write_text(json.dumps(data))
        patterns = load_json_export(f)
        assert len(patterns) == 2
        assert patterns[0].offset == 5
        assert patterns[1].pattern == bytes.fromhex("0102030405060708")

    def test_missing_field(self, tmp_path):
        data = [{"index": 0, "offset": 5}]  # missing pattern_hex
        f = tmp_path / "rules.json"
        f.write_text(json.dumps(data))
        with pytest.raises(KeyError):
            load_json_export(f)
