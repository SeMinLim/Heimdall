from pathlib import Path

from pfbench.experiment import run_experiment, ExperimentConfig


def test_smoke_synthetic(tmp_path):
    """End-to-end smoke test: synthetic rules + synthetic packets → metrics."""
    # Create a fixture hex-list
    rules_file = tmp_path / "rules.txt"
    lines = []
    for i in range(10):
        offset = i % 57
        pattern_hex = f"{i:02x}" * 8
        lines.append(f"{offset} {pattern_hex}")
    rules_file.write_text("\n".join(lines))

    config = ExperimentConfig(
        hash_fn="crc32",
        reduce_fn="truncate",
        address_bits=19,
        rules_path=rules_file,
        rules_format="hex_list",
        packet_source="synthetic_uniform",
        packet_count=50,
        packet_seed=42,
        output_dir=tmp_path / "results",
    )

    result = run_experiment(config)

    # Check that metrics are present
    assert "fill_rate" in result
    assert "rule_collisions" in result
    assert "per_lane_fp_rates" in result
    assert "per_packet_fp_rate" in result
    assert isinstance(result["per_packet_fp_rate"], float)
    assert isinstance(result["fill_rate"], float)
    assert len(result["per_lane_fp_rates"]) == 57

    # Check output directory was created with plots
    output_dir = tmp_path / "results"
    assert output_dir.exists()
    assert any(output_dir.glob("*.png"))


def test_smoke_ascii_traffic(tmp_path):
    rules_file = tmp_path / "rules.txt"
    rules_file.write_text("0 DEADBEEFCAFEBABE\n5 0102030405060708\n")

    config = ExperimentConfig(
        hash_fn="crc32c",
        reduce_fn="xor_fold_overlap",
        address_bits=19,
        rules_path=rules_file,
        rules_format="hex_list",
        packet_source="synthetic_ascii",
        packet_count=20,
        packet_seed=123,
        output_dir=tmp_path / "results",
    )

    result = run_experiment(config)
    assert 0.0 <= result["per_packet_fp_rate"] <= 1.0
