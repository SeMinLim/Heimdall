"""Tests for pfbench.provenance."""

from pfbench.provenance import provenance


def test_provenance_structure():
    p = provenance()
    assert "timestamp_utc" in p
    assert "git_sha" in p
    assert "git_dirty" in p
    assert "pfbench_version" in p
    assert "python_version" in p
    assert "platform" in p


def test_timestamp_format():
    p = provenance()
    # ISO 8601 UTC with seconds precision
    assert "T" in p["timestamp_utc"]
    assert p["timestamp_utc"].endswith("+00:00")


def test_git_sha_shape():
    """In a git repo, git_sha should be a 40-char hex string or None."""
    p = provenance()
    if p["git_sha"] is not None:
        assert len(p["git_sha"]) == 40
        assert all(c in "0123456789abcdef" for c in p["git_sha"])
