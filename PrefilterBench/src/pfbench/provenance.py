"""Provenance helpers: capture run environment so JSON output is self-describing."""

from __future__ import annotations

import platform
import subprocess
from datetime import datetime, timezone
from importlib.metadata import PackageNotFoundError, version
from typing import Any


def _git_sha() -> str | None:
    try:
        out = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
            timeout=2,
        )
        return out.stdout.strip()
    except (subprocess.SubprocessError, FileNotFoundError):
        return None


def _git_dirty() -> bool | None:
    try:
        out = subprocess.run(
            ["git", "status", "--porcelain"],
            check=True,
            capture_output=True,
            text=True,
            timeout=2,
        )
        return bool(out.stdout.strip())
    except (subprocess.SubprocessError, FileNotFoundError):
        return None


def _pkg_version() -> str | None:
    try:
        return version("pfbench")
    except PackageNotFoundError:
        return None


def provenance() -> dict[str, Any]:
    """Return a dict describing the current run environment."""
    return {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "git_sha": _git_sha(),
        "git_dirty": _git_dirty(),
        "pfbench_version": _pkg_version(),
        "python_version": platform.python_version(),
        "platform": platform.platform(),
    }
