"""Behavioral tests for release-time Quick Guide version updates."""

# Test assertions and the controlled subprocess are intentional: the updater
# operates only on a copied guide below pytest's temporary directory.
# ruff: noqa: S101, S603

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


import pytest


pytestmark = pytest.mark.unit
V2_DIR = Path(__file__).parents[1]
SCRIPT_PATH = V2_DIR / "scripts" / "update_quick_guide_versions.py"
QUICK_GUIDE_PATH = V2_DIR / "doc" / "quick-guide.md"


def run_updater(
    guide_path: Path,
    version: str,
) -> subprocess.CompletedProcess[str]:
    """Run the release updater against an isolated Quick Guide copy.

    Args:
        guide_path: Temporary Quick Guide path to update.
        version: Stable version passed to the updater.

    Returns:
        Completed updater process without automatic status checking.

    Raises:
        OSError: If Python cannot start the updater.
    """
    return subprocess.run(
        [
            sys.executable,
            str(SCRIPT_PATH),
            "--path",
            str(guide_path),
            "--version",
            version,
        ],
        check=False,
        capture_output=True,
        text=True,
    )


def test_update_quick_guide_versions_real_guide_updates_application_only(
    tmp_path: Path,
) -> None:
    """The real guide updates all application versions and preserves dependencies."""
    guide_path = tmp_path / "quick-guide.md"
    original = QUICK_GUIDE_PATH.read_text(encoding="utf-8")
    guide_path.write_text(original, encoding="utf-8")

    result = run_updater(guide_path, "9.8.7")

    assert result.returncode == 0, result.stderr
    updated = guide_path.read_text(encoding="utf-8")
    assert "Updated 4 validated Quick Guide version reference(s)" in result.stderr
    assert updated.count("dar-backup-9.8.7") == 1
    assert updated.count("manager:                   9.8.7") == 1
    assert updated.count("dar-backup:               9.8.7") == 2
    assert "argcomplete-3.6.2" in updated
    assert "dar version:              2.7.21" in updated
    assert "markdown-it-py-3.0.0" in updated


def test_update_quick_guide_versions_missing_manager_fails_without_modification(
    tmp_path: Path,
) -> None:
    """A missing expected CLI reference fails without partially changing the guide."""
    guide_path = tmp_path / "quick-guide.md"
    content = "".join(
        line
        for line in QUICK_GUIDE_PATH.read_text(encoding="utf-8").splitlines(
            keepends=True
        )
        if not line.startswith("manager:")
    )
    guide_path.write_text(content, encoding="utf-8")

    result = run_updater(guide_path, "9.8.7")

    assert result.returncode == 2
    assert "manager startup version" in result.stderr
    assert guide_path.read_text(encoding="utf-8") == content
