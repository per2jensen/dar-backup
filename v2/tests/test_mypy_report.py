"""Tests for the structured mypy report runner."""

# ruff: noqa: S101 - pytest uses assert for test expectations.

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest


pytestmark = pytest.mark.component
REPORTER = Path(__file__).parents[1] / "scripts" / "run_mypy_report.py"


def test_mypy_report_valid_source_writes_passing_checks(tmp_path: Path) -> None:
    """Valid source must produce a passing report with effective checks.

    Args:
        tmp_path: Isolated pytest directory.
    """
    source = tmp_path / "valid_module.py"
    source.write_text("value: int = 1\n", encoding="utf-8")
    output = tmp_path / "mypy.json"

    result = subprocess.run(  # noqa: S603 - execute the repository-owned helper.
        [
            sys.executable,
            str(REPORTER),
            "--output",
            str(output),
            str(source),
        ],
        check=False,
        capture_output=True,
        text=True,
        cwd=tmp_path,
    )

    report = json.loads(output.read_text(encoding="utf-8"))
    assert result.returncode == 0
    assert report["status"] == "passed"
    assert report["exit_code"] == 0
    assert report["summary"] == {
        "errors": 0,
        "notes": 0,
        "warnings": 0,
        "files_with_errors": 0,
        "diagnostics": 0,
    }
    assert report["diagnostics"] == []
    assert report["checks"]["enabled_error_codes"] == sorted(
        report["checks"]["enabled_error_codes"]
    )
    assert "assignment" in report["checks"]["enabled_error_codes"]
    assert len(report["checks_sha256"]) == 64
    assert report["version"].startswith("mypy ")


def test_mypy_report_invalid_source_writes_failed_diagnostics(tmp_path: Path) -> None:
    """Invalid source must preserve mypy's failure and structured diagnostic.

    Args:
        tmp_path: Isolated pytest directory.
    """
    source = tmp_path / "invalid_module.py"
    source.write_text("value: int = 'wrong'\n", encoding="utf-8")
    output = tmp_path / "mypy.json"

    result = subprocess.run(  # noqa: S603 - execute the repository-owned helper.
        [
            sys.executable,
            str(REPORTER),
            "--output",
            str(output),
            str(source),
        ],
        check=False,
        capture_output=True,
        text=True,
        cwd=tmp_path,
    )

    report = json.loads(output.read_text(encoding="utf-8"))
    assert result.returncode == 1
    assert report["status"] == "failed"
    assert report["exit_code"] == 1
    assert report["summary"]["errors"] == 1
    assert report["summary"]["files_with_errors"] == 1
    assert report["summary"]["diagnostics"] == 1
    assert report["diagnostics"][0]["code"] == "assignment"
    assert "Incompatible types in assignment" in report["diagnostics"][0]["message"]
    assert "mypy exited with status 1" in result.stderr
