"""Tests for release environment and wheel-content validation."""

import zipfile
from pathlib import Path

import pytest

from scripts.release_validation import (
    collect_staged_document_paths,
    validate_tool_versions,
    validate_wheel_documentation,
)

pytestmark = pytest.mark.unit


def test_validate_tool_versions_supported_versions_pass() -> None:
    """Supported release-tool versions must pass validation."""
    validate_tool_versions(
        {"packaging": "26.0", "twine": "6.2.1"},
        (("packaging", "26.0"), ("twine", "6.2.0")),
    )


@pytest.mark.parametrize(
    ("installed_versions", "expected_message"),
    [
        ({"twine": "6.2.0"}, "packaging"),
        ({"packaging": "25.0", "twine": "6.2.0"}, "too old"),
    ],
)
def test_validate_tool_versions_missing_or_old_version_raises(
    installed_versions: dict[str, str],
    expected_message: str,
) -> None:
    """Missing and obsolete release tools must fail validation."""
    with pytest.raises(ValueError, match=expected_message):
        validate_tool_versions(
            installed_versions,
            (("packaging", "26.0"), ("twine", "6.2.0")),
        )


def test_validate_wheel_documentation_all_staged_docs_pass(tmp_path: Path) -> None:
    """A wheel containing every staged document must pass validation."""
    staging_dir = tmp_path / "src" / "dar_backup"
    docs_dir = staging_dir / "doc"
    docs_dir.mkdir(parents=True)
    (staging_dir / "README.md").write_text("readme", encoding="utf-8")
    (staging_dir / "Changelog.md").write_text("changelog", encoding="utf-8")
    (docs_dir / "restoring.md").write_text("restore", encoding="utf-8")

    required_paths = collect_staged_document_paths(staging_dir)
    wheel_path = tmp_path / "dar_backup-1.0.0-py3-none-any.whl"
    with zipfile.ZipFile(wheel_path, "w") as wheel:
        for required_path in required_paths:
            wheel.writestr(required_path, "content")

    validate_wheel_documentation(wheel_path, required_paths)


def test_validate_wheel_documentation_missing_staged_doc_raises(tmp_path: Path) -> None:
    """A wheel missing one staged document must fail validation."""
    wheel_path = tmp_path / "dar_backup-1.0.0-py3-none-any.whl"
    with zipfile.ZipFile(wheel_path, "w") as wheel:
        wheel.writestr("dar_backup/README.md", "readme")
        wheel.writestr("dar_backup/Changelog.md", "changelog")

    required_paths = (
        "dar_backup/README.md",
        "dar_backup/Changelog.md",
        "dar_backup/doc/restoring.md",
    )
    with pytest.raises(ValueError, match="dar_backup/doc/restoring.md"):
        validate_wheel_documentation(wheel_path, required_paths)
