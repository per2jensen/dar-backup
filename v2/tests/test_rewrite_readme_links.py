# SPDX-License-Identifier: GPL-3.0-or-later
"""
Tests for v2/scripts/rewrite_readme_links.py

The script is a standalone file (not a package), so it is loaded via
importlib.util.spec_from_file_location, matching the pattern used for
scripts/import-archive-metrics.py.
"""

import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

# ---------------------------------------------------------------------------
# Load the script as a module
# ---------------------------------------------------------------------------
_SCRIPT = Path(__file__).parent.parent / "scripts" / "rewrite_readme_links.py"

_spec = importlib.util.spec_from_file_location("rewrite_readme_links", _SCRIPT)
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)  # type: ignore[union-attr]

rewrite_links = _mod.rewrite_links
main = _mod.main


# ── rewrite_links: relative targets get rewritten ──────────────────────────

def test_plain_relative_link_becomes_github_blob_url() -> None:
    """A plain relative link must become an absolute GitHub blob URL."""
    text = "See the [Quick Guide](v2/doc/quick-guide.md) for details."
    result = rewrite_links(text, ref="v2-1.1.10", repo="per2jensen/dar-backup")
    assert (
        "[Quick Guide]"
        "(https://github.com/per2jensen/dar-backup/blob/v2-1.1.10/v2/doc/quick-guide.md)"
    ) in result


def test_relative_link_with_fragment_preserves_fragment() -> None:
    """A relative link with a #fragment must keep the fragment on the blob URL."""
    text = "[config file](v2/doc/config-reference.md#config-file)"
    result = rewrite_links(text, ref="v2-1.1.10")
    assert result == (
        "[config file]"
        "(https://github.com/per2jensen/dar-backup/blob/v2-1.1.10/v2/doc/config-reference.md#config-file)"
    )


def test_plain_relative_image_becomes_raw_githubusercontent_url() -> None:
    """A plain relative image must become an absolute raw.githubusercontent.com URL."""
    text = "![overview](v2/doc/dar-backup-overview.png)"
    result = rewrite_links(text, ref="v2-1.1.10")
    assert result == (
        "![overview]"
        "(https://raw.githubusercontent.com/per2jensen/dar-backup/v2-1.1.10/v2/doc/dar-backup-overview.png)"
    )


def test_root_relative_file_link_rewritten() -> None:
    """Bare repo-root files (no subdirectory) must also be rewritten."""
    text = 'have a look at the ["LICENSE"](LICENSE) file'
    result = rewrite_links(text, ref="v2-1.1.10")
    assert (
        '["LICENSE"](https://github.com/per2jensen/dar-backup/blob/v2-1.1.10/LICENSE)'
        in result
    )


def test_linked_image_badge_rewrites_both_targets_without_corruption() -> None:
    """A linked image `[![alt](img)](link)` must rewrite both targets and stay valid markdown."""
    text = "[![dar-backup overview](v2/doc/small.png)](v2/doc/full.png)"
    result = rewrite_links(text, ref="v2-1.1.10")
    assert result == (
        "[![dar-backup overview]"
        "(https://raw.githubusercontent.com/per2jensen/dar-backup/v2-1.1.10/v2/doc/small.png)]"
        "(https://github.com/per2jensen/dar-backup/blob/v2-1.1.10/v2/doc/full.png)"
    )


# ── rewrite_links: already-absolute / anchor targets are left alone ────────

def test_absolute_https_link_is_unchanged() -> None:
    """A target that is already an absolute https:// URL must not be modified."""
    text = "[dar](https://github.com/Edrusb/DAR)"
    result = rewrite_links(text, ref="v2-1.1.10")
    assert result == text


def test_absolute_badge_with_nested_image_is_unchanged() -> None:
    """A badge whose image and link targets are both already absolute must be untouched."""
    text = (
        "[![Codecov](https://codecov.io/gh/per2jensen/dar-backup/branch/main/graph/badge.svg)]"
        "(https://codecov.io/gh/per2jensen/dar-backup)"
    )
    result = rewrite_links(text, ref="v2-1.1.10")
    assert result == text


def test_same_document_anchor_is_unchanged() -> None:
    """A same-document anchor (#section) must not be rewritten into a GitHub URL."""
    text = "[jump to section](#some-section)"
    result = rewrite_links(text, ref="v2-1.1.10")
    assert result == text


# ── rewrite_links: input validation ─────────────────────────────────────────

def test_empty_ref_raises_value_error() -> None:
    """An empty ref must raise ValueError rather than silently emitting broken URLs."""
    with pytest.raises(ValueError, match="ref"):
        rewrite_links("[x](y.md)", ref="")


def test_empty_repo_raises_value_error() -> None:
    """An empty repo slug must raise ValueError rather than silently emitting broken URLs."""
    with pytest.raises(ValueError, match="repo"):
        rewrite_links("[x](y.md)", ref="v2-1.1.10", repo="")


# ── CLI: end-to-end via main() ──────────────────────────────────────────────

def test_cli_rewrites_file_and_leaves_input_untouched_when_output_differs(tmp_path: Path) -> None:
    """Running the CLI with distinct --input/--output must write a rewritten copy
    and leave the original input file exactly as it was."""
    src = tmp_path / "README.md"
    dst = tmp_path / "README.pypi.md"
    original = "[docs](v2/doc/quick-guide.md)\n"
    src.write_text(original, encoding="utf-8")

    result = subprocess.run(
        [
            sys.executable, str(_SCRIPT),
            "--input", str(src), "--output", str(dst),
            "--ref", "v2-1.1.10",
        ],
        capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr
    assert src.read_text(encoding="utf-8") == original
    assert "github.com/per2jensen/dar-backup/blob/v2-1.1.10/v2/doc/quick-guide.md" in dst.read_text(encoding="utf-8")


def test_cli_missing_input_file_exits_nonzero(tmp_path: Path) -> None:
    """A missing --input file must fail the process instead of writing an empty output."""
    missing = tmp_path / "does-not-exist.md"
    out = tmp_path / "out.md"

    result = subprocess.run(
        [
            sys.executable, str(_SCRIPT),
            "--input", str(missing), "--output", str(out),
            "--ref", "v2-1.1.10",
        ],
        capture_output=True, text=True,
    )
    assert result.returncode != 0
    assert not out.exists()
