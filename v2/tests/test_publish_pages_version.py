"""Integration tests for release-time GitHub Pages version publication."""

# Test assertions and controlled subprocesses are intentional here: every Git
# operation targets a fresh repository below pytest's temporary directory.
# ruff: noqa: S101, S603

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from typing import Sequence

import pytest


pytestmark = pytest.mark.unit
SCRIPT_PATH = Path(__file__).parents[1] / "scripts" / "publish_pages_version.py"
VERSION_MARKER = '<span class="status-pill green">v1.1.7 current</span>'


def run_command(
    arguments: Sequence[str],
    working_directory: Path | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    """Run a real subprocess for a test repository operation.

    Args:
        arguments: Complete command and arguments to execute.
        working_directory: Optional subprocess working directory.
        check: Whether a non-zero exit status should raise immediately.

    Returns:
        The completed subprocess with captured text output.

    Raises:
        OSError: If the executable cannot be started.
        subprocess.CalledProcessError: If ``check`` is true and the command fails.
    """
    return subprocess.run(
        list(arguments),
        cwd=working_directory,
        check=check,
        capture_output=True,
        text=True,
    )


def run_git(
    repository: Path,
    arguments: Sequence[str],
) -> subprocess.CompletedProcess[str]:
    """Run Git against a real test repository.

    Args:
        repository: Working tree or bare repository used for the command.
        arguments: Git arguments excluding the executable and ``-C``.

    Returns:
        The completed Git process.

    Raises:
        OSError: If Git cannot be started.
        subprocess.CalledProcessError: If Git exits with a non-zero status.
    """
    return run_command(["git", "-C", str(repository), *arguments])


def create_release_repository(tmp_path: Path, pages_html: str) -> tuple[Path, Path, str]:
    """Create application and Pages revisions in a real local Git remote.

    Args:
        tmp_path: Isolated pytest directory for repositories.
        pages_html: Complete initial ``gh-pages/index.html`` content.

    Returns:
        The source checkout, bare remote, and immutable source commit.

    Raises:
        OSError: If repository files cannot be written.
        subprocess.CalledProcessError: If repository setup fails.
    """
    remote = tmp_path / "remote.git"
    source = tmp_path / "source"
    run_command(["git", "init", "--bare", str(remote)])
    run_command(["git", "init", str(source)])
    run_git(source, ["config", "user.name", "Release Test"])
    run_git(source, ["config", "user.email", "release-test@example.invalid"])

    (source / "README.md").write_text("application source\n", encoding="utf-8")
    run_git(source, ["add", "README.md"])
    run_git(source, ["commit", "-m", "application source"])
    run_git(source, ["branch", "-M", "main"])
    run_git(source, ["remote", "add", "origin", str(remote)])
    run_git(source, ["push", "--set-upstream", "origin", "main"])
    run_git(source, ["tag", "v2-1.1.11"])
    source_commit = run_git(source, ["rev-parse", "HEAD"]).stdout.strip()

    run_git(source, ["switch", "--orphan", "gh-pages"])
    # Newer Git versions clear tracked files for an orphan switch; older ones
    # leave them staged, so remove the source file only when it remains.
    if (source / "README.md").exists():
        run_git(source, ["rm", "--force", "README.md"])
    (source / "index.html").write_text(pages_html, encoding="utf-8")
    run_git(source, ["add", "index.html"])
    run_git(source, ["commit", "-m", "initial Pages site"])
    run_git(source, ["push", "--set-upstream", "origin", "gh-pages"])
    run_git(source, ["switch", "main"])

    return source, remote, source_commit


def run_publisher(
    source: Path,
    version: str = "1.1.11",
    tag: str = "v2-1.1.11",
) -> subprocess.CompletedProcess[str]:
    """Invoke the Pages publisher exactly as the release script does.

    Args:
        source: Application release checkout.
        version: Stable version to publish.
        tag: Immutable application-source tag.

    Returns:
        The completed publisher process without automatic status checking.

    Raises:
        OSError: If Python cannot start the publisher.
    """
    return run_command(
        [
            sys.executable,
            str(SCRIPT_PATH),
            "--repository",
            str(source),
            "--version",
            version,
            "--tag",
            tag,
        ],
        check=False,
    )


def remote_pages_commit(remote: Path) -> str:
    """Return the current Pages commit in a bare test remote.

    Args:
        remote: Bare Git repository containing ``gh-pages``.

    Returns:
        Full commit identifier at ``gh-pages``.

    Raises:
        OSError: If Git cannot be started.
        subprocess.CalledProcessError: If the branch cannot be resolved.
    """
    return run_git(remote, ["rev-parse", "gh-pages"]).stdout.strip()


def assert_temporary_worktree_removed(source: Path) -> None:
    """Assert that publication left only the original source worktree.

    Args:
        source: Application release checkout.

    Returns:
        None.

    Raises:
        AssertionError: If a temporary Pages worktree remains registered.
        OSError: If Git cannot be started.
        subprocess.CalledProcessError: If Git cannot list worktrees.
    """
    worktrees = run_git(source, ["worktree", "list", "--porcelain"]).stdout
    assert worktrees.count("worktree ") == 1


def test_publish_pages_version_valid_release_updates_and_pushes(tmp_path: Path) -> None:
    """A valid release updates Pages and records both source revisions."""
    html = f"<!DOCTYPE html>\n<html><body>{VERSION_MARKER}</body></html>\n"
    source, remote, source_commit = create_release_repository(tmp_path, html)

    result = run_publisher(source)

    assert result.returncode == 0, result.stderr
    published_html = run_git(remote, ["show", "gh-pages:index.html"]).stdout
    assert "v1.1.11 current" in published_html
    assert "v1.1.7 current" not in published_html
    commit_message = run_git(remote, ["log", "-1", "--format=%B", "gh-pages"]).stdout
    assert f"Application-source: {source_commit}" in commit_message
    assert f"Orchestration: {source_commit}" in commit_message
    assert "Release-tag: v2-1.1.11" in commit_message
    assert run_git(source, ["status", "--porcelain"]).stdout == ""
    assert_temporary_worktree_removed(source)


def test_publish_pages_version_current_release_does_not_commit(tmp_path: Path) -> None:
    """An already-current Pages branch exits successfully without a new commit."""
    current_marker = VERSION_MARKER.replace("1.1.7", "1.1.11")
    html = f"<!DOCTYPE html>\n<html><body>{current_marker}</body></html>\n"
    source, remote, _ = create_release_repository(tmp_path, html)
    original_pages_commit = remote_pages_commit(remote)

    result = run_publisher(source)

    assert result.returncode == 0, result.stderr
    assert remote_pages_commit(remote) == original_pages_commit
    assert_temporary_worktree_removed(source)


@pytest.mark.parametrize(
    "pages_html",
    [
        "<!DOCTYPE html><html><body>No version marker</body></html>\n",
        f"<!DOCTYPE html><html><body>{VERSION_MARKER}{VERSION_MARKER}</body></html>\n",
    ],
    ids=["missing-marker", "duplicate-marker"],
)
def test_publish_pages_version_invalid_marker_fails_without_push(
    tmp_path: Path,
    pages_html: str,
) -> None:
    """Missing or duplicate markers fail closed and leave Pages unchanged."""
    source, remote, _ = create_release_repository(tmp_path, pages_html)
    original_pages_commit = remote_pages_commit(remote)

    result = run_publisher(source)

    assert result.returncode == 2
    assert "exactly one current-version status marker" in result.stderr
    assert remote_pages_commit(remote) == original_pages_commit
    assert_temporary_worktree_removed(source)


def test_publish_pages_version_development_version_fails_without_fetch(tmp_path: Path) -> None:
    """A development version is rejected before the Pages branch can change."""
    html = f"<!DOCTYPE html>\n<html><body>{VERSION_MARKER}</body></html>\n"
    source, remote, _ = create_release_repository(tmp_path, html)
    original_pages_commit = remote_pages_commit(remote)

    result = run_publisher(source, version="1.1.12.dev1", tag="v2-1.1.12.dev1")

    assert result.returncode == 2
    assert "three or four numeric components" in result.stderr
    assert remote_pages_commit(remote) == original_pages_commit
    assert_temporary_worktree_removed(source)
