#!/usr/bin/env python3
"""Publish the released dar-backup version to the GitHub Pages branch."""

from __future__ import annotations

import argparse
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Sequence


LOGGER = logging.getLogger(__name__)
VERSION_PATTERN = re.compile(r"^[0-9]+(?:\.[0-9]+){2,3}$")
REMOTE_PATTERN = re.compile(r"^[A-Za-z0-9._-]+$")
BRANCH_PATTERN = re.compile(r"^[A-Za-z0-9._/-]+$")
CURRENT_VERSION_PATTERN = re.compile(
    r'(<span class="status-pill green">)v(?P<version>[0-9]+(?:\.[0-9]+){2,3})( current</span>)'
)


def find_git_executable() -> str:
    """Resolve Git to an absolute executable path.

    Returns:
        Absolute path to the Git executable.

    Raises:
        OSError: If Git is not available through ``PATH``.
    """
    executable = shutil.which("git")
    if executable is None:
        raise OSError("Git executable was not found in PATH")
    return executable


def validate_release_version(version: str) -> None:
    """Validate a stable dar-backup release version.

    Args:
        version: Candidate release version without the ``v2-`` tag prefix.

    Returns:
        None.

    Raises:
        ValueError: If the version is empty or is not a supported stable version.
    """
    if not isinstance(version, str) or not version:
        raise ValueError("Release version must be a non-empty string")
    if VERSION_PATTERN.fullmatch(version) is None:
        raise ValueError(
            f"Release version must contain three or four numeric components: {version!r}"
        )


def validate_git_name(value: str, label: str, pattern: re.Pattern[str]) -> None:
    """Validate a Git remote or branch name used to construct a refspec.

    Args:
        value: Name to validate.
        label: Human-readable name used in validation errors.
        pattern: Allow-list pattern for the requested kind of Git name.

    Returns:
        None.

    Raises:
        ValueError: If the name is empty, unsafe, or malformed.
    """
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} must be a non-empty string")
    if pattern.fullmatch(value) is None:
        raise ValueError(f"{label} contains unsupported characters: {value!r}")
    if value.startswith(('.', '/')) or value.endswith(('.', '/')) or '..' in value or '//' in value:
        raise ValueError(f"{label} is not a safe Git name: {value!r}")


def run_git(repository: Path, arguments: Sequence[str]) -> subprocess.CompletedProcess[str]:
    """Run one Git command and capture its output.

    Args:
        repository: Checkout in which Git should run.
        arguments: Git arguments excluding the executable name and ``-C`` option.

    Returns:
        The completed Git process.

    Raises:
        OSError: If Git cannot be executed.
        subprocess.CalledProcessError: If Git exits with a non-zero status.
    """
    # Git receives an argv list (never a shell string); callers supply only
    # fixed commands plus names and paths validated by this module.
    return subprocess.run(  # noqa: S603
        [find_git_executable(), "-C", str(repository), *arguments],
        check=True,
        capture_output=True,
        text=True,
    )


def update_pages_version(html_path: Path, version: str) -> bool:
    """Replace the single current-version marker in a Pages HTML file.

    Args:
        html_path: Path to the checked-out ``index.html`` file.
        version: Stable release version without the ``v2-`` tag prefix.

    Returns:
        ``True`` when the file changed, otherwise ``False``.

    Raises:
        OSError: If the HTML file cannot be read or replaced atomically.
        ValueError: If inputs or the current-version marker are invalid.
    """
    validate_release_version(version)
    if not isinstance(html_path, Path):
        raise ValueError("HTML path must be a pathlib.Path")  # noqa: TRY004
    if not html_path.is_file():
        raise ValueError(f"Pages HTML file does not exist or is not a regular file: {html_path}")

    original = html_path.read_text(encoding="utf-8")
    matches = list(CURRENT_VERSION_PATTERN.finditer(original))
    if len(matches) != 1:
        raise ValueError(
            "Pages HTML must contain exactly one current-version status marker; "
            f"found {len(matches)} in {html_path}"
        )

    match = matches[0]
    if match.group("version") == version:
        return False

    updated = (
        original[: match.start("version")]
        + version
        + original[match.end("version") :]
    )
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=html_path.parent,
            prefix=f".{html_path.name}.",
            delete=False,
        ) as temporary_file:
            temporary_file.write(updated)
            temporary_file.flush()
            os.fsync(temporary_file.fileno())
            temporary_path = Path(temporary_file.name)

        os.chmod(temporary_path, html_path.stat().st_mode)
        os.replace(temporary_path, html_path)
        temporary_path = None
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)

    return True


def publish_pages_version(
    repository: Path,
    version: str,
    tag: str,
    remote: str,
    branch: str,
) -> bool:
    """Update and push the Pages version from an isolated temporary worktree.

    Args:
        repository: Application and orchestration checkout used for the release.
        version: Stable release version without the ``v2-`` tag prefix.
        tag: Immutable application-source release tag.
        remote: Git remote containing the Pages branch.
        branch: Branch from which GitHub Pages is published.

    Returns:
        ``True`` when a Pages commit was pushed, otherwise ``False``.

    Raises:
        OSError: If filesystem or process operations fail.
        RuntimeError: If temporary-worktree cleanup fails after publication.
        subprocess.CalledProcessError: If a required Git command fails.
        ValueError: If validation fails or checkout state is inconsistent.
    """
    validate_release_version(version)
    validate_git_name(remote, "Git remote", REMOTE_PATTERN)
    validate_git_name(branch, "Pages branch", BRANCH_PATTERN)
    if not isinstance(repository, Path):
        raise ValueError("Repository path must be a pathlib.Path")  # noqa: TRY004

    resolved_repository = repository.resolve(strict=True)
    if not resolved_repository.is_dir():
        raise ValueError(f"Repository path is not a directory: {resolved_repository}")

    expected_tag = f"v2-{version}"
    if tag != expected_tag:
        raise ValueError(f"Release tag must be {expected_tag!r}, received {tag!r}")

    tooling_commit = run_git(resolved_repository, ["rev-parse", "HEAD"]).stdout.strip()
    source_commit = run_git(
        resolved_repository,
        ["rev-parse", f"{tag}^{{commit}}"],
    ).stdout.strip()
    if tooling_commit != source_commit:
        raise ValueError(
            "Release checkout HEAD must equal the immutable application-source tag: "
            f"HEAD={tooling_commit}, {tag}={source_commit}"
        )

    remote_ref = f"refs/remotes/{remote}/{branch}"
    fetch_refspec = f"+refs/heads/{branch}:{remote_ref}"
    run_git(resolved_repository, ["fetch", "--no-tags", remote, fetch_refspec])
    pages_commit = run_git(resolved_repository, ["rev-parse", remote_ref]).stdout.strip()

    with tempfile.TemporaryDirectory(prefix="dar-backup-pages-") as temporary_directory:
        pages_checkout = Path(temporary_directory) / "checkout"
        worktree_added = False
        try:
            run_git(
                resolved_repository,
                ["worktree", "add", "--detach", str(pages_checkout), pages_commit],
            )
            worktree_added = True

            checked_out_commit = run_git(pages_checkout, ["rev-parse", "HEAD"]).stdout.strip()
            if checked_out_commit != pages_commit:
                raise ValueError(
                    "Pages worktree revision mismatch: "
                    f"expected {pages_commit}, found {checked_out_commit}"
                )
            if run_git(pages_checkout, ["status", "--porcelain"]).stdout:
                raise ValueError("Pages worktree is unexpectedly dirty before version update")

            html_path = pages_checkout / "index.html"
            changed = update_pages_version(html_path, version)
            if not changed:
                LOGGER.info("GitHub Pages already reports dar-backup %s", version)
                return False

            run_git(pages_checkout, ["add", "--", "index.html"])
            commit_message = (
                f"pages: update current version to {version}\n\n"
                f"Application-source: {source_commit}\n"
                f"Orchestration: {tooling_commit}\n"
                f"Release-tag: {tag}"
            )
            # The repository pre-commit hook belongs to the application checkout
            # and cannot run in the intentionally separate gh-pages checkout.
            run_git(
                pages_checkout,
                ["commit", "--no-verify", "-m", commit_message],
            )
            push_result = run_git(
                pages_checkout,
                ["push", remote, f"HEAD:refs/heads/{branch}"],
            )
            if push_result.stderr.strip():
                LOGGER.info("Git push: %s", push_result.stderr.strip())
            return True
        finally:
            if worktree_added:
                # The executable and every command token are fixed here; the
                # validated repository owns the generated temporary worktree.
                cleanup_result = subprocess.run(  # noqa: S603
                    [
                        find_git_executable(),
                        "-C",
                        str(resolved_repository),
                        "worktree",
                        "remove",
                        "--force",
                        str(pages_checkout),
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                if cleanup_result.returncode != 0:
                    message = (
                        "Failed to remove temporary Pages worktree "
                        f"{pages_checkout}: {cleanup_result.stderr.strip()}"
                    )
                    if sys.exc_info()[0] is not None:
                        LOGGER.error("%s; preserving the original publication error", message)
                    else:
                        raise RuntimeError(message)


def main(argv: Sequence[str] | None = None) -> int:
    """Parse command-line arguments and publish the Pages version.

    Args:
        argv: Optional arguments excluding the executable name.

    Returns:
        Zero on success, one for Git or filesystem failures, and two for
        validation failures.

    Raises:
        SystemExit: If argparse rejects the command-line syntax.
    """
    parser = argparse.ArgumentParser(
        description="Update the release version in an isolated GitHub Pages worktree."
    )
    parser.add_argument("--repository", required=True, type=Path)
    parser.add_argument("--version", required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--remote", default="origin")
    parser.add_argument("--branch", default="gh-pages")
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    try:
        changed = publish_pages_version(
            repository=args.repository,
            version=args.version,
            tag=args.tag,
            remote=args.remote,
            branch=args.branch,
        )
    except ValueError as exc:
        LOGGER.error(  # noqa: TRY400
            "GitHub Pages publication validation failed: %s",
            exc,
        )
        return 2
    except subprocess.CalledProcessError as exc:
        detail = (exc.stderr or exc.stdout or "no command output").strip()
        LOGGER.error(  # noqa: TRY400
            "GitHub Pages Git command failed with status %d: %s (%s)",
            exc.returncode,
            " ".join(str(part) for part in exc.cmd),
            detail,
        )
        return 1
    except OSError as exc:
        LOGGER.error(  # noqa: TRY400
            "GitHub Pages filesystem or process operation failed: %s",
            exc,
        )
        return 1
    except RuntimeError as exc:
        LOGGER.error(  # noqa: TRY400
            "GitHub Pages temporary-worktree cleanup failed: %s",
            exc,
        )
        return 1

    if changed:
        LOGGER.info("Published dar-backup %s to GitHub Pages", args.version)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
