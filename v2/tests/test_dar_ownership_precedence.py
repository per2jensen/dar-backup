# SPDX-License-Identifier: GPL-3.0-or-later
"""
Integration tests that verify dar's --comparison-field flag behaviour when
passed on the CLI versus when present in the darrc restore-options section.

These tests exist to lock down the dar behaviour our implementation relies on:
  - CLI --comparison-field=ignore-owner works WITHOUT a darrc entry.
  - CLI --comparison-field=ignore-owner and the same flag in darrc coexist
    without error (backward-compat for existing .darrc files during migration).
  - A CLI --comparison-field=owner passed alongside a darrc ignore-owner
    entry is accepted by dar (which setting wins cannot be proven without
    root, since the test user owns the restored files either way).

NOTE: ownership-restoration correctness cannot be fully verified without root
access, because chown() to your own uid/gid never fails regardless of whether
dar tries it.  These tests validate CLI flag acceptance and exit-code success.
"""

import os
import subprocess
import tempfile
import textwrap

import pytest

pytestmark = [pytest.mark.integration, pytest.mark.smoke]


def _write_darrc(path: str, restore_options_lines: list[str]) -> None:
    """Write a minimal darrc with the given restore-options lines."""
    lines = ["restore-options:\n"]
    for line in restore_options_lines:
        lines.append(line + "\n")
    with open(path, "w") as fh:
        fh.writelines(lines)


def _create_backup(archive_path: str, source_dir: str, darrc: str) -> None:
    """Create a dar FULL backup of source_dir."""
    cmd = [
        "dar", "-c", archive_path,
        "-R", source_dir,
        "--noconf", "-Q",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    assert result.returncode == 0, (
        f"dar backup failed (rc={result.returncode}):\n"
        f"stdout: {result.stdout}\nstderr: {result.stderr}"
    )


def _restore(archive_path: str, restore_dir: str, darrc: str,
             extra_cli_flags: list[str]) -> subprocess.CompletedProcess:
    """Run dar -x with the given darrc and any extra CLI flags.

    stdin is always DEVNULL so behaviour is consistent between interactive
    terminals (local runs) and non-interactive environments (CI).
    """
    cmd = [
        "dar", "-x", archive_path,
        "-R", restore_dir,
        "--noconf", "-Q",
        "-B", darrc, "restore-options",
    ] + extra_cli_flags
    return subprocess.run(cmd, capture_output=True, text=True,
                          stdin=subprocess.DEVNULL)


@pytest.fixture
def work_dir():
    """Isolated temp directory for each test."""
    with tempfile.TemporaryDirectory(prefix="dar-test-") as d:
        yield d


def _setup_backup(work_dir: str) -> tuple[str, str]:
    """
    Create a small source tree and a dar FULL archive of it.

    Returns (archive_path_without_slice_suffix, minimal_darrc_path).
    """
    source = os.path.join(work_dir, "source")
    os.makedirs(source)
    (open(os.path.join(source, "a.txt"), "w")).write("hello")
    (open(os.path.join(source, "b.txt"), "w")).write("world")

    minimal_darrc = os.path.join(work_dir, "minimal.darrc")
    _write_darrc(minimal_darrc, [])

    archive = os.path.join(work_dir, "test_archive")
    _create_backup(archive, source, minimal_darrc)
    return archive, minimal_darrc


def test_dar_cli_ignore_owner_without_darrc_entry_succeeds(work_dir):
    """
    Verify that --comparison-field=ignore-owner passed on the CLI is accepted
    by dar even when the darrc has no --comparison-field entry.

    This is the exact mode our implementation uses after removing the flag
    from .darrc and injecting it programmatically on the command line.
    """
    archive, _ = _setup_backup(work_dir)

    darrc_no_flag = os.path.join(work_dir, "no_flag.darrc")
    _write_darrc(darrc_no_flag, [])

    restore_dir = os.path.join(work_dir, "restore1")
    os.makedirs(restore_dir)

    result = _restore(
        archive, restore_dir, darrc_no_flag,
        extra_cli_flags=["--comparison-field=ignore-owner"],
    )
    assert result.returncode == 0, (
        f"dar restore failed with CLI ignore-owner but no darrc entry "
        f"(rc={result.returncode}):\nstdout: {result.stdout}\nstderr: {result.stderr}"
    )


def test_dar_ignore_owner_in_both_darrc_and_cli_succeeds(work_dir):
    """
    Verify that having --comparison-field=ignore-owner in BOTH the darrc
    restore-options AND on the CLI does not cause dar to fail.

    This matters for the migration window when existing users still have the
    old .darrc entry and dar-backup also injects the flag on the CLI.
    """
    archive, _ = _setup_backup(work_dir)

    darrc_with_flag = os.path.join(work_dir, "with_flag.darrc")
    _write_darrc(darrc_with_flag, ["--comparison-field=ignore-owner"])

    restore_dir = os.path.join(work_dir, "restore2")
    os.makedirs(restore_dir)

    result = _restore(
        archive, restore_dir, darrc_with_flag,
        extra_cli_flags=["--comparison-field=ignore-owner"],
    )
    assert result.returncode == 0, (
        f"dar restore failed when --comparison-field=ignore-owner appears in "
        f"both darrc and CLI (rc={result.returncode}):\n"
        f"stdout: {result.stdout}\nstderr: {result.stderr}"
    )


def test_dar_cli_owner_alongside_darrc_ignore_owner_succeeds(work_dir):
    """
    Verify that passing --comparison-field=owner on the CLI while the darrc
    has --comparison-field=ignore-owner does not cause dar to abort.

    Which setting actually wins cannot be determined without root (chown to
    the same uid never fails), but this test confirms dar accepts both flags
    simultaneously — a necessary pre-condition for CLI override to be feasible.
    """
    archive, _ = _setup_backup(work_dir)

    darrc_with_ignore = os.path.join(work_dir, "ignore.darrc")
    _write_darrc(darrc_with_ignore, ["--comparison-field=ignore-owner"])

    restore_dir = os.path.join(work_dir, "restore3")
    os.makedirs(restore_dir)

    result = _restore(
        archive, restore_dir, darrc_with_ignore,
        extra_cli_flags=["--comparison-field=owner"],
    )
    assert result.returncode == 0, (
        f"dar rejected --comparison-field=owner alongside darrc ignore-owner "
        f"(rc={result.returncode}):\nstdout: {result.stdout}\nstderr: {result.stderr}"
    )


def test_dar_no_comparison_field_anywhere_nonroot_behaviour(work_dir):
    """
    Verify dar's behaviour when neither darrc nor CLI specify --comparison-field
    and stdin is non-interactive (DEVNULL).

    The outcome is dar-version-dependent:
    - Older dar: prompts about ownership, gets no answer, aborts with rc=4 and
      an ownership warning in stderr.
    - Newer dar (>= 2.7.x): detects non-interactive mode, skips the prompt,
      and succeeds with rc=0 because chown to the same uid is a no-op.

    Both outcomes are acceptable.  If rc=4 we assert the ownership message is
    present so we know it is the expected failure and not an unrelated error.
    This test documents why dar-backup must inject
    --comparison-field=ignore-owner for non-root restores.
    """
    archive, _ = _setup_backup(work_dir)

    darrc_empty = os.path.join(work_dir, "empty.darrc")
    _write_darrc(darrc_empty, [])

    restore_dir = os.path.join(work_dir, "restore4")
    os.makedirs(restore_dir)

    result = _restore(archive, restore_dir, darrc_empty, extra_cli_flags=[])
    assert result.returncode in (0, 4), (
        f"Unexpected dar exit code (expected 0 or 4) without --comparison-field "
        f"as non-root (rc={result.returncode}):\n"
        f"stdout: {result.stdout}\nstderr: {result.stderr}"
    )
    if result.returncode == 4:
        assert "ownership" in result.stderr.lower(), (
            f"rc=4 but no ownership message in stderr:\n{result.stderr}"
        )
