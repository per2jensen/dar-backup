# SPDX-License-Identifier: GPL-3.0-or-later
"""
Integration tests that verify dar's --deleted=ignore flag behaviour.

These tests lock down the dar behaviour that dar-backup relies on for the
--no-deleted feature:
  - DIFF restore to an empty directory fails (rc != 0) without --deleted=ignore
    when deletion records reference files not present in the restore target.
  - DIFF restore to an empty directory succeeds (rc=0) with --deleted=ignore.
  - Removing -/ Oo from the dar command does not change data or EA overwriting
    behaviour compared to the default.

Both dar 2.7.13 (Ubuntu 24.04 / CI) and 2.7.21 are covered by the same
flag syntax: --deleted=ignore.
"""

import os
import subprocess
import tempfile

import pytest

pytestmark = [pytest.mark.integration, pytest.mark.smoke]


def _write_darrc(path: str) -> None:
    """Write a minimal darrc that suppresses the ownership prompt on non-root runs.

    --comparison-field=ignore-owner mirrors dar-backup's default (RESTORE_OWNERSHIP=no)
    and prevents dar 2.7.13 from prompting when stdin is closed (rc=4 on EOF).
    """
    with open(path, "w") as fh:
        fh.write("restore-options:\n--comparison-field=ignore-owner\n")


def _create_full(archive: str, source: str) -> None:
    """Create a FULL dar archive of source."""
    result = subprocess.run(
        ["dar", "-c", archive, "-R", source, "--noconf", "-Q"],
        capture_output=True, text=True, stdin=subprocess.DEVNULL,
    )
    assert result.returncode == 0, f"dar FULL backup failed: {result.stderr}"


def _create_diff(archive: str, reference: str, source: str) -> None:
    """Create a DIFF dar archive of source relative to reference."""
    result = subprocess.run(
        ["dar", "-c", archive, "-A", reference, "-R", source, "--noconf", "-Q"],
        capture_output=True, text=True, stdin=subprocess.DEVNULL,
    )
    assert result.returncode == 0, f"dar DIFF backup failed: {result.stderr}"


def _restore(archive: str, restore_dir: str, darrc: str,
             extra_flags: list[str]) -> subprocess.CompletedProcess:
    """Run dar -x with the given flags; stdin always DEVNULL for consistency."""
    cmd = ["dar", "-x", archive, "-wa", "--noconf", "-Q",
           "-R", restore_dir, "-B", darrc, "restore-options"] + extra_flags
    return subprocess.run(cmd, capture_output=True, text=True,
                          stdin=subprocess.DEVNULL)


@pytest.fixture
def work_dir():
    """Isolated temp directory for each test."""
    with tempfile.TemporaryDirectory(prefix="dar-deleted-test-") as d:
        yield d


def _setup(work_dir: str):
    """
    Build a FULL and a DIFF archive where one file was deleted between them.

    Returns (full_path, diff_path, darrc_path).
    """
    darrc = os.path.join(work_dir, "test.darrc")
    _write_darrc(darrc)

    source = os.path.join(work_dir, "source")
    os.makedirs(source)
    (open(os.path.join(source, "kept.txt"), "w")).write("stays")
    (open(os.path.join(source, "deleted.txt"), "w")).write("goes away")

    full = os.path.join(work_dir, "archive_FULL")
    _create_full(full, source)

    os.remove(os.path.join(source, "deleted.txt"))
    (open(os.path.join(source, "new.txt"), "w")).write("added later")

    diff = os.path.join(work_dir, "archive_DIFF")
    _create_diff(diff, full, source)

    return full, diff, darrc


def test_diff_restore_without_deleted_ignore_fails(work_dir):
    """
    Verify that restoring a DIFF archive to an empty directory fails when
    --deleted=ignore is NOT passed.

    The DIFF contains a deletion record for deleted.txt.  Since the file is
    absent from the empty restore target, dar cannot complete the deletion and
    exits with a non-zero return code.  This is the failure mode that
    --no-deleted (--deleted=ignore) is designed to prevent.
    """
    _, diff, darrc = _setup(work_dir)
    restore_dir = os.path.join(work_dir, "restore_no_flag")
    os.makedirs(restore_dir)

    result = _restore(diff, restore_dir, darrc, extra_flags=[])
    assert result.returncode != 0, (
        f"Expected dar to fail without --deleted=ignore (rc={result.returncode}). "
        f"stdout: {result.stdout}\nstderr: {result.stderr}"
    )


def test_diff_restore_with_deleted_ignore_succeeds(work_dir):
    """
    Verify that --deleted=ignore suppresses deletion record errors when
    restoring a DIFF archive to an empty directory.

    This is the exact flag dar-backup injects when --no-deleted is passed.
    """
    _, diff, darrc = _setup(work_dir)
    restore_dir = os.path.join(work_dir, "restore_with_flag")
    os.makedirs(restore_dir)

    result = _restore(diff, restore_dir, darrc,
                      extra_flags=["--deleted=ignore"])
    assert result.returncode == 0, (
        f"dar DIFF restore with --deleted=ignore failed (rc={result.returncode}): "
        f"stdout: {result.stdout}\nstderr: {result.stderr}"
    )
    # Only new.txt was saved in the DIFF (kept.txt was unchanged and not re-saved)
    assert os.path.isfile(os.path.join(restore_dir, "new.txt"))


def test_diff_restore_deleted_ignore_zero_deletions_logged(work_dir):
    """
    Verify that --deleted=ignore results in '0 inode(s) deleted' in dar output,
    confirming deletion records were suppressed rather than silently processed.
    """
    _, diff, darrc = _setup(work_dir)
    restore_dir = os.path.join(work_dir, "restore_zero_del")
    os.makedirs(restore_dir)

    result = _restore(diff, restore_dir, darrc,
                      extra_flags=["--deleted=ignore"])
    assert result.returncode == 0
    assert "0 inode(s) deleted" in result.stdout, (
        f"Expected '0 inode(s) deleted' in stdout:\n{result.stdout}"
    )


def test_full_restore_without_overwriting_policy_succeeds(work_dir):
    """
    Verify that removing -/ Oo from the dar command does not break FULL
    restore — data is restored correctly with the default overwriting behaviour.
    """
    full, _, darrc = _setup(work_dir)
    restore_dir = os.path.join(work_dir, "restore_full_no_policy")
    os.makedirs(restore_dir)

    result = _restore(full, restore_dir, darrc, extra_flags=[])
    assert result.returncode == 0, (
        f"FULL restore without -/ Oo failed (rc={result.returncode}): "
        f"stdout: {result.stdout}\nstderr: {result.stderr}"
    )
    assert os.path.isfile(os.path.join(restore_dir, "kept.txt"))
    assert os.path.isfile(os.path.join(restore_dir, "deleted.txt"))
