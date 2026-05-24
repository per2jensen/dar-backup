#!/usr/bin/env python3
"""
Integration tests for FULL archive deletion via the cleanup entry point.

The tests drive a real `dar-backup --full-backup` run to produce genuine dar
archives (multi-slice binary files registered in dar_manager's catalog), then
invoke `cleanup --cleanup-specific-archives` to exercise the full confirmation
→ deletion → catalog-removal path.

Two behaviours are verified:
  - CLEANUP_TEST_DELETE_FULL=yes  → slices removed from disk, catalog cleared
  - CLEANUP_TEST_DELETE_FULL=no   → slices survive untouched
"""

import os
import subprocess
import sys
from typing import List

import pytest

pytestmark = [pytest.mark.integration, pytest.mark.smoke]

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from dar_backup.command_runner import CommandRunner
from tests.testdata_verification import run_backup_script


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _find_archive_name(backup_dir: str, backup_type: str, backup_def: str) -> str:
    """
    Return the base archive name (without .N.dar suffix) for the first matching archive.

    Args:
        backup_dir: Directory containing .dar slice files.
        backup_type: One of FULL, DIFF, INCR.
        backup_def: Backup definition prefix (e.g. "example").

    Returns:
        Archive base name such as "example_FULL_2026-05-23".

    Raises:
        RuntimeError: If no matching archive is found.
    """
    marker = f"{backup_def}_{backup_type}_"
    for name in sorted(os.listdir(backup_dir)):
        if name.endswith(".1.dar") and marker in name:
            return name[: -len(".1.dar")]
    raise RuntimeError(
        f"No {backup_type} archive found for '{backup_def}' in '{backup_dir}'"
    )


def _dar_slices(backup_dir: str, archive_name: str) -> List[str]:
    """
    Return paths of all .dar slices present on disk for the given archive base name.

    Args:
        backup_dir: Directory to scan.
        archive_name: Base name without the .N.dar suffix.

    Returns:
        Sorted list of absolute paths for matching .dar files.
    """
    return sorted(
        os.path.join(backup_dir, f)
        for f in os.listdir(backup_dir)
        if f.startswith(archive_name) and f.endswith(".dar")
    )


def _run_cleanup_specific(
    env,
    archive_name: str,
    delete_answer: str,
) -> subprocess.CompletedProcess:
    """
    Run `cleanup --cleanup-specific-archives` in test-mode with the given answer.

    Args:
        env: EnvData fixture.
        archive_name: Archive base name to pass to --cleanup-specific-archives.
        delete_answer: Value for CLEANUP_TEST_DELETE_FULL ("yes" or "no").

    Returns:
        CompletedProcess from subprocess.run.
    """
    env_vars = {**os.environ, "CLEANUP_TEST_DELETE_FULL": delete_answer}
    command = [
        "cleanup",
        "--test-mode",
        "--cleanup-specific-archives", archive_name,
        "--config-file", env.config_file,
        "--log-level", "debug",
        "--log-stdout",
    ]
    result = subprocess.run(command, capture_output=True, text=True, env=env_vars)
    env.logger.info("cleanup stdout:\n%s", result.stdout)
    if result.returncode != 0:
        env.logger.error("cleanup stderr:\n%s", result.stderr)
    return result


def _catalog_contains(env, archive_name: str) -> bool:
    """
    Return True if dar_manager's catalog still lists the given archive.

    Args:
        env: EnvData fixture.
        archive_name: Archive base name to search for.

    Returns:
        True if the archive name appears in the catalog listing.
    """
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
    db_path = os.path.join(env.backup_dir, "example.db")
    result = runner.run(
        ["dar_manager", "--base", db_path, "--list"],
        timeout=60,
    )
    env.logger.info("dar_manager --list:\n%s", result.stdout)
    return archive_name in result.stdout


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_cleanup_full_archive_yes_deletes_slices_and_catalog(setup_environment, env):
    """
    CLEANUP_TEST_DELETE_FULL=yes must remove all .dar slices from disk
    and remove the catalog entry from dar_manager.
    """
    run_backup_script("--full-backup", env)

    archive_name = _find_archive_name(env.backup_dir, "FULL", "example")
    env.logger.info("Archive under test: %s", archive_name)

    slices_before = _dar_slices(env.backup_dir, archive_name)
    assert slices_before, f"No .dar slices found before deletion for: {archive_name}"

    assert _catalog_contains(env, archive_name), (
        f"Archive '{archive_name}' not found in catalog before deletion"
    )

    result = _run_cleanup_specific(env, archive_name, delete_answer="yes")
    assert result.returncode == 0, f"cleanup exited non-zero:\n{result.stderr}"

    # All .dar slices must be gone from disk
    slices_after = _dar_slices(env.backup_dir, archive_name)
    assert not slices_after, (
        f"Expected all slices deleted, but these remain: {slices_after}"
    )

    # Catalog entry must have been removed
    assert not _catalog_contains(env, archive_name), (
        f"Archive '{archive_name}' still present in catalog after deletion"
    )


def test_cleanup_full_archive_no_keeps_slices_on_disk(setup_environment, env):
    """
    CLEANUP_TEST_DELETE_FULL=no must leave all .dar slices untouched
    when the user declines the confirmation prompt.
    """
    run_backup_script("--full-backup", env)

    archive_name = _find_archive_name(env.backup_dir, "FULL", "example")
    env.logger.info("Archive under test: %s", archive_name)

    slices_before = _dar_slices(env.backup_dir, archive_name)
    assert slices_before, f"No .dar slices found before the 'no' run for: {archive_name}"

    result = _run_cleanup_specific(env, archive_name, delete_answer="no")
    assert result.returncode == 0, f"cleanup exited non-zero:\n{result.stderr}"

    # All slices must still be present
    slices_after = _dar_slices(env.backup_dir, archive_name)
    assert slices_after == slices_before, (
        f"Expected slices unchanged after 'no' answer.\n"
        f"  Before: {slices_before}\n"
        f"  After:  {slices_after}"
    )

    # Catalog entry must still be present
    assert _catalog_contains(env, archive_name), (
        f"Archive '{archive_name}' was removed from catalog despite 'no' answer"
    )
