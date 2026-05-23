#!/usr/bin/env python3
"""
Integration tests for relocate_archive_paths() via `manager --relocate-archive-path`.

The tests drive a real `dar-backup --full-backup` run so that genuine dar
archives are created and registered in the dar_manager catalog. They then
call `manager --relocate-archive-path OLD NEW` and verify the catalog DB
via a follow-up `dar_manager --list` call.

Two scenarios:
  - dry-run flag: DB paths are unchanged after the command
  - real run:     DB paths are rewritten to the new prefix
"""

import os
import subprocess
import sys

import pytest

pytestmark = pytest.mark.integration

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from dar_backup.command_runner import CommandRunner
from tests.testdata_verification import run_backup_script


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _catalog_paths(env) -> str:
    """
    Return raw stdout from `dar_manager --list` for the example catalog.

    Args:
        env: EnvData fixture.

    Returns:
        dar_manager --list stdout as a string.

    Raises:
        AssertionError: If dar_manager exits non-zero.
    """
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
    db_path = os.path.join(env.backup_dir, "example.db")
    result = runner.run(["dar_manager", "--base", db_path, "--list"], timeout=60)
    env.logger.info("dar_manager --list:\n%s", result.stdout)
    assert result.returncode == 0, f"dar_manager --list failed: {result.stderr}"
    return result.stdout


def _run_relocate(
    env,
    old_prefix: str,
    new_prefix: str,
    dry_run: bool = False,
) -> subprocess.CompletedProcess:
    """
    Run `manager --relocate-archive-path OLD NEW --backup-def example`.

    Args:
        env: EnvData fixture.
        old_prefix: Current directory prefix stored in the catalog.
        new_prefix: Replacement directory prefix.
        dry_run: If True, add --relocate-archive-path-dry-run.

    Returns:
        CompletedProcess with stdout/stderr captured as text.
    """
    command = [
        "manager",
        "--relocate-archive-path", old_prefix, new_prefix,
        "--backup-def", "example",
        "--config-file", env.config_file,
        "--log-level", "debug",
        "--log-stdout",
    ]
    if dry_run:
        command.append("--relocate-archive-path-dry-run")

    result = subprocess.run(command, capture_output=True, text=True)
    env.logger.info("relocate stdout:\n%s", result.stdout)
    if result.returncode != 0:
        env.logger.error("relocate stderr:\n%s", result.stderr)
    return result


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_relocate_dry_run_does_not_change_catalog(setup_environment, env):
    """
    --relocate-archive-path-dry-run must exit 0 and must NOT modify the
    catalog: the original backup_dir path must still appear, and the new
    prefix must not appear, in a subsequent dar_manager --list call.
    """
    run_backup_script("--full-backup", env)

    old_prefix = env.backup_dir
    new_prefix = os.path.join(env.test_dir, "moved_backups")

    # Verify old path is in the catalog before we do anything
    listing_before = _catalog_paths(env)
    assert old_prefix in listing_before, (
        f"Expected old_prefix '{old_prefix}' in catalog before dry-run:\n{listing_before}"
    )

    result = _run_relocate(env, old_prefix, new_prefix, dry_run=True)
    assert result.returncode == 0, f"dry-run relocate failed:\n{result.stderr}"

    listing_after = _catalog_paths(env)

    assert old_prefix in listing_after, (
        f"Old prefix '{old_prefix}' disappeared from catalog after dry-run "
        f"(it should not have changed):\n{listing_after}"
    )
    assert new_prefix not in listing_after, (
        f"New prefix '{new_prefix}' appeared in catalog after dry-run "
        f"(it should not have been written):\n{listing_after}"
    )


def test_relocate_rewrites_catalog_paths(setup_environment, env):
    """
    --relocate-archive-path must rewrite the archive directory in the catalog
    DB so that a subsequent dar_manager --list shows the new prefix and no
    longer shows the old prefix.
    """
    run_backup_script("--full-backup", env)

    old_prefix = env.backup_dir
    new_prefix = os.path.join(env.test_dir, "moved_backups")

    # Confirm old path present before relocate
    listing_before = _catalog_paths(env)
    assert old_prefix in listing_before, (
        f"Expected old_prefix '{old_prefix}' in catalog before relocate:\n{listing_before}"
    )

    result = _run_relocate(env, old_prefix, new_prefix, dry_run=False)
    assert result.returncode == 0, f"relocate failed:\n{result.stderr}"

    listing_after = _catalog_paths(env)

    assert new_prefix in listing_after, (
        f"New prefix '{new_prefix}' not found in catalog after relocate:\n{listing_after}"
    )
    assert old_prefix not in listing_after, (
        f"Old prefix '{old_prefix}' still present in catalog after relocate "
        f"(expected it to be replaced):\n{listing_after}"
    )
