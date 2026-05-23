#!/usr/bin/env python3
"""
Integration tests for list_backups() exercised through `cleanup --list`.

The tests create real dar archives via `dar-backup --full-backup` (and
optionally DIFF/INCR), then invoke `cleanup --list` as a subprocess. The
output of list_backups() goes to stdout via print(); by omitting
--log-stdout the log messages are kept in the log file, so stdout contains
only the table produced by list_backups().

Scenarios:
  - FULL + DIFF + INCR archives all appear with a parseable size column
  - A --backup-definition filter that matches nothing yields "No backups available."
"""

import os
import re
import subprocess
import sys

import pytest

pytestmark = pytest.mark.integration

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from tests.testdata_verification import run_backup_script


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _run_list(env, backup_def: str = None) -> subprocess.CompletedProcess:
    """
    Run `cleanup --list` and return the CompletedProcess.

    Logging is intentionally NOT sent to stdout so that the only stdout
    content is the table printed by list_backups().

    Args:
        env: EnvData fixture.
        backup_def: Optional value for -d / --backup-definition.

    Returns:
        CompletedProcess with stdout/stderr captured as text.
    """
    command = [
        "cleanup",
        "--list",
        "--config-file", env.config_file,
    ]
    if backup_def is not None:
        command.extend(["-d", backup_def])

    result = subprocess.run(command, capture_output=True, text=True)
    env.logger.info("list stdout:\n%s", result.stdout)
    if result.returncode != 0:
        env.logger.error("list stderr:\n%s", result.stderr)
    return result


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_list_backups_shows_all_archive_types(setup_environment, env):
    """
    list_backups must display FULL, DIFF, and INCR archives with a
    parseable size column when real dar archives exist on disk.

    The size column is verified to be a non-negative integer (archives
    created from small test data are typically < 1 MB, so 0 MB is allowed).
    """
    run_backup_script("--full-backup", env)
    run_backup_script("--differential-backup", env)
    run_backup_script("--incremental-backup", env)

    result = _run_list(env, backup_def="example")
    assert result.returncode == 0, f"cleanup --list failed:\n{result.stderr}"

    output = result.stdout

    # Each archive type must appear by name
    for backup_type in ("FULL", "DIFF", "INCR"):
        expected_prefix = f"example_{backup_type}_{env.datestamp}"
        assert expected_prefix in output, (
            f"'{expected_prefix}' not found in list output:\n{output}"
        )

    # Each line that contains an archive name must also have a size column
    # matching the format:  "example_<TYPE>_<date>... : <digits> MB"
    size_line = re.compile(
        r"example_(?:FULL|DIFF|INCR)_\S+\s+:\s+(\d+)\s+MB"
    )
    matches = size_line.findall(output)
    assert len(matches) >= 3, (
        f"Expected at least 3 size entries in output, found {len(matches)}:\n{output}"
    )
    for size_str in matches:
        assert int(size_str) >= 0, f"Negative size in output: {size_str} MB"


def test_list_backups_no_match_prints_empty_message(setup_environment, env):
    """
    When the --backup-definition filter matches no archives, list_backups
    must print 'No backups available.' to stdout.

    A real FULL backup is created first so the backup directory is populated,
    proving the filter (not an empty directory) is responsible for the message.
    """
    run_backup_script("--full-backup", env)

    result = _run_list(env, backup_def="nonexistent_definition")
    assert result.returncode == 0, f"cleanup --list failed:\n{result.stderr}"

    assert "No backups available." in result.stdout, (
        f"Expected 'No backups available.' in stdout, got:\n{result.stdout}"
    )

    # Confirm the real archive does NOT appear (filter worked)
    assert f"example_FULL_{env.datestamp}" not in result.stdout, (
        f"Real FULL archive leaked into filtered output:\n{result.stdout}"
    )
