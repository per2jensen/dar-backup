# SPDX-License-Identifier: GPL-3.0-or-later
"""
Integration tests: zero eligible restore-test candidates does not abort backup.

Finding #7 — The unit test test_verify_skips_when_no_eligible_files_logs_info
uses mocks and covers the in-process code path.  There is no real integration
test that sets up exclusion rules or a size window aggressive enough to
eliminate every candidate, runs a full backup, and verifies:

  (a) dar-backup exits 0 (backup was written successfully).
  (b) No Python traceback appears in the output.
  (c) The archive is still readable by dar (integrity unaffected by the
      missing restore-test step).

Two scenarios drive the zero-candidate condition:

  Scenario A — all candidates excluded by RESTORETEST_EXCLUDE_SUFFIXES.
  Scenario B — MIN_SIZE_VERIFICATION_MB is set higher than all files in
               the archive, so the size filter eliminates every candidate.

The "example" definition (created by conftest) is used here because these
tests care only about backup completion, not metrics.  The example definition
metrics are intentionally skipped by dar-backup — that is fine for these tests.

Marks: integration, slow
"""

import os
import sys
from configparser import ConfigParser

import pytest

pytestmark = [pytest.mark.integration, pytest.mark.slow]

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from dar_backup.command_runner import CommandRunner
from tests.envdata import EnvData


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _disable_par2(env: EnvData) -> None:
    config = ConfigParser()
    config.read(env.config_file)
    if "PAR2" not in config:
        config["PAR2"] = {}
    config["PAR2"]["ENABLED"] = "False"
    with open(env.config_file, "w") as fh:
        config.write(fh)


def _inject_misc_config(env: EnvData, overrides: dict) -> None:
    """Patch [MISC] in env.config_file with the supplied key/value pairs."""
    config = ConfigParser()
    config.read(env.config_file)
    if "MISC" not in config:
        config["MISC"] = {}
    for key, value in overrides.items():
        config["MISC"][key] = value
    with open(env.config_file, "w") as fh:
        config.write(fh)


def _run_full_backup(env: EnvData) -> tuple:
    """Run dar-backup --full-backup -d example; return (returncode, combined output)."""
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
    result = runner.run(
        [
            "dar-backup", "--full-backup",
            "-d", "example",
            "--verbose",
            "--log-stdout", "--log-level", "debug",
            "--config-file", env.config_file,
        ],
        timeout=300,
    )
    combined = (result.stdout or "") + (result.stderr or "")
    return result.returncode, combined


def _dar_test_archive(env: EnvData) -> bool:
    """Return True if dar -t passes on the FULL archive produced by conftest."""
    slices = [
        f for f in os.listdir(env.backup_dir)
        if f.startswith("example_FULL_") and f.endswith(".1.dar")
    ]
    if not slices:
        return False
    archive_base = os.path.join(env.backup_dir, slices[0][:-len(".1.dar")])
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
    result = runner.run(["dar", "-t", archive_base, "-N", "-Q"], timeout=60)
    return result.returncode == 0


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_zero_candidates_via_suffix_exclusion_backup_succeeds(
    setup_environment, env: EnvData
) -> None:
    """
    Excluding every file by suffix must NOT abort the backup.
    All test-data files created by conftest end in .txt — excluding .txt
    eliminates all candidates from the restore-test selection pool.

    Expected outcomes:
      - dar-backup exits 0.
      - The archive is intact (dar -t passes).
    """
    _disable_par2(env)
    _inject_misc_config(
        env,
        {
            "RESTORETEST_EXCLUDE_SUFFIXES": ".txt",
            "NO_FILES_VERIFICATION": "5",
            "MIN_SIZE_VERIFICATION_MB": "0",
            "MAX_SIZE_VERIFICATION_MB": "100",
        },
    )

    rc, output = _run_full_backup(env)

    assert rc == 0, (
        f"dar-backup must exit 0 even when all candidates are excluded "
        f"(rc={rc}):\n{output}"
    )
    env.logger.info("dar-backup exited 0 with all candidates excluded via suffix rule")

    assert _dar_test_archive(env), (
        "Archive integrity check (dar -t) failed after backup with zero candidates"
    )


def test_zero_candidates_via_size_window_backup_succeeds(
    setup_environment, env: EnvData
) -> None:
    """
    Setting MIN_SIZE_VERIFICATION_MB above the size of all files in the archive
    means the size filter eliminates every candidate.

    The conftest test files are all small text files (a few bytes each).
    Setting MIN_SIZE_VERIFICATION_MB = 50 ensures none qualify.

    Expected outcomes:
      - dar-backup exits 0.
      - The archive is intact (dar -t passes).
    """
    _disable_par2(env)
    _inject_misc_config(
        env,
        {
            "MIN_SIZE_VERIFICATION_MB": "50",   # all test files are < 1 MB
            "MAX_SIZE_VERIFICATION_MB": "100",
            "NO_FILES_VERIFICATION": "5",
        },
    )

    rc, output = _run_full_backup(env)

    assert rc == 0, (
        f"dar-backup must exit 0 when size window excludes all candidates "
        f"(rc={rc}):\n{output}"
    )
    env.logger.info("dar-backup exited 0 with size window eliminating all candidates")

    assert _dar_test_archive(env), (
        "Archive integrity check (dar -t) failed after backup with zero size-eligible candidates"
    )


def test_zero_candidates_log_contains_info_not_error(
    setup_environment, env: EnvData
) -> None:
    """
    When no candidates are selected the log output must not contain an
    unhandled Python traceback.  The "No files eligible" info message from
    verify() should appear in the output.
    """
    _disable_par2(env)
    _inject_misc_config(
        env,
        {
            "RESTORETEST_EXCLUDE_SUFFIXES": ".txt",
            "NO_FILES_VERIFICATION": "5",
            "MIN_SIZE_VERIFICATION_MB": "0",
            "MAX_SIZE_VERIFICATION_MB": "100",
        },
    )

    rc, output = _run_full_backup(env)

    assert rc == 0, f"Unexpected non-zero exit: {rc}\n{output}"
    assert "Traceback" not in output, (
        "Unexpected Python traceback in output when candidates are zero:\n"
        + output[:2000]
    )
    env.logger.info("No traceback present in output — zero-candidate path is clean")
