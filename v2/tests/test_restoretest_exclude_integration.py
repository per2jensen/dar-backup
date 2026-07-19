# SPDX-License-Identifier: GPL-3.0-or-later
"""
Integration tests: RESTORETEST_EXCLUDE_* config keys in a real backup run.

Finding #1 — The unit tests for the restore-test exclusion logic
(select_restoretest_samples / _is_restoretest_candidate) are thorough,
but no integration test puts RESTORETEST_EXCLUDE_PREFIXES, SUFFIXES, and
REGEX in an actual config file, runs a full backup, and asserts that those
paths are never selected as restore-test candidates.

These tests drive real dar and par2 binaries against a filesystem that
contains files in excluded paths and verify through the --log-stdout output
that:

  - Files whose paths match an exclusion rule never appear in
    "Restoring file:" log lines (which dar-backup emits for every file
    it selects for a restore-test).
  - Files in non-excluded paths do appear (so the exclusions are not
    accidentally swallowing everything).
  - When every candidate is excluded the backup still completes with
    returncode 0 and does not raise an unhandled exception.

Verification strategy: parse --log-stdout output for "Restoring file:" lines.
These lines are emitted at INFO level when --verbose is passed (which
run_backup_script already does).  No metrics DB is required.

Marks: integration, slow
"""

import os
import re
import sys
from configparser import ConfigParser
from pathlib import Path

import pytest

pytestmark = [pytest.mark.integration, pytest.mark.slow]

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from dar_backup.command_runner import CommandRunner
from tests.envdata import EnvData


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_BACKUP_DEF = "excl-test"


def _write_backup_def(env: EnvData) -> None:
    """Write a backup definition that captures data_dir and creates the catalog."""
    def_path = os.path.join(env.backup_d_dir, _BACKUP_DEF)
    Path(def_path).write_text(
        "-R /\n-s 10G\n-z6\n-am\n--cache-directory-tagging\n"
        f"-g {env.data_dir.lstrip('/')}\n"
    )
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
    result = runner.run(
        ["manager", "--create-db", "--config-file", env.config_file, "--log-stdout"],
        timeout=30,
    )
    if result.returncode != 0:
        raise RuntimeError(f"manager --create-db failed: {result.stderr}")


def _inject_misc_config(env: EnvData, overrides: dict) -> None:
    """Patch [MISC] in env.config_file with the supplied key/value pairs."""
    config = ConfigParser()
    config.read(env.config_file)
    if "MISC" not in config:
        config["MISC"] = {}
    for key, value in overrides.items():
        config["MISC"][key] = value
    # Disable PAR2 to keep tests fast
    if "PAR2" not in config:
        config["PAR2"] = {}
    config["PAR2"]["ENABLED"] = "False"
    with open(env.config_file, "w") as fh:
        config.write(fh)


def _create_mixed_tree(env: EnvData) -> None:
    """
    Populate data_dir with files in both excluded and non-excluded paths:

      normal/keep.txt          — must NOT be excluded (plain file, safe suffix)
      .cache/cached.sqlite-wal — excluded by prefix (.cache/) and suffix (.sqlite-wal)
      logs/app.log             — excluded by prefix (logs/) and suffix (.log)
      Cache/thumb.dat          — excluded by regex (case-insensitive Cache/ dir)
    """
    data = env.data_dir

    normal_dir = os.path.join(data, "normal")
    os.makedirs(normal_dir, exist_ok=True)
    Path(os.path.join(normal_dir, "keep.txt")).write_text(
        "I must be a restore-test candidate.\n"
    )

    cache_dir = os.path.join(data, ".cache")
    os.makedirs(cache_dir, exist_ok=True)
    Path(os.path.join(cache_dir, "cached.sqlite-wal")).write_bytes(os.urandom(2048))

    log_dir = os.path.join(data, "logs")
    os.makedirs(log_dir, exist_ok=True)
    Path(os.path.join(log_dir, "app.log")).write_text("log line\n" * 50)

    regex_dir = os.path.join(data, "Cache")
    os.makedirs(regex_dir, exist_ok=True)
    Path(os.path.join(regex_dir, "thumb.dat")).write_bytes(os.urandom(512))


def _run_backup(env: EnvData, definition: str = _BACKUP_DEF) -> str:
    """
    Run dar-backup --full-backup with --verbose and return the combined stdout+stderr.
    Raises RuntimeError on non-zero exit.
    """
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
    result = runner.run(
        [
            "dar-backup", "--full-backup",
            "-d", definition,
            "--verbose",
            "--log-stdout", "--log-level", "debug",
            "--config-file", env.config_file,
        ],
        timeout=300,
    )
    combined = (result.stdout or "") + (result.stderr or "")
    if result.returncode != 0:
        raise RuntimeError(
            f"dar-backup exited {result.returncode}:\n{combined}"
        )
    return combined


def _restoring_file_paths(output: str) -> list:
    """
    Extract file paths from all "Restoring file: '<path>'" log lines.
    Returns a list of path strings (without the surrounding quotes).
    """
    return re.findall(r"Restoring file: '([^']+)'", output)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_restoretest_exclude_prefixes_and_suffixes_end_to_end(
    setup_environment, env: EnvData
) -> None:
    """
    Files under .cache/ and logs/ and those ending in .log or .sqlite-wal must
    never appear in "Restoring file:" log entries when the corresponding
    EXCLUDE config keys are set.  A normal file in normal/ must still be selected.
    """
    _create_mixed_tree(env)
    _write_backup_def(env)
    _inject_misc_config(
        env,
        {
            "RESTORETEST_EXCLUDE_PREFIXES": ".cache/, logs/",
            "RESTORETEST_EXCLUDE_SUFFIXES": ".sqlite-wal, .log",
            "NO_FILES_VERIFICATION": "10",
            "MIN_SIZE_VERIFICATION_MB": "0",
            "MAX_SIZE_VERIFICATION_MB": "100",
        },
    )

    output = _run_backup(env)
    selected = _restoring_file_paths(output)
    env.logger.info("Selected restore-test paths: %s", selected)

    # Must have selected at least the keep.txt file
    assert selected, (
        "Expected at least one file to be selected for restore-test, got none.\n"
        "Check that normal/keep.txt passes size and exclusion filters."
    )

    for path in selected:
        norm = path.lstrip("/")
        assert not norm.endswith(".sqlite-wal"), (
            f"Excluded suffix .sqlite-wal leaked into restore-test selection: {path}"
        )
        assert not norm.endswith(".log"), (
            f"Excluded suffix .log leaked into restore-test selection: {path}"
        )
        # Check prefix exclusions relative to data_dir
        try:
            data_rel = os.path.relpath(norm, env.data_dir.lstrip("/"))
        except ValueError:
            data_rel = norm
        assert not data_rel.startswith(".cache/"), (
            f"Excluded prefix .cache/ leaked into restore-test selection: {path}"
        )
        assert not data_rel.startswith("logs/"), (
            f"Excluded prefix logs/ leaked into restore-test selection: {path}"
        )


def test_restoretest_exclude_regex_end_to_end(
    setup_environment, env: EnvData
) -> None:
    """
    Files under any directory matching the regex (^|/)(Cache|cache)/ must be
    excluded from restore-test candidates — verified via log output.
    """
    _create_mixed_tree(env)
    _write_backup_def(env)
    _inject_misc_config(
        env,
        {
            "RESTORETEST_EXCLUDE_REGEX": r"(^|/)(Cache|cache)/",
            "NO_FILES_VERIFICATION": "10",
            "MIN_SIZE_VERIFICATION_MB": "0",
            "MAX_SIZE_VERIFICATION_MB": "100",
        },
    )

    output = _run_backup(env)
    selected = _restoring_file_paths(output)
    env.logger.info("Selected restore-test paths: %s", selected)

    regex = re.compile(r"(^|/)(Cache|cache)/")
    for path in selected:
        assert not regex.search(path), (
            f"Regex-excluded path (Cache/) leaked into restore-test selection: {path}"
        )


def test_restoretest_exclude_all_candidates_backup_still_succeeds(
    setup_environment, env: EnvData
) -> None:
    """
    When every file in the archive matches an exclusion rule the backup must
    complete with returncode 0 — no abort, no unhandled exception.

    All test-data files created by conftest end in .txt — excluding .txt
    eliminates all candidates.  We use the "example" definition (all .txt
    files) and verify only rc=0 and absence of a Python traceback.
    """
    _inject_misc_config(
        env,
        {
            "RESTORETEST_EXCLUDE_SUFFIXES": ".txt",
            "NO_FILES_VERIFICATION": "10",
            "MIN_SIZE_VERIFICATION_MB": "0",
            "MAX_SIZE_VERIFICATION_MB": "100",
        },
    )

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

    assert result.returncode == 0, (
        f"dar-backup must exit 0 even when all candidates are excluded "
        f"(rc={result.returncode}):\n{combined}"
    )
    assert "Traceback" not in combined, (
        "Unexpected Python traceback when all restore-test candidates are excluded:\n"
        + combined[:2000]
    )
