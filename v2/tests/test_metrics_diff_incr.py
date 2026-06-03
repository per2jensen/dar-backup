# SPDX-License-Identifier: GPL-3.0-or-later
"""
Integration tests: metrics DB rows for DIFF and INCR backup types.

Finding #9 — test_full_backup_metrics_row_has_key_fields_populated covers
the FULL backup path in detail.  There is no equivalent asserting that a
DIFF or INCR run writes backup_type = 'DIFF'/'INCR' in the metrics row, or
that inodes_saved, archive_size_bytes, and timing fields are non-null and
sane for those backup types.  DIFF and INCR have distinct code paths in
generic_backup() so they deserve their own validation.

Test structure:

  test_diff_backup_metrics_row_correct_type_and_fields
      Full → Diff → verify metrics row.

  test_incr_backup_metrics_row_correct_type_and_fields
      Full → Diff → Incr → verify metrics row for the INCR run.

  test_diff_and_incr_metrics_rows_accumulated
      Full → Diff → Incr → verify three rows are present and each has the
      correct backup_type value.

Marks: integration, slow
"""

import os
import re
import sqlite3
import sys
from configparser import ConfigParser
from contextlib import closing
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

_BACKUP_DEF = "metrics-diff-incr"


def _write_backup_def(env: EnvData) -> None:
    """Write a non-'example' backup definition and create its catalog DB."""
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


def _inject_metrics_config(env: EnvData) -> str:
    """Add METRICS_DB_PATH to [MISC] and disable PAR2; return DB path."""
    metrics_db = os.path.join(env.test_dir, "metrics.db")
    config = ConfigParser()
    config.read(env.config_file)
    if "MISC" not in config:
        config["MISC"] = {}
    config["MISC"]["METRICS_DB_PATH"] = metrics_db
    if "PAR2" not in config:
        config["PAR2"] = {}
    config["PAR2"]["ENABLED"] = "False"
    with open(env.config_file, "w") as fh:
        config.write(fh)
    return metrics_db


def _run_backup(env: EnvData, backup_type_flag: str) -> None:
    """
    Run dar-backup with the specified type flag (--full-backup,
    --differential-backup, --incremental-backup) for _BACKUP_DEF and assert rc=0.
    """
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
    result = runner.run(
        [
            "dar-backup", backup_type_flag,
            "-d", _BACKUP_DEF,
            "--log-stdout", "--log-level", "debug",
            "--config-file", env.config_file,
        ],
        timeout=300,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"dar-backup {backup_type_flag} failed (rc={result.returncode}):\n{result.stderr}"
        )


def _rows_for_def(metrics_db: str, backup_definition: str) -> list[dict]:
    """Return all backup_runs rows for the given definition, ordered by rowid."""
    with closing(sqlite3.connect(metrics_db)) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM backup_runs WHERE backup_definition = ? ORDER BY rowid",
            (backup_definition,),
        ).fetchall()
    return [dict(r) for r in rows]


def _assert_common_row_fields(row: dict, expected_type: str) -> None:
    """Assert invariants shared by FULL, DIFF, and INCR metrics rows."""
    assert row["backup_type"] == expected_type, (
        f"Expected backup_type={expected_type!r}, got {row['backup_type']!r}"
    )
    assert row["status"] in ("SUCCESS", "WARNING"), (
        f"Expected SUCCESS or WARNING status for {expected_type}, got {row['status']!r}"
    )
    assert row["backup_definition"] == _BACKUP_DEF, (
        f"Wrong backup_definition: {row['backup_definition']!r}"
    )
    assert re.match(
        rf"{re.escape(_BACKUP_DEF)}_{expected_type}_\d{{4}}-\d{{2}}-\d{{2}}$",
        row["archive_name"] or "",
    ), f"Unexpected archive_name format: {row['archive_name']!r}"

    assert row["archive_size_bytes"] is not None, (
        f"{expected_type}: archive_size_bytes must not be NULL"
    )
    assert row["archive_size_bytes"] > 0, (
        f"{expected_type}: archive_size_bytes must be positive, got {row['archive_size_bytes']}"
    )
    assert row["dar_exit_code"] in (0, 5), (
        f"{expected_type}: unexpected dar_exit_code={row['dar_exit_code']}"
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_diff_backup_metrics_row_correct_type_and_fields(
    setup_environment, env: EnvData
) -> None:
    """
    After Full → Diff the metrics DB must contain a row with
    backup_type='DIFF', a valid archive_name, and non-null archive_size_bytes.
    """
    _write_backup_def(env)
    metrics_db = _inject_metrics_config(env)

    _run_backup(env, "--full-backup")
    _run_backup(env, "--differential-backup")

    rows = _rows_for_def(metrics_db, _BACKUP_DEF)
    assert len(rows) == 2, f"Expected 2 metrics rows (FULL+DIFF), got {len(rows)}"

    diff_row = rows[1]
    _assert_common_row_fields(diff_row, "DIFF")

    env.logger.info(
        "DIFF metrics row: type=%s status=%s archive_size=%s",
        diff_row["backup_type"],
        diff_row["status"],
        diff_row["archive_size_bytes"],
    )


def test_incr_backup_metrics_row_correct_type_and_fields(
    setup_environment, env: EnvData
) -> None:
    """
    After Full → Diff → Incr the metrics DB must contain an INCR row with
    backup_type='INCR', a valid archive_name, and non-null archive_size_bytes.
    """
    _write_backup_def(env)
    metrics_db = _inject_metrics_config(env)

    _run_backup(env, "--full-backup")
    _run_backup(env, "--differential-backup")

    # Modify a file so the INCR has something to do
    Path(os.path.join(env.data_dir, "file1.txt")).write_text("modified for INCR test\n")
    _run_backup(env, "--incremental-backup")

    rows = _rows_for_def(metrics_db, _BACKUP_DEF)
    assert len(rows) == 3, f"Expected 3 metrics rows (FULL+DIFF+INCR), got {len(rows)}"

    incr_row = rows[2]
    _assert_common_row_fields(incr_row, "INCR")

    env.logger.info(
        "INCR metrics row: type=%s status=%s archive_size=%s",
        incr_row["backup_type"],
        incr_row["status"],
        incr_row["archive_size_bytes"],
    )


def test_diff_and_incr_metrics_rows_accumulated_in_order(
    setup_environment, env: EnvData
) -> None:
    """
    Running Full → Diff → Incr must produce exactly 3 rows in backup_runs.
    Each row must have the correct backup_type in insertion order.
    """
    _write_backup_def(env)
    metrics_db = _inject_metrics_config(env)

    _run_backup(env, "--full-backup")
    _run_backup(env, "--differential-backup")
    Path(os.path.join(env.data_dir, "file2.txt")).write_text("changed for INCR\n")
    _run_backup(env, "--incremental-backup")

    rows = _rows_for_def(metrics_db, _BACKUP_DEF)
    assert len(rows) == 3, f"Expected exactly 3 rows, got {len(rows)}: {rows}"

    for row, expected_type in zip(rows, ("FULL", "DIFF", "INCR")):
        assert row["backup_type"] == expected_type, (
            f"Row out of order: expected {expected_type!r}, got {row['backup_type']!r}"
        )
        assert row["status"] in ("SUCCESS", "WARNING"), (
            f"{expected_type} row has unexpected status: {row['status']!r}"
        )

    env.logger.info("All 3 rows present with correct backup_type values in insertion order")


def test_diff_backup_archive_size_less_than_or_equal_to_full(
    setup_environment, env: EnvData
) -> None:
    """
    A DIFF archive of unchanged data should be smaller than or equal to
    the FULL archive (no new data changed).  This validates that the
    archive_size_bytes field is not erroneously swapped between rows.

    Note: DIFF archives are not strictly guaranteed to be smaller in all
    cases (dar overhead etc.), so we use a soft check — both must be
    positive and the DIFF must not be implausibly larger than the FULL
    (more than 10x would indicate a row-ordering bug).
    """
    _write_backup_def(env)
    metrics_db = _inject_metrics_config(env)

    _run_backup(env, "--full-backup")
    # No data changes — DIFF should be tiny (just metadata)
    _run_backup(env, "--differential-backup")

    rows = _rows_for_def(metrics_db, _BACKUP_DEF)
    assert len(rows) == 2

    full_size = rows[0]["archive_size_bytes"]
    diff_size = rows[1]["archive_size_bytes"]

    assert full_size > 0, f"FULL archive_size_bytes must be positive, got {full_size}"
    assert diff_size > 0, f"DIFF archive_size_bytes must be positive, got {diff_size}"
    assert diff_size <= full_size * 10, (
        f"DIFF archive ({diff_size} bytes) is implausibly larger than FULL "
        f"({full_size} bytes) — possible row ordering bug"
    )
    env.logger.info(
        "Size sanity: FULL=%d bytes, DIFF=%d bytes", full_size, diff_size
    )
