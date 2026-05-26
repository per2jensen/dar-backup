# SPDX-License-Identifier: GPL-3.0-or-later
"""
Smoke integration tests: metrics DB end-to-end write and field validation.

A single FULL backup is run; the resulting SQLite row is checked for fields
not validated at smoke level in any existing test: archive_name,
archive_size_bytes, dar_exit_code, and hostname.

Marks: integration, smoke
"""

import os
import re
import socket
import sqlite3
import sys
from pathlib import Path

import pytest

pytestmark = [pytest.mark.integration, pytest.mark.smoke]

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from dar_backup.command_runner import CommandRunner
from envdata import EnvData


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_BACKUP_DEF = "metrics-smoke"


def _inject_metrics_db(env: EnvData) -> str:
    """Insert METRICS_DB_PATH into the [MISC] section of env.config_file.

    Args:
        env: Test environment.

    Returns:
        Absolute path to the metrics DB file that will be created.

    Raises:
        RuntimeError: If [MISC] section is absent from the config file.
    """
    metrics_db = os.path.join(env.test_dir, "metrics.db")
    content = Path(env.config_file).read_text()
    if "[MISC]\n" not in content:
        raise RuntimeError(f"[MISC] section not found in {env.config_file}")
    Path(env.config_file).write_text(
        content.replace("[MISC]\n", f"[MISC]\nMETRICS_DB_PATH = {metrics_db}\n", 1)
    )
    return metrics_db


def _create_backup_def(env: EnvData) -> None:
    """Write the metrics-smoke backup definition and create its catalog DB.

    Uses a non-"example" name so dar-backup does not skip metrics collection.

    Args:
        env: Test environment.

    Raises:
        RuntimeError: If manager --create-db exits non-zero.
    """
    Path(os.path.join(env.backup_d_dir, _BACKUP_DEF)).write_text(
        "-R /\n-s 10G\n-z6\n-am\n--cache-directory-tagging\n"
        f"-g {env.data_dir.lstrip('/')}\n"
    )
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
    result = runner.run(
        ["manager", "--create-db", "--config-file", env.config_file, "--log-stdout"],
        timeout=30,
    )
    if result.returncode != 0:
        raise RuntimeError(f"manager --create-db failed (rc={result.returncode}): {result.stderr}")


def _run_full_backup(env: EnvData) -> None:
    """Run dar-backup --full-backup for the metrics-smoke definition.

    Args:
        env: Test environment.

    Raises:
        RuntimeError: If dar-backup exits non-zero.
    """
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
    result = runner.run(
        [
            "dar-backup", "--full-backup",
            "-d", _BACKUP_DEF,
            "--log-stdout", "--log-level", "debug",
            "--config-file", env.config_file,
        ],
        timeout=300,
    )
    if result.returncode != 0:
        raise RuntimeError(f"dar-backup exited {result.returncode}: {result.stderr}")


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_full_backup_metrics_row_has_key_fields_populated(
    setup_environment, env: EnvData
) -> None:
    """FULL backup must write a row with correct archive_name, archive_size_bytes,
    dar_exit_code, and hostname — fields not checked at smoke level elsewhere.
    """
    metrics_db = _inject_metrics_db(env)
    _create_backup_def(env)
    _run_full_backup(env)

    assert os.path.exists(metrics_db), f"Metrics DB not created at {metrics_db}"

    with sqlite3.connect(metrics_db) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT * FROM backup_runs").fetchall()

    assert len(rows) == 1, f"Expected 1 metrics row, got {len(rows)}"
    row = dict(rows[0])

    assert row["backup_type"] == "FULL", f"backup_type: {row['backup_type']}"
    assert row["status"] in ("SUCCESS", "WARNING"), f"status: {row['status']}"
    assert row["dar_exit_code"] in (0, 5), f"dar_exit_code: {row['dar_exit_code']}"
    assert row["hostname"] == socket.gethostname(), f"hostname: {row['hostname']}"

    assert row["archive_name"], "archive_name must not be empty"
    assert re.match(
        r"metrics-smoke_FULL_\d{4}-\d{2}-\d{2}$", row["archive_name"]
    ), f"Unexpected archive_name format: {row['archive_name']}"

    assert row["archive_size_bytes"] is not None, "archive_size_bytes must not be NULL"
    assert row["archive_size_bytes"] > 0, (
        f"archive_size_bytes must be positive, got {row['archive_size_bytes']}"
    )


def test_full_backup_writes_restore_test_samples(
    setup_environment, env: EnvData
) -> None:
    """A FULL backup must write at least one restore_test_samples row with
    run_id matching backup_runs, result='PASS', and non-null file_size_bytes.
    """
    metrics_db = _inject_metrics_db(env)
    _create_backup_def(env)
    _run_full_backup(env)

    with sqlite3.connect(metrics_db) as conn:
        conn.row_factory = sqlite3.Row

        run_row = dict(conn.execute("SELECT run_id FROM backup_runs").fetchone())
        run_id = run_row["run_id"]

        samples = conn.execute(
            "SELECT * FROM restore_test_samples WHERE run_id = ?", (run_id,)
        ).fetchall()

    assert len(samples) >= 1, "Expected at least one restore_test_samples row"

    for s in samples:
        row = dict(s)
        assert row["run_id"]            == run_id
        assert row["backup_definition"] == _BACKUP_DEF
        assert re.match(r"metrics-smoke_FULL_\d{4}-\d{2}-\d{2}$", row["archive_name"]), (
            f"Unexpected archive_name: {row['archive_name']}"
        )
        assert row["file_path"],                    "file_path must not be empty"
        assert row["file_size_bytes"] is not None,  "file_size_bytes must not be NULL"
        assert row["file_size_bytes"] >= 0,         f"file_size_bytes negative: {row['file_size_bytes']}"
        assert row["result"] == "PASS",             f"Expected PASS, got {row['result']}"
        assert row["fail_reason_id"] is None,       "PASS row must have null fail_reason_id"
        assert row["tested_at"],                    "tested_at must not be empty"
