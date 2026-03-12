# SPDX-License-Identifier: GPL-3.0-or-later
"""
Integration tests: FULL → DIFF → INCR backups verify inode counts in metrics DB.

These tests run dar-backup end-to-end and then query the SQLite metrics DB
to assert that the inode counters (inodes_saved, inodes_total, etc.) and the
hostname field are correctly populated.

Marks: integration, slow
"""

import os
import shutil
import socket
import sqlite3
import sys
from pathlib import Path
from typing import Optional

import pytest

# ---------------------------------------------------------------------------
# Make project importable when run directly
# ---------------------------------------------------------------------------
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from dar_backup.command_runner import CommandRunner, CommandResult
from envdata import EnvData

pytestmark = [pytest.mark.integration, pytest.mark.slow]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _inject_metrics_db_path(env: EnvData) -> str:
    """
    Insert ``METRICS_DB_PATH`` into the ``[MISC]`` section of env.config_file
    using a direct text substitution to preserve all comments and key casing.

    Returns:
        Absolute path to the metrics DB file that will be created.
    """
    metrics_db = os.path.join(env.test_dir, "metrics.db")
    with open(env.config_file) as fh:
        content = fh.read()

    # Insert immediately after the [MISC] section header (first occurrence)
    if "[MISC]\n" not in content:
        raise RuntimeError(f"[MISC] section not found in {env.config_file}")
    content = content.replace(
        "[MISC]\n",
        f"[MISC]\nMETRICS_DB_PATH = {metrics_db}\n",
        1,
    )
    with open(env.config_file, "w") as fh:
        fh.write(content)

    env.logger.info("Injected METRICS_DB_PATH = %s into config", metrics_db)
    return metrics_db


def _query_backup_rows(db_path: str, backup_type: Optional[str] = None) -> list[dict]:
    """
    Return all rows from backup_runs, optionally filtered by backup_type.

    Args:
        db_path:     Path to the SQLite metrics DB.
        backup_type: 'FULL', 'DIFF', or 'INCR'; None means all rows.

    Returns:
        List of row dicts ordered by rowid ascending.
    """
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        if backup_type:
            rows = conn.execute(
                "SELECT * FROM backup_runs WHERE backup_type = ? ORDER BY rowid",
                (backup_type,),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM backup_runs ORDER BY rowid"
            ).fetchall()
    return [dict(r) for r in rows]


_BACKUP_DEF_NAME = "metrics-test"


def _create_metrics_backup_definition(env: EnvData) -> None:
    """
    Write a dar backup definition named ``metrics-test`` pointing at env.data_dir
    and create its catalog DB.

    Using a name other than ``example`` is required — dar-backup explicitly skips
    metrics collection for the ``example`` definition (it is a demo definition).
    """
    dcf_path = os.path.join(env.backup_d_dir, _BACKUP_DEF_NAME)
    # dar does not allow a leading "/" in -g paths
    data_path = env.data_dir.lstrip("/")
    content = (
        "-R /\n"
        "-s 10G\n"
        "-z6\n"
        "-am\n"
        "--cache-directory-tagging\n"
        f"-g {data_path}\n"
    )
    Path(dcf_path).write_text(content)
    env.logger.info("Created backup definition: %s", dcf_path)

    # Create the catalog DB for this definition
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
    command = [
        "manager", "--create-db",
        "--config-file", env.config_file,
        "--log-level", "debug",
        "--log-stdout",
    ]
    result = runner.run(command, timeout=30)
    if result.returncode != 0:
        raise RuntimeError(
            f"manager --create-db failed (rc={result.returncode}): {result.stderr}"
        )
    env.logger.info("Catalog DB created for backup definition: %s", _BACKUP_DEF_NAME)


def _run_backup(backup_type: str, env: EnvData) -> CommandResult:
    """
    Run dar-backup with the metrics-test backup definition.

    Args:
        backup_type: CLI flag, e.g. ``--full-backup`` / ``-F``, ``-D``, ``-I``.
        env:         Test environment.

    Returns:
        CommandResult from the backup run.

    Raises:
        Exception: If dar-backup exits non-zero.
    """
    command = [
        "dar-backup", backup_type,
        "-d", _BACKUP_DEF_NAME,
        "--verbose",
        "--log-level", "debug",
        "--log-stdout",
        "--config-file", env.config_file,
    ]
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
    result: CommandResult = runner.run(command, timeout=300)
    if result.returncode != 0:
        env.logger.error("Backup command failed: %s", command)
        env.logger.error("stderr: %s", result.stderr)
        raise RuntimeError(f"dar-backup exited {result.returncode}: {command}")
    return result


def _create_extra_testdata(env: EnvData) -> dict[str, int]:
    """
    Create a controlled set of additional inodes in env.data_dir:
      - a subdirectory 'subdir' with 3 files
      - 2 symbolic links

    Returns a dict describing what was created so the caller can update
    expectations as the test progresses.
    """
    subdir = os.path.join(env.data_dir, "subdir")
    os.makedirs(subdir, exist_ok=True)
    for i in range(1, 4):
        Path(os.path.join(subdir, f"sub_{i}.txt")).write_text(f"subdir file {i}")

    # Symlinks inside data_dir
    target = os.path.join(env.data_dir, "file1.txt")
    Path(os.path.join(env.data_dir, "link1.txt")).symlink_to(target)
    Path(os.path.join(env.data_dir, "link2.txt")).symlink_to(target)

    return {"subdir_files": 3, "symlinks": 2}


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestMetricsInodeCounts:
    """End-to-end FULL / DIFF / INCR backup inode-count metrics tests."""

    def test_full_backup_populates_inode_metrics(self, setup_environment, env):
        """
        FULL backup of files + subdirectory + symlinks must write a metrics row
        with a non-zero hostname, inodes_saved, and inodes_total.
        """
        metrics_db = _inject_metrics_db_path(env)
        _create_metrics_backup_definition(env)

        # Add subdirectory + symlinks on top of the conftest-created test files
        _create_extra_testdata(env)

        _run_backup("--full-backup", env)

        assert os.path.exists(metrics_db), (
            f"Metrics DB was not created at {metrics_db} — check that METRICS_DB_PATH "
            f"was injected into the config correctly"
        )
        rows = _query_backup_rows(metrics_db, "FULL")
        assert len(rows) == 1, "Expected exactly one FULL backup row"
        row = rows[0]

        assert row["hostname"] == socket.gethostname(), "hostname must match current host"
        assert row["backup_type"] == "FULL"
        assert row["status"] in ("SUCCESS", "WARNING"), f"Unexpected status: {row['status']}"

        # The dar backup includes data_dir itself, subdirectory, all files, and symlinks.
        # conftest creates 9 files; we add 1 subdir + 3 subdir files + 2 symlinks = 15 min.
        assert row["inodes_saved"] is not None, "inodes_saved must not be NULL for FULL backup"
        assert row["inodes_saved"] >= 15, (
            f"Expected at least 15 inodes saved, got {row['inodes_saved']}"
        )

        assert row["inodes_total"] is not None, "inodes_total must not be NULL"
        assert row["inodes_total"] >= row["inodes_saved"], (
            "inodes_total must be >= inodes_saved"
        )

        env.logger.info(
            "FULL backup metrics: inodes_saved=%s inodes_total=%s hostname=%s",
            row["inodes_saved"],
            row["inodes_total"],
            row["hostname"],
        )


    def test_diff_backup_reflects_new_files(self, setup_environment, env):
        """
        After a FULL backup, adding new files and running a DIFF backup must
        produce a metrics row where inodes_saved reflects at least the new files,
        and inodes_not_saved reflects the unchanged files.
        """
        metrics_db = _inject_metrics_db_path(env)
        _create_metrics_backup_definition(env)
        _create_extra_testdata(env)

        # Establish baseline FULL backup
        _run_backup("--full-backup", env)

        # Add new files that will be picked up by the DIFF
        new_files = ["diff_new_1.txt", "diff_new_2.txt", "diff_new_3.txt"]
        for fname in new_files:
            Path(os.path.join(env.data_dir, fname)).write_text(f"diff content: {fname}")

        _run_backup("-D", env)

        assert os.path.exists(metrics_db), f"Metrics DB not created at {metrics_db}"
        diff_rows = _query_backup_rows(metrics_db, "DIFF")
        assert len(diff_rows) == 1, "Expected exactly one DIFF backup row"
        row = diff_rows[0]

        assert row["hostname"] == socket.gethostname()
        assert row["backup_type"] == "DIFF"
        assert row["status"] in ("SUCCESS", "WARNING"), f"Unexpected status: {row['status']}"

        assert row["inodes_saved"] is not None, "inodes_saved must not be NULL for DIFF"
        assert row["inodes_saved"] >= len(new_files), (
            f"DIFF inodes_saved={row['inodes_saved']} must be >= {len(new_files)} new files"
        )

        assert row["inodes_not_saved"] is not None, "inodes_not_saved must not be NULL for DIFF"
        assert row["inodes_not_saved"] > 0, (
            "DIFF must report unchanged inodes in inodes_not_saved"
        )

        assert row["inodes_total"] is not None
        assert row["inodes_total"] >= row["inodes_saved"]

        env.logger.info(
            "DIFF backup metrics: inodes_saved=%s inodes_not_saved=%s inodes_total=%s",
            row["inodes_saved"],
            row["inodes_not_saved"],
            row["inodes_total"],
        )


    def test_incr_backup_reflects_new_files(self, setup_environment, env):
        """
        After FULL → DIFF, adding new files and running an INCR backup must
        produce a metrics row where inodes_saved >= the number of newly added files.
        """
        metrics_db = _inject_metrics_db_path(env)
        _create_metrics_backup_definition(env)
        _create_extra_testdata(env)

        # Establish FULL
        _run_backup("--full-backup", env)

        # DIFF baseline (add a couple files so it's not empty)
        Path(os.path.join(env.data_dir, "diff_file.txt")).write_text("diff baseline")
        _run_backup("-D", env)

        # Add new files for INCR
        new_files = ["incr_new_1.txt", "incr_new_2.txt"]
        for fname in new_files:
            Path(os.path.join(env.data_dir, fname)).write_text(f"incr content: {fname}")

        _run_backup("-I", env)

        assert os.path.exists(metrics_db), f"Metrics DB not created at {metrics_db}"
        incr_rows = _query_backup_rows(metrics_db, "INCR")
        assert len(incr_rows) == 1, "Expected exactly one INCR backup row"
        row = incr_rows[0]

        assert row["hostname"] == socket.gethostname()
        assert row["backup_type"] == "INCR"
        assert row["status"] in ("SUCCESS", "WARNING"), f"Unexpected status: {row['status']}"

        assert row["inodes_saved"] is not None, "inodes_saved must not be NULL for INCR"
        assert row["inodes_saved"] >= len(new_files), (
            f"INCR inodes_saved={row['inodes_saved']} must be >= {len(new_files)} new files"
        )

        assert row["inodes_not_saved"] is not None
        assert row["inodes_not_saved"] > 0, (
            "INCR must report unchanged inodes in inodes_not_saved"
        )

        assert row["inodes_total"] is not None
        assert row["inodes_total"] >= row["inodes_saved"]

        env.logger.info(
            "INCR backup metrics: inodes_saved=%s inodes_not_saved=%s inodes_total=%s",
            row["inodes_saved"],
            row["inodes_not_saved"],
            row["inodes_total"],
        )


    def test_full_backup_symlinks_counted(self, setup_environment, env):
        """
        Symbolic links are real inodes and must be counted in inodes_total.
        The FULL backup inodes_total must exceed just the plain file count,
        confirming symlinks (and the directory itself) are included.
        """
        metrics_db = _inject_metrics_db_path(env)
        _create_metrics_backup_definition(env)
        created = _create_extra_testdata(env)  # adds 2 symlinks

        _run_backup("--full-backup", env)

        assert os.path.exists(metrics_db), f"Metrics DB not created at {metrics_db}"
        rows = _query_backup_rows(metrics_db, "FULL")
        assert rows, "No FULL backup row found"
        row = rows[0]

        # At minimum: 9 conftest files + data_dir + subdir + 3 subdir files + 2 symlinks
        plain_file_count = 9
        extra = 1 + 1 + created["subdir_files"] + created["symlinks"]  # data_dir + subdir + files + links
        minimum_total = plain_file_count + extra

        assert row["inodes_total"] >= minimum_total, (
            f"inodes_total={row['inodes_total']} expected >= {minimum_total} "
            f"(files + dirs + symlinks)"
        )

        env.logger.info(
            "Symlink test: inodes_total=%s (minimum expected: %s)",
            row["inodes_total"],
            minimum_total,
        )


    def test_metrics_db_has_all_inode_columns(self, setup_environment, env):
        """
        After any backup the metrics DB must contain all 12 inode-counter columns
        plus the hostname column — none may be missing from the schema.
        """
        metrics_db = _inject_metrics_db_path(env)
        _create_metrics_backup_definition(env)
        _run_backup("--full-backup", env)

        assert os.path.exists(metrics_db), f"Metrics DB not created at {metrics_db}"
        with sqlite3.connect(metrics_db) as conn:
            cols = {row[1] for row in conn.execute("PRAGMA table_info(backup_runs)")}

        expected = {
            "hostname",
            "inodes_saved",
            "hard_links_treated",
            "inodes_changed_during_backup",
            "bytes_wasted",
            "inodes_metadata_only",
            "inodes_not_saved",
            "inodes_failed",
            "inodes_excluded",
            "inodes_deleted",
            "inodes_total",
            "ea_saved",
            "fsa_saved",
        }
        missing = expected - cols
        assert not missing, f"Metrics DB is missing columns: {missing}"


    def test_no_metrics_written_when_db_path_absent(self, setup_environment, env):
        """
        When METRICS_DB_PATH is absent from the config, no metrics DB must be
        created and the backup must still succeed.
        """
        # Do NOT inject METRICS_DB_PATH — template config has no such key
        default_metrics_db = os.path.join(env.test_dir, "metrics.db")
        _create_metrics_backup_definition(env)

        _run_backup("--full-backup", env)

        assert not os.path.exists(default_metrics_db), (
            "Metrics DB must NOT be created when METRICS_DB_PATH is not configured"
        )
