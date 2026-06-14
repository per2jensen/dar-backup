# SPDX-License-Identifier: GPL-3.0-or-later
"""
Integration tests: concurrent dar-backup invocations against the same config.

Instance lock (fcntl.flock, per-config) guarantees that only one dar-backup
process runs at a time for a given config file.  A second invocation that
finds the lock held exits immediately with rc=1 and writes a FAILURE/PREREQ
row to the metrics DB.

Scenario A — same backup definition, simultaneous FULL:
  The instance lock means exactly one process runs; the other exits rc=1.
  The catalog DB must remain consistent.

Scenario B — different backup definitions, simultaneous FULL:
  Both use the same config → same lock → one runs (rc=0), one exits (rc=1).
  Per-config serialisation is intentional: prevents INCR from referencing an
  in-progress DIFF archive from the same config.

Marks: integration, slow
"""

import fcntl
import os
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
from contextlib import closing
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

def _derive_lock_path(config_file: str) -> str:
    """Return the instance-lock path dar-backup will use for *config_file*."""
    config_abs = os.path.realpath(config_file)
    lock_name = config_abs.replace('/', '_').replace(' ', '_').lstrip('_') + '.lock'
    lock_dir = '/run/lock' if os.path.isdir('/run/lock') else tempfile.gettempdir()
    return os.path.join(lock_dir, lock_name)


def _inject_metrics_db(env: EnvData) -> str:
    """Insert METRICS_DB_PATH into [MISC] of *env.config_file*; return the DB path."""
    metrics_db = os.path.join(env.test_dir, "metrics.db")
    content = Path(env.config_file).read_text()
    Path(env.config_file).write_text(
        content.replace("[MISC]\n", f"[MISC]\nMETRICS_DB_PATH = {metrics_db}\n", 1)
    )
    return metrics_db


def _disable_par2(env: EnvData) -> None:
    """Turn off PAR2 to keep tests fast."""
    config = ConfigParser()
    config.read(env.config_file)
    if "PAR2" not in config:
        config["PAR2"] = {}
    config["PAR2"]["ENABLED"] = "False"
    with open(env.config_file, "w") as fh:
        config.write(fh)


def _write_backup_def(env: EnvData, name: str, data_dir: str) -> None:
    """Write a backup definition and create its catalog DB."""
    def_path = os.path.join(env.backup_d_dir, name)
    Path(def_path).write_text(
        "-R /\n-s 10G\n-z6\n-am\n--cache-directory-tagging\n"
        f"-g {data_dir.lstrip('/')}\n"
    )
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
    result = runner.run(
        ["manager", "--create-db", "--config-file", env.config_file, "--log-stdout"],
        timeout=30,
    )
    if result.returncode != 0:
        raise RuntimeError(f"manager --create-db failed (rc={result.returncode}): {result.stderr}")


def _run_backup_subprocess(
    config_file: str,
    definition: str,
    results: list,
    index: int,
) -> None:
    """
    Launch dar-backup --full-backup in a subprocess and store the returncode
    in results[index].  Designed to be called from a threading.Thread.
    """
    proc = subprocess.run(
        [
            "dar-backup", "--full-backup",
            "-d", definition,
            "--log-stdout", "--log-level", "debug",
            "--config-file", config_file,
        ],
        capture_output=True,
        text=True,
        timeout=300,
    )
    results[index] = proc.returncode


def _catalog_is_consistent(env: EnvData, definition: str) -> bool:
    """Return True if dar_manager --check exits 0 for the given definition's DB."""
    db_path = os.path.join(env.backup_dir, f"{definition}.db")
    if not os.path.exists(db_path):
        return False
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
    result = runner.run(
        ["dar_manager", "--base", db_path, "--check"],
        timeout=30,
    )
    return result.returncode == 0


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_concurrent_same_definition_does_not_corrupt_catalog(
    setup_environment, env: EnvData
) -> None:
    """
    Two dar-backup processes targeting the same FULL backup definition must
    not corrupt the catalog DB.  The instance lock ensures exactly one runs
    (rc=0) and the other exits immediately (rc=1, lock held).
    """
    _disable_par2(env)

    results = [None, None]
    threads = [
        threading.Thread(
            target=_run_backup_subprocess,
            args=(env.config_file, "example", results, i),
            daemon=True,
        )
        for i in range(2)
    ]

    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=360)

    env.logger.info("Concurrent same-def results: %s", results)

    for i, rc in enumerate(results):
        assert rc is not None, f"Thread {i} did not complete"

    # Exactly one must succeed; the loser exits rc=1 (lock held)
    assert sorted(results) == [0, 1], (
        f"Expected one rc=0 and one rc=1; got {results}"
    )

    # Catalog DB must still pass sanity check
    assert _catalog_is_consistent(env, "example"), (
        "Catalog DB is inconsistent after concurrent backup run"
    )

    # Exactly one .1.dar slice (the winner's)
    dar_slices = [
        f for f in os.listdir(env.backup_dir)
        if f.startswith("example_FULL_") and f.endswith(".1.dar")
    ]
    assert len(dar_slices) == 1, (
        f"Expected exactly one .1.dar slice, found: {dar_slices}"
    )


def test_concurrent_different_definitions_serialize(
    setup_environment, env: EnvData
) -> None:
    """
    Two dar-backup processes using the same config file serialize via the
    per-config instance lock even when they target different definitions.
    The loser exits rc=1 immediately; the winner completes rc=0.

    Per-config serialisation is intentional: it prevents INCR from referencing
    an in-progress DIFF archive that shares the same config and backup_dir.
    """
    _disable_par2(env)

    second_data = os.path.join(env.test_dir, "data2")
    os.makedirs(second_data, exist_ok=True)
    for name in ("alpha.txt", "beta.txt", "gamma.txt"):
        Path(os.path.join(second_data, name)).write_text(f"content of {name}\n")

    _write_backup_def(env, "second-def", second_data)

    results = [None, None]
    threads = [
        threading.Thread(
            target=_run_backup_subprocess,
            args=(env.config_file, definition, results, i),
            daemon=True,
        )
        for i, definition in enumerate(["example", "second-def"])
    ]

    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=360)

    env.logger.info("Concurrent different-def results: %s", results)

    for i, rc in enumerate(results):
        assert rc is not None, f"Thread {i} did not complete"

    # One winner (rc=0), one loser (rc=1)
    assert sorted(results) == [0, 1], (
        f"Expected one rc=0 and one rc=1 (serialised by lock); got {results}"
    )

    # The winner's catalog DB must be consistent
    winner_def = "example" if results[0] == 0 else "second-def"
    assert _catalog_is_consistent(env, winner_def), (
        f"Catalog DB for '{winner_def}' is inconsistent after serialised run"
    )


def test_instance_lock_released_after_backup(
    setup_environment, env: EnvData
) -> None:
    """
    Positive: after dar-backup exits normally the instance lock must be free
    so a subsequent invocation can acquire it without error.
    """
    _disable_par2(env)

    proc = subprocess.run(
        ["dar-backup", "--full-backup", "--log-stdout", "--config-file", env.config_file],
        capture_output=True, text=True, timeout=300,
    )
    assert proc.returncode in (0, 2), (
        f"Backup exited with unexpected rc={proc.returncode}\n{proc.stdout}\n{proc.stderr}"
    )

    lock_path = _derive_lock_path(env.config_file)
    assert os.path.exists(lock_path), f"Lock file was never created: {lock_path}"

    # The lock must be free — acquiring it must succeed immediately.
    with open(lock_path, 'w') as fh:
        try:
            fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            pytest.fail(f"Lock {lock_path} was not released after dar-backup exited")


def test_instance_lock_blocks_second_invocation(
    setup_environment, env: EnvData
) -> None:
    """
    Negative: when the instance lock is already held a second dar-backup
    invocation must exit rc=1 and write a FAILURE/PREREQ row to the metrics DB.
    """
    _disable_par2(env)
    metrics_db = _inject_metrics_db(env)

    # "example" is skipped in _record_prereq_failure; create a real definition
    # so there is at least one non-example entry and a metrics row is written.
    lock_test_data = os.path.join(env.test_dir, "lock_test_data")
    os.makedirs(lock_test_data, exist_ok=True)
    _write_backup_def(env, "lock-test-def", lock_test_data)

    lock_path = _derive_lock_path(env.config_file)

    # Hold the lock in a subprocess; it signals readiness via stdout.
    holder_script = (
        f"import fcntl, sys, time\n"
        f"fh = open({lock_path!r}, 'w')\n"
        f"fcntl.flock(fh, fcntl.LOCK_EX)\n"
        f"sys.stdout.write('locked\\n'); sys.stdout.flush()\n"
        f"time.sleep(60)\n"
    )
    holder = subprocess.Popen(
        ["python3", "-c", holder_script],
        stdout=subprocess.PIPE,
        text=True,
    )
    try:
        holder.stdout.readline()  # block until the child has the lock

        proc = subprocess.run(
            ["dar-backup", "--full-backup", "--log-stdout", "--config-file", env.config_file],
            capture_output=True, text=True, timeout=30,
        )
        assert proc.returncode == 1, (
            f"Expected rc=1 (lock held), got rc={proc.returncode}\n"
            f"stdout: {proc.stdout}\nstderr: {proc.stderr}"
        )

        with closing(sqlite3.connect(metrics_db)) as conn:
            row = conn.execute(
                "SELECT status, failed_phase, error_summary FROM backup_runs "
                "WHERE failed_phase = 'PREREQ' ORDER BY run_started_at DESC LIMIT 1"
            ).fetchone()

        assert row is not None, "No PREREQ FAILURE row written to metrics DB"
        status, failed_phase, error_summary = row
        assert status == "FAILURE"
        assert failed_phase == "PREREQ"
        assert "Another dar-backup instance" in (error_summary or ""), (
            f"Unexpected error_summary: {error_summary!r}"
        )
    finally:
        holder.terminate()
        holder.wait()
