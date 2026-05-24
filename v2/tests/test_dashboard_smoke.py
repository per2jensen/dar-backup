# SPDX-License-Identifier: GPL-3.0-or-later
"""
Smoke integration test: dar-backup-dashboard starts Datasette, serves the
metrics DB over HTTP, and the backup_runs table is queryable.

Skipped automatically when datasette is not installed.

Marks: integration, smoke
"""

import json
import os
import signal
import shutil
import socket
import subprocess
import sys
import time
import urllib.request
import urllib.error
from pathlib import Path

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from dar_backup.command_runner import CommandRunner
from envdata import EnvData

pytestmark = [
    pytest.mark.integration,
    pytest.mark.smoke,
    pytest.mark.skipif(
        not shutil.which("datasette"),
        reason="datasette not installed — pip install dar-backup[dashboard]",
    ),
]

_BACKUP_DEF = "dash-smoke"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

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
    """Write the dash-smoke backup definition and create its catalog DB.

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
    """Run dar-backup --full-backup for the dash-smoke definition.

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


def _free_port() -> int:
    """Return an OS-assigned free TCP port (immediately released).

    Returns:
        A port number that was free at the time of the call.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_ready(port: int, timeout: int = 30) -> bool:
    """Poll Datasette's /-/versions endpoint until it responds or timeout expires.

    Args:
        port:    TCP port Datasette is expected to be listening on.
        timeout: Maximum seconds to wait.

    Returns:
        True if Datasette responded before the timeout, False otherwise.
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/-/versions", timeout=1)
            return True
        except Exception:
            time.sleep(0.3)
    return False


def _kill_group(proc: subprocess.Popen) -> None:
    """Send SIGTERM to the process group led by proc, then SIGKILL on timeout.

    Args:
        proc: The process whose group should be terminated.
    """
    try:
        pgid = os.getpgid(proc.pid)
        os.killpg(pgid, signal.SIGTERM)
        proc.wait(timeout=8)
    except ProcessLookupError:
        pass  # process already gone
    except subprocess.TimeoutExpired:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except ProcessLookupError:
            pass


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_dashboard_starts_and_serves_metrics_db(
    setup_environment, env: EnvData
) -> None:
    """dar-backup-dashboard must start Datasette, respond HTTP 200 on
    /-/versions, and serve the backup_runs table with at least one row.
    """
    metrics_db = _inject_metrics_db(env)
    _create_backup_def(env)
    _run_full_backup(env)
    assert os.path.exists(metrics_db), f"Metrics DB not created: {metrics_db}"

    port = _free_port()
    db_stem = Path(metrics_db).stem  # "metrics"

    dash_proc = subprocess.Popen(
        [
            "dar-backup-dashboard",
            "--no-browser",
            "--port", str(port),
            "--db", metrics_db,
            "--config-file", env.config_file,
        ],
        # New session so killpg() terminates both this process and the
        # datasette child it spawns, without affecting the test runner.
        start_new_session=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    try:
        assert _wait_ready(port), (
            f"Datasette did not become ready on port {port} within 30 s"
        )

        resp = urllib.request.urlopen(
            f"http://127.0.0.1:{port}/-/versions", timeout=5
        )
        assert resp.status == 200, f"/-/versions returned HTTP {resp.status}"

        sql_url = (
            f"http://127.0.0.1:{port}/{db_stem}.json"
            "?sql=SELECT+COUNT(*)+AS+n+FROM+backup_runs"
        )
        resp2 = urllib.request.urlopen(sql_url, timeout=5)
        data = json.loads(resp2.read())
        count = data["rows"][0][0]
        assert count >= 1, f"Expected ≥1 row in backup_runs via Datasette, got {count}"

    finally:
        _kill_group(dash_proc)
