#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later

"""
Tests that SIGINT and SIGTERM are caught and logged correctly in the
manager (PITR) restore code paths.

Both signals must:
  - cause manager to exit with a non-zero return code
  - emit a clear error message to the log file naming the interrupted
    restore and warning the target directory may be incomplete

The SIGTERM test also proves that the _sigterm_handler installed in
manager.main() converts SIGTERM to KeyboardInterrupt so the same
handler chain fires as for Ctrl-C.

Test approach
-------------
A fake dar stub is placed in front of the real dar on PATH. It delegates
--version, -c (backup) and -t (integrity) calls to the real dar so that
the setup backup runs normally. On -x (restore) it writes a trigger file
then stalls (sleep 30 & wait with trap), giving the test thread time to
send the signal to the manager process.
"""

import os
import shutil
import signal
import subprocess as _sp
import sys
import threading
import time
import glob as _glob

import pytest

pytestmark = pytest.mark.integration

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from dar_backup.command_runner import CommandRunner
from tests.envdata import EnvData

# Re-use helpers from test_manager.py
from test_manager import generate_catalog_db, generate_test_data_and_full_backup


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_BACKUP_DEF = "example"


def _make_slow_dar(fake_dar_path: str, real_dar: str, trigger_file: str) -> None:
    """
    Write a fake dar stub that:
      - delegates --version and -c (backup) to real dar
      - on -l (list used by _is_directory_in_archive) or -x (restore):
        touches trigger_file then stalls until signal
    """
    content = (
        "#!/bin/bash\n"
        f"REAL_DAR='{real_dar}'\n"
        "# Delegate version check and backup to real dar\n"
        "if [[ \"$*\" == *\"--version\"* ]] || [[ \"$*\" == *\"-c \"* ]]; then\n"
        "  exec \"$REAL_DAR\" \"$@\"\n"
        "fi\n"
        "# List or restore invocation: touch trigger file then stall\n"
        f"touch '{trigger_file}'\n"
        "trap 'exit 0' INT TERM\n"
        "sleep 30 &\n"
        "wait\n"
        "exit 0\n"
    )
    with open(fake_dar_path, "w") as fh:
        fh.write(content)
    os.chmod(fake_dar_path, 0o755)


def _run_with_signal(env: EnvData, command: list, sig: int, trigger_file: str) -> tuple:
    """
    Launch command as a subprocess, wait for trigger_file to appear
    (indicating the restore stall has started), then send sig to the process.
    Returns (returncode, stdout_data).
    """
    proc_holder = [None]

    def _sender():
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if os.path.exists(trigger_file):
                break
            time.sleep(0.1)
        time.sleep(0.2)
        if proc_holder[0] is not None:
            try:
                os.kill(proc_holder[0], sig)
                env.logger.info(f"Sent signal {sig} to manager pid={proc_holder[0]}")
            except ProcessLookupError:
                env.logger.warning("Manager process already gone before signal")

    t = threading.Thread(target=_sender, daemon=True)
    t.start()

    env_copy = os.environ.copy()
    env_copy["PATH"] = f"{env.test_dir}:{env_copy.get('PATH', '')}"
    proc = _sp.Popen(command, stdout=_sp.PIPE, stderr=_sp.STDOUT, text=True, env=env_copy)
    proc_holder[0] = proc.pid
    try:
        stdout_data, _ = proc.communicate(timeout=60)
    except _sp.TimeoutExpired:
        # Give the process a chance to flush logs and exit cleanly after the signal
        # before resorting to SIGKILL
        try:
            stdout_data, _ = proc.communicate(timeout=10)
        except _sp.TimeoutExpired:
            proc.kill()
            stdout_data, _ = proc.communicate()

    t.join(timeout=5)
    return proc.returncode, stdout_data


def _assert_log_contains_interrupt(env: EnvData, context: str) -> None:
    """Assert the dar-backup log file contains an interrupt/termination message."""
    # manager writes to dar-backup.log in test_root, not env.log_file (which is
    # the pytest test logger). The config sets LOGFILE_LOCATION to test_root/dar-backup.log.
    from dar_backup.config_settings import ConfigSettings
    config = ConfigSettings(env.config_file)
    log_path = config.logfile_location
    assert os.path.exists(log_path), f"dar-backup log file not found: {log_path}"
    with open(log_path, "r", errors="replace") as fh:
        log_content = fh.read().lower()
    assert any(kw in log_content for kw in ("interrupt", "sigterm", "incomplete", "terminated")), (
        f"Expected interrupt/termination message in {log_path} for {context}\n"
        f"Log tail: {log_content[-500:]}"
    )


# ---------------------------------------------------------------------------
# PITR signal tests
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("sig,sig_name", [
    (signal.SIGINT,  "SIGINT"),
    (signal.SIGTERM, "SIGTERM"),
])
def test_signal_during_pitr_restore_logs_error(setup_environment, env: EnvData, sig, sig_name):
    """
    SIGINT and SIGTERM during a PITR restore (manager --restore-path) must:
      - cause manager to exit non-zero
      - log a clear error message warning the target directory is incomplete

    The fake dar stalls on -x (restore), giving the test thread time to
    deliver the signal while manager is blocked inside _restore_with_dar().
    """
    from datetime import datetime as _dt

    # Setup: create catalog DB and a real FULL backup
    generate_catalog_db(env)
    generate_test_data_and_full_backup(env)

    today = _dt.now().strftime("%Y-%m-%d")

    # Trigger file: fake dar touches this when it enters the restore stall
    trigger_file = os.path.join(env.test_dir, "pitr-restore-stall-started")

    # Install fake dar
    real_dar = shutil.which("dar") or "/home/pj/.local/dar/bin/dar"
    fake_dar = os.path.join(env.test_dir, "dar")
    _make_slow_dar(fake_dar, real_dar, trigger_file)

    # Target directory for the PITR restore
    pitr_target = os.path.join(env.test_dir, "pitr-target")
    os.makedirs(pitr_target, exist_ok=True)

    # Pick one of the backed-up files as the restore path
    restore_path = os.path.join(env.data_dir, "random-1byte.dat").lstrip("/")

    command = [
        "manager",
        "--restore-path", restore_path,
        "--when", today,
        "--target", pitr_target,
        "-d", _BACKUP_DEF,
        "--config-file", env.config_file,
        "--log-level", "debug",
        "--log-stdout",
    ]

    returncode, stdout_data = _run_with_signal(env, command, sig, trigger_file)

    env.logger.info(f"manager returncode: {returncode}")
    env.logger.info(f"stdout (last 1000): {stdout_data[-1000:]}")

    assert returncode != 0, (
        f"Expected manager to exit non-zero after {sig_name} during PITR restore, "
        f"got {returncode}"
    )
    _assert_log_contains_interrupt(env, f"{sig_name} during PITR restore")
