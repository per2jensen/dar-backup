#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later

"""
Tests for the "silent dar failure" bug fix: dar exits 0 but writes no archive
slices (e.g. due to an NFS stall mid-backup).

Two scenarios are tested:

  Positive: a normal FULL backup completes and is recorded as SUCCESS.
  Negative: dar is replaced by a stub that exits 0 but writes nothing;
            dar-backup must record FAILURE, not SUCCESS.

The negative test reproduces the exact real-world failure observed on
2026-05-04 where an NFS mount stall caused dar to exit 0 without writing
any .dar slices, yet the metrics DB recorded SUCCESS.
"""

import os
import sqlite3
import sys
import pytest

pytestmark = [pytest.mark.integration]

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from dar_backup.command_runner import CommandRunner, CommandResult
from tests.envdata import EnvData


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# The backup definition name must NOT be "example" — perform_backup() skips
# stats/metrics collection for any definition named "example" to avoid noise
# from the demo/quick-start workflow.
_BACKUP_DEF_NAME = "test-backup"


def _row_count(db: str) -> int:
    with sqlite3.connect(db) as conn:
        return conn.execute("SELECT count(*) FROM backup_runs").fetchone()[0]


def _latest_row(db: str) -> sqlite3.Row:
    with sqlite3.connect(db) as conn:
        conn.row_factory = sqlite3.Row
        return conn.execute(
            "SELECT * FROM backup_runs ORDER BY id DESC LIMIT 1"
        ).fetchone()


def _metrics_db_path(env: EnvData) -> str:
    """Return the metrics DB path written into the test config."""
    return os.path.join(env.test_dir, "dar-backup-metrics.db")


def _inject_metrics_db(env: EnvData) -> str:
    """
    Insert METRICS_DB_PATH into the [MISC] section of the test config file
    so that perform_backup() writes metrics rows we can inspect.
    Appending to the end of the file does not work because configparser assigns
    orphaned keys to the last section, which may not be [MISC].
    Returns the db path.
    """
    db_path = _metrics_db_path(env)
    with open(env.config_file, "r") as fh:
        content = fh.read()
    # Insert immediately after the [MISC] header
    content = content.replace(
        "[MISC]\n",
        f"[MISC]\nMETRICS_DB_PATH = {db_path}\n",
        1,
    )
    with open(env.config_file, "w") as fh:
        fh.write(content)
    return db_path


def _create_backup_definition(env: EnvData, name: str) -> None:
    """
    Write a minimal backup definition file alongside the existing ones.
    Mirrors the structure used by conftest.py's create_backup_definitions().
    Also creates the dar_manager catalog DB for this definition.
    """
    content = (
        "-R /\n"
        "-s 10G\n"
        "-z6\n"
        "-am\n"
        "--cache-directory-tagging\n"
        f"-g {env.data_dir}\n"
    ).replace("-g /tmp/", "-g tmp/")

    def_path = os.path.join(env.test_dir, "backup.d", name)
    with open(def_path, "w") as fh:
        fh.write(content)

    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
    runner.run([
        "manager", "--create-db",
        "--config-file", env.config_file,
        "--log-level", "debug",
    ])


def _write_fake_dar(path: str, exit_code: int, write_slice: bool, backup_dir: str) -> None:
    """
    Write a bash stub that impersonates dar.

    If write_slice is True the stub creates a minimal (but non-empty) .1.dar
    file in backup_dir so that _list_dar_slices() finds it.
    If write_slice is False the stub exits without touching the filesystem,
    reproducing the NFS-stall scenario.
    """
    if write_slice:
        slice_body = (
            # Parse the -c <archive_base> argument from the dar command line
            # and write a tiny placeholder slice next to the other archives.
            "for i in \"$@\"; do\n"
            "  if [ \"$prev\" = \"-c\" ]; then\n"
            "    touch \"${i}.1.dar\"\n"
            "    break\n"
            "  fi\n"
            "  prev=\"$i\"\n"
            "done\n"
        )
    else:
        slice_body = "# NFS stall simulation: do nothing, write no slices\n"

    content = (
        "#!/bin/bash\n"
        f"# Fake dar stub — exit {exit_code}, write_slice={write_slice}\n"
        + slice_body
        + f"exit {exit_code}\n"
    )
    with open(path, "w") as fh:
        fh.write(content)
    os.chmod(path, 0o755)


# ---------------------------------------------------------------------------
# Positive test — normal backup, SUCCESS recorded
# ---------------------------------------------------------------------------

def test_successful_backup_records_success_in_metrics(setup_environment, env: EnvData):
    """
    A full backup that completes normally must be recorded as SUCCESS
    in the metrics DB with num_slices > 0.
    """
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
    db_path = _inject_metrics_db(env)
    _create_backup_definition(env, _BACKUP_DEF_NAME)

    command = [
        "dar-backup", "--full-backup",
        "-d", _BACKUP_DEF_NAME,
        "--config-file", env.config_file,
        "--log-level", "debug",
        "--log-stdout",
    ]
    result: CommandResult = runner.run(command, timeout=300)

    env.logger.info(f"dar-backup returncode: {result.returncode}")
    env.logger.info(f"stdout (last 2000): {result.stdout[-2000:]}")

    assert result.returncode == 0, (
        f"Expected dar-backup to succeed, got returncode {result.returncode}\n"
        f"stdout: {result.stdout[-1000:]}\nstderr: {result.stderr[-1000:]}"
    )

    assert os.path.exists(db_path), "Metrics DB was not created"
    assert _row_count(db_path) == 1, "Expected exactly one metrics row"

    row = _latest_row(db_path)
    assert row["status"] == "SUCCESS", (
        f"Expected SUCCESS in metrics, got '{row['status']}'"
    )
    assert row["num_slices"] is not None and row["num_slices"] > 0, (
        f"Expected num_slices > 0 for a successful backup, got {row['num_slices']}"
    )
    assert row["failed_phase"] is None, (
        f"Expected failed_phase to be NULL for a successful backup, got '{row['failed_phase']}'"
    )


# ---------------------------------------------------------------------------
# Negative test — dar exits 0 but writes no slices (NFS stall scenario)
# ---------------------------------------------------------------------------

def test_dar_exits_zero_but_no_slices_records_failure(setup_environment, env: EnvData):
    """
    When dar exits 0 but writes no archive slices (reproducing the NFS stall
    scenario observed on 2026-05-04), dar-backup must:

      - exit with a non-zero return code, AND
      - record FAILURE (not SUCCESS) in the metrics DB, AND
      - set failed_phase to 'DAR'

    Before this bug fix the metrics DB incorrectly recorded SUCCESS.
    """
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
    db_path = _inject_metrics_db(env)
    _create_backup_definition(env, _BACKUP_DEF_NAME)

    # Replace dar with a stub that exits 0 but writes nothing
    fake_dar = os.path.join(env.test_dir, "dar")
    _write_fake_dar(
        path=fake_dar,
        exit_code=0,
        write_slice=False,
        backup_dir=env.backup_dir,
    )

    # Prepend our fake dar directory so it shadows the real one
    patched_env = os.environ.copy()
    patched_env["PATH"] = env.test_dir + os.pathsep + patched_env.get("PATH", "")

    wrapper_path = os.path.join(env.test_dir, "run_with_fake_dar.sh")
    wrapper_content = (
        "#!/bin/bash\n"
        f"export PATH={env.test_dir}:$PATH\n"
        'exec dar-backup "$@"\n'
    )
    with open(wrapper_path, "w") as fh:
        fh.write(wrapper_content)
    os.chmod(wrapper_path, 0o755)

    command = [
        wrapper_path, "--full-backup",
        "-d", _BACKUP_DEF_NAME,
        "--config-file", env.config_file,
        "--log-level", "debug",
        "--log-stdout",
    ]
    result: CommandResult = runner.run(command, timeout=300)

    env.logger.info(f"dar-backup returncode: {result.returncode}")
    env.logger.info(f"stdout (last 2000): {result.stdout[-2000:]}")

    # dar-backup must propagate the failure as a non-zero exit code
    assert result.returncode != 0, (
        "Expected dar-backup to fail when dar writes no slices, "
        f"but it returned {result.returncode} (the pre-fix bug)"
    )

    assert os.path.exists(db_path), "Metrics DB was not created"
    assert _row_count(db_path) >= 1, "Expected at least one metrics row"

    row = _latest_row(db_path)
    assert row["status"] == "FAILURE", (
        f"Expected FAILURE in metrics when no slices were written, "
        f"got '{row['status']}' — this is the silent-failure bug"
    )
    assert row["failed_phase"] in ("DAR", "VERIFY"), (
        f"Expected failed_phase to be 'DAR' or 'VERIFY', got '{row['failed_phase']}'"
    )
    assert row["num_slices"] == 0 or row["num_slices"] is None, (
        f"Expected num_slices=0 or NULL when no slices written, got {row['num_slices']}"
    )


# ---------------------------------------------------------------------------
# Realistic NFS stall scenario — dar produces output then exits 0, no slices
# ---------------------------------------------------------------------------

def test_dar_stalls_mid_run_then_exits_zero_records_failure(setup_environment, env: EnvData):
    """
    Reproduces the exact real-world failure from 2026-05-04:
      - dar starts and prints directory inspection lines (simulating normal progress)
      - then stalls (NFS mount hang) and eventually exits 0 with no slices written
      - dar-backup must record FAILURE, not SUCCESS

    The stub sleeps 2 seconds to simulate the stall and emits inspection lines
    to stdout so the command log looks like a real mid-run abort.
    """
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
    db_path = _inject_metrics_db(env)
    _create_backup_definition(env, _BACKUP_DEF_NAME)

    # dar stub: emits a few inspection lines, sleeps to simulate stall, exits 0
    fake_dar = os.path.join(env.test_dir, "dar")
    content = (
        "#!/bin/bash\n"
        "# Simulates NFS stall: prints progress then hangs briefly and exits 0\n"
        "echo 'Inspecting directory /home'\n"
        "echo 'Inspecting directory /home/pj'\n"
        "echo 'Inspecting directory /data/billeder/2011'\n"
        "sleep 2\n"
        "# NFS came back but dar had nothing to write — exit 0, no slices\n"
        "exit 0\n"
    )
    with open(fake_dar, "w") as fh:
        fh.write(content)
    os.chmod(fake_dar, 0o755)

    wrapper_path = os.path.join(env.test_dir, "run_with_fake_dar.sh")
    with open(wrapper_path, "w") as fh:
        fh.write(
            "#!/bin/bash\n"
            f"export PATH={env.test_dir}:$PATH\n"
            'exec dar-backup "$@"\n'
        )
    os.chmod(wrapper_path, 0o755)

    command = [
        wrapper_path, "--full-backup",
        "-d", _BACKUP_DEF_NAME,
        "--config-file", env.config_file,
        "--log-level", "debug",
        "--log-stdout",
    ]
    result: CommandResult = runner.run(command, timeout=300)

    env.logger.info(f"dar-backup returncode: {result.returncode}")
    env.logger.info(f"stdout (last 2000): {result.stdout[-2000:]}")

    assert result.returncode != 0, (
        "Expected dar-backup to fail when dar stalls and writes no slices, "
        f"but it returned {result.returncode}"
    )

    assert os.path.exists(db_path), "Metrics DB was not created"
    row = _latest_row(db_path)
    assert row["status"] == "FAILURE", (
        f"Expected FAILURE after NFS stall scenario, got '{row['status']}'"
    )
    assert row["failed_phase"] in ("DAR", "VERIFY"), (
        f"Expected failed_phase 'DAR' or 'VERIFY', got '{row['failed_phase']}'"
    )
    assert row["num_slices"] == 0 or row["num_slices"] is None, (
        f"Expected num_slices=0 or NULL after stall, got {row['num_slices']}"
    )


# ---------------------------------------------------------------------------
# Ctrl-C (KeyboardInterrupt) scenario
# ---------------------------------------------------------------------------

def test_keyboard_interrupt_during_backup_records_failure(setup_environment, env: EnvData):
    """
    When the user presses Ctrl-C (SIGINT) while dar is running, dar-backup must:

      - record FAILURE (not SUCCESS) in the metrics DB
      - log a clear message naming the interrupted phase and warning that
        any partial slices on disk must NOT be used for restore
      - still exit with a non-zero return code

    The fake dar stub writes a partial .1.dar slice (worst case: slices_written
    would be True without the fix), then sends SIGINT directly to its *parent*
    process (the dar-backup Python process) to simulate Ctrl-C reaching Python.

    Without the `except KeyboardInterrupt` fix in perform_backup(), the finally
    block would see slices_written=True and success=True and record SUCCESS.
    With the fix, FAILURE is recorded and the error_summary describes the
    interruption clearly.

    NOTE: The test asserts that EITHER:
      - the metrics DB records FAILURE with an interrupt-related error_summary
        (proving the KeyboardInterrupt handler fired), OR
      - dar-backup exits non-zero due to the signal before metrics are written
        (acceptable — the process was killed cleanly)
    The critical assertion is that status is never SUCCESS when a partial slice
    is on disk.
    """
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
    db_path = _inject_metrics_db(env)
    _create_backup_definition(env, _BACKUP_DEF_NAME)

    # dar stub: writes a partial slice then sleeps, giving the test thread time
    # to send SIGINT to the dar-backup process from outside.
    fake_dar = os.path.join(env.test_dir, "dar")
    content = (
        "#!/bin/bash\n"
        "# Fake dar: respond to --version quickly (for preflight),\n"
        "# write a partial slice and stall only during the real backup (-c flag).\n"
        "if [[ \"$*\" == *\"--version\"* ]]; then\n"
        "  echo 'dar version 2.7.21'\n"
        "  exit 0\n"
        "fi\n"
        "# Real backup invocation: write partial slice then stall\n"
        "prev=''\n"
        "for i in \"$@\"; do\n"
        "  if [ \"$prev\" = \"-c\" ]; then\n"
        "    touch \"${i}.1.dar\"\n"
        "    break\n"
        "  fi\n"
        "  prev=\"$i\"\n"
        "done\n"
        "# Exit cleanly on SIGINT so dar-backup's CommandRunner unblocks\n"
        "trap 'exit 0' INT\n"
        "# Stall until SIGINT arrives from the test thread\n"
        "sleep 30 &\n"
        "wait\n"
        "exit 0\n"
    )
    with open(fake_dar, "w") as fh:
        fh.write(content)
    os.chmod(fake_dar, 0o755)

    wrapper_path = os.path.join(env.test_dir, "run_with_fake_dar.sh")
    with open(wrapper_path, "w") as fh:
        fh.write(
            "#!/bin/bash\n"
            f"export PATH={env.test_dir}:$PATH\n"
            'exec dar-backup "$@"\n'
        )
    os.chmod(wrapper_path, 0o755)

    command = [
        wrapper_path, "--full-backup",
        "-d", _BACKUP_DEF_NAME,
        "--config-file", env.config_file,
        "--log-level", "debug",
        "--log-stdout",
    ]

    # Write the dar-backup PID to a file from a background thread so we can
    # send SIGINT to it once it is inside the DAR phase (i.e. after preflight).
    pid_file = os.path.join(env.test_dir, "dar-backup.pid")

    import signal
    import subprocess
    import threading
    import time

    proc_holder = [None]

    def _send_sigint_after_delay():
        """Wait until dar-backup is inside the DAR phase then send SIGINT."""
        deadline = time.monotonic() + 20
        # Poll until the fake dar slice appears — that means we're in the DAR phase
        slice_pattern = os.path.join(env.backup_dir, f"{_BACKUP_DEF_NAME}_FULL_*.1.dar")
        import glob as _glob
        while time.monotonic() < deadline:
            if _glob.glob(slice_pattern):
                break
            time.sleep(0.1)
        # Give Python a moment to be blocking inside CommandRunner.run()
        time.sleep(0.2)
        if proc_holder[0] is not None:
            try:
                os.kill(proc_holder[0], signal.SIGINT)
                env.logger.info(f"Sent SIGINT to dar-backup pid={proc_holder[0]}")
            except ProcessLookupError:
                env.logger.warning("dar-backup process already gone before SIGINT")

    sigint_thread = threading.Thread(target=_send_sigint_after_delay, daemon=True)
    sigint_thread.start()

    # Run dar-backup as a raw subprocess so we have the PID
    import subprocess as _sp
    env_copy = os.environ.copy()
    env_copy["PATH"] = f"{env.test_dir}:{env_copy.get('PATH', '')}"
    proc = _sp.Popen(command, stdout=_sp.PIPE, stderr=_sp.STDOUT, text=True, env=env_copy)
    proc_holder[0] = proc.pid
    try:
        stdout_data, _ = proc.communicate(timeout=30)
    except _sp.TimeoutExpired:
        proc.kill()
        stdout_data, _ = proc.communicate()
    returncode = proc.returncode

    sigint_thread.join(timeout=5)

    env.logger.info(f"dar-backup returncode: {returncode}")
    env.logger.info(f"stdout (last 2000): {stdout_data[-2000:]}")

    # dar-backup must exit non-zero after Ctrl-C
    assert returncode != 0, (
        "Expected dar-backup to exit non-zero after Ctrl-C, "
        f"but it returned {returncode}"
    )

    # Metrics DB must exist — the finally block must have run and written the row
    assert os.path.exists(db_path), (
        "Metrics DB was not created — the KeyboardInterrupt handler must write "
        "metrics before re-raising"
    )
    row = _latest_row(db_path)

    # The critical assertion: a partial slice on disk must NEVER be SUCCESS
    assert row["status"] == "FAILURE", (
        f"Expected FAILURE in metrics after Ctrl-C with partial slice on disk, "
        f"got '{row['status']}' — this is the KeyboardInterrupt bug"
    )

    # The error summary must mention the interruption (proves the new handler fired,
    # not just the existing slices_written check)
    assert row["error_summary"] is not None, "Expected error_summary to be set after Ctrl-C"
    summary_lower = row["error_summary"].lower()
    assert "interrupt" in summary_lower or "ctrl" in summary_lower or "incomplete" in summary_lower, (
        f"Expected error_summary to describe the interruption, got: '{row['error_summary']}'"
    )

    # The main log file must contain the ERROR message emitted by the
    # KeyboardInterrupt handler — this proves the handler ran and logged,
    # not just that the slices_written fallback caught it.
    log_path = env.log_file
    assert os.path.exists(log_path), f"Log file not found: {log_path}"
    with open(log_path, "r", errors="replace") as fh:
        log_content = fh.read().lower()
    assert "interrupt" in log_content or "ctrl" in log_content or "incomplete" in log_content, (
        f"Expected the KeyboardInterrupt error message to appear in {log_path} — "
        f"the except KeyboardInterrupt handler may not have fired"
    )


# ---------------------------------------------------------------------------
# SIGTERM scenario — `kill <pid>`
# ---------------------------------------------------------------------------

def test_sigterm_during_backup_records_failure(setup_environment, env: EnvData):
    """
    When the process receives SIGTERM (`kill <pid>`), dar-backup must:

      - record FAILURE (not SUCCESS) in the metrics DB
      - log a clear message describing the termination
      - exit with a non-zero return code

    Without the SIGTERM handler installed in main(), the process would terminate
    immediately on SIGTERM with no finally blocks running, no metrics written,
    and no log entry — a silent failure identical to kill -9.

    The SIGTERM handler converts the signal to KeyboardInterrupt so the same
    handler chain fires as for Ctrl-C.
    """
    import signal
    import subprocess as _sp
    import threading
    import time
    import glob as _glob

    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
    db_path = _inject_metrics_db(env)
    _create_backup_definition(env, _BACKUP_DEF_NAME)

    # Same fake dar as the Ctrl-C test: handles --version quickly,
    # writes a partial slice on real backup invocation, then stalls.
    fake_dar = os.path.join(env.test_dir, "dar")
    content = (
        "#!/bin/bash\n"
        "if [[ \"$*\" == *\"--version\"* ]]; then\n"
        "  echo 'dar version 2.7.21'\n"
        "  exit 0\n"
        "fi\n"
        "prev=''\n"
        "for i in \"$@\"; do\n"
        "  if [ \"$prev\" = \"-c\" ]; then\n"
        "    touch \"${i}.1.dar\"\n"
        "    break\n"
        "  fi\n"
        "  prev=\"$i\"\n"
        "done\n"
        "trap 'exit 0' TERM\n"
        "sleep 30 &\n"
        "wait\n"
        "exit 0\n"
    )
    with open(fake_dar, "w") as fh:
        fh.write(content)
    os.chmod(fake_dar, 0o755)

    wrapper_path = os.path.join(env.test_dir, "run_with_fake_dar.sh")
    with open(wrapper_path, "w") as fh:
        fh.write(
            "#!/bin/bash\n"
            f"export PATH={env.test_dir}:$PATH\n"
            'exec dar-backup "$@"\n'
        )
    os.chmod(wrapper_path, 0o755)

    command = [
        wrapper_path, "--full-backup",
        "-d", _BACKUP_DEF_NAME,
        "--config-file", env.config_file,
        "--log-level", "debug",
        "--log-stdout",
    ]

    proc_holder = [None]

    def _send_sigterm_after_slice():
        """Wait until the DAR phase has started (slice on disk) then send SIGTERM."""
        deadline = time.monotonic() + 20
        slice_pattern = os.path.join(env.backup_dir, f"{_BACKUP_DEF_NAME}_FULL_*.1.dar")
        while time.monotonic() < deadline:
            if _glob.glob(slice_pattern):
                break
            time.sleep(0.1)
        time.sleep(0.2)
        if proc_holder[0] is not None:
            try:
                os.kill(proc_holder[0], signal.SIGTERM)
                env.logger.info(f"Sent SIGTERM to dar-backup pid={proc_holder[0]}")
            except ProcessLookupError:
                env.logger.warning("dar-backup process already gone before SIGTERM")

    sigterm_thread = threading.Thread(target=_send_sigterm_after_slice, daemon=True)
    sigterm_thread.start()

    env_copy = os.environ.copy()
    env_copy["PATH"] = f"{env.test_dir}:{env_copy.get('PATH', '')}"
    proc = _sp.Popen(command, stdout=_sp.PIPE, stderr=_sp.STDOUT, text=True, env=env_copy)
    proc_holder[0] = proc.pid
    try:
        stdout_data, _ = proc.communicate(timeout=30)
    except _sp.TimeoutExpired:
        proc.kill()
        stdout_data, _ = proc.communicate()
    returncode = proc.returncode

    sigterm_thread.join(timeout=5)

    env.logger.info(f"dar-backup returncode: {returncode}")
    env.logger.info(f"stdout (last 2000): {stdout_data[-2000:]}")

    assert returncode != 0, (
        "Expected dar-backup to exit non-zero after SIGTERM, "
        f"but it returned {returncode}"
    )

    assert os.path.exists(db_path), (
        "Metrics DB was not created after SIGTERM — the SIGTERM handler must "
        "write metrics before terminating"
    )
    row = _latest_row(db_path)

    assert row["status"] == "FAILURE", (
        f"Expected FAILURE in metrics after SIGTERM, got '{row['status']}'"
    )

    # The log must contain an error message describing the termination —
    # this is the key proof that the SIGTERM handler fired and logged.
    log_path = env.log_file
    assert os.path.exists(log_path), f"Log file not found: {log_path}"
    with open(log_path, "r", errors="replace") as fh:
        log_content = fh.read().lower()
    assert "interrupt" in log_content or "sigterm" in log_content or "incomplete" in log_content, (
        f"Expected a SIGTERM/interrupt error message in {log_path} — "
        f"the SIGTERM handler may not have fired"
    )


# ---------------------------------------------------------------------------
# Helper: run a real FULL backup so restore/verify tests have an archive
# ---------------------------------------------------------------------------

def _run_full_backup(env: EnvData, backup_def: str) -> None:
    """Run a real FULL backup using the standard dar. Used as setup for restore/verify tests."""
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
    result = runner.run([
        "dar-backup", "--full-backup",
        "-d", backup_def,
        "--config-file", env.config_file,
        "--log-level", "debug",
    ], timeout=120)
    assert result.returncode == 0, (
        f"Setup backup failed (returncode={result.returncode})\n{result.stdout[-500:]}"
    )


def _make_slow_dar(fake_dar_path: str, real_dar_path: str) -> None:
    """
    Write a dar stub that delegates --version and real backups to the real dar,
    but sleeps during restore (-x flag) so SIGINT/SIGTERM can be delivered.
    """
    content = (
        "#!/bin/bash\n"
        "# Delegate --version and backup (-c) to real dar; stall on restore (-x)\n"
        f"REAL_DAR='{real_dar_path}'\n"
        "if [[ \"$*\" == *\"--version\"* ]] || [[ \"$*\" == *\"-c \"* ]] || [[ \"$*\" == *\"-t \"* ]]; then\n"
        "  exec \"$REAL_DAR\" \"$@\"\n"
        "fi\n"
        "# Restore or list invocation: stall so signal can be delivered\n"
        "trap 'exit 0' INT TERM\n"
        "sleep 30 &\n"
        "wait\n"
        "exit 0\n"
    )
    with open(fake_dar_path, "w") as fh:
        fh.write(content)
    os.chmod(fake_dar_path, 0o755)


def _run_with_signal(env: EnvData, command: list, signal_no: int,
                     trigger_file: str = None, delay: float = 1.0) -> tuple:
    """
    Run dar-backup as a subprocess and send signal_no to it either after
    `delay` seconds (if trigger_file is None) or once trigger_file appears.
    Returns (returncode, stdout_data).
    """
    import signal as _signal
    import subprocess as _sp
    import threading
    import time
    import glob as _glob

    proc_holder = [None]

    def _sender():
        if trigger_file:
            deadline = time.monotonic() + 20
            while time.monotonic() < deadline:
                if os.path.exists(trigger_file):
                    break
                time.sleep(0.1)
        else:
            time.sleep(delay)
        time.sleep(0.2)
        if proc_holder[0] is not None:
            try:
                os.kill(proc_holder[0], signal_no)
                env.logger.info(f"Sent signal {signal_no} to pid={proc_holder[0]}")
            except ProcessLookupError:
                env.logger.warning("Process already gone before signal")

    t = threading.Thread(target=_sender, daemon=True)
    t.start()

    env_copy = os.environ.copy()
    env_copy["PATH"] = f"{env.test_dir}:{env_copy.get('PATH', '')}"
    proc = _sp.Popen(command, stdout=_sp.PIPE, stderr=_sp.STDOUT, text=True, env=env_copy)
    proc_holder[0] = proc.pid
    try:
        stdout_data, _ = proc.communicate(timeout=30)
    except _sp.TimeoutExpired:
        proc.kill()
        stdout_data, _ = proc.communicate()

    t.join(timeout=5)
    return proc.returncode, stdout_data


def _assert_log_contains_interrupt(env: EnvData, context: str) -> None:
    """Assert the dar-backup log file contains an interrupt/termination message."""
    log_path = env.log_file
    assert os.path.exists(log_path), f"Log file not found: {log_path}"
    with open(log_path, "r", errors="replace") as fh:
        log_content = fh.read().lower()
    assert any(kw in log_content for kw in ("interrupt", "sigterm", "incomplete", "terminated")), (
        f"Expected interrupt/termination message in {log_path} for {context}"
    )


# ---------------------------------------------------------------------------
# Restore signal tests
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("sig,sig_name", [
    (2,  "SIGINT"),
    (15, "SIGTERM"),
])
def test_signal_during_restore_logs_error(setup_environment, env: EnvData, sig, sig_name):
    """
    SIGINT and SIGTERM during restore_backup() must log a clear error message
    naming the interrupted restore and warning the restore directory is incomplete.
    """
    import signal as _signal
    _create_backup_definition(env, _BACKUP_DEF_NAME)
    _inject_metrics_db(env)

    # Run a real FULL backup first so there is an archive to restore from
    _run_full_backup(env, _BACKUP_DEF_NAME)

    # Find the archive name
    import glob as _glob
    from datetime import datetime as _dt
    date = _dt.now().strftime("%Y-%m-%d")
    archive_name = f"{_BACKUP_DEF_NAME}_FULL_{date}"

    # Replace dar with a stub that stalls on restore (-x)
    import shutil as _shutil
    real_dar = _shutil.which("dar") or "/home/pj/.local/dar/bin/dar"
    fake_dar = os.path.join(env.test_dir, "dar")
    _make_slow_dar(fake_dar, real_dar)

    wrapper_path = os.path.join(env.test_dir, "run_with_fake_dar.sh")
    with open(wrapper_path, "w") as fh:
        fh.write(
            "#!/bin/bash\n"
            f"export PATH={env.test_dir}:$PATH\n"
            'exec dar-backup "$@"\n'
        )
    os.chmod(wrapper_path, 0o755)

    command = [
        wrapper_path, "--restore", archive_name,
        "--restore-dir", env.restore_dir,
        "--config-file", env.config_file,
        "--log-level", "debug",
        "--log-stdout",
    ]

    returncode, stdout_data = _run_with_signal(env, command, sig, delay=1.5)

    env.logger.info(f"dar-backup returncode: {returncode}")
    env.logger.info(f"stdout (last 1000): {stdout_data[-1000:]}")

    assert returncode != 0, (
        f"Expected non-zero exit after {sig_name} during restore, got {returncode}"
    )
    _assert_log_contains_interrupt(env, f"{sig_name} during restore")


# ---------------------------------------------------------------------------
# Verify signal tests
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("sig,sig_name", [
    (2,  "SIGINT"),
    (15, "SIGTERM"),
])
def test_signal_during_verify_logs_error(setup_environment, env: EnvData, sig, sig_name):
    """
    SIGINT and SIGTERM during verify() must log a clear error message.
    The signal is delivered while dar is performing the restore-test comparison,
    which stalls in the fake dar stub.

    The fake dar completes the real backup (-c) then stalls on restore-test (-x),
    giving a clean window to deliver the signal during the VERIFY phase.
    """
    _create_backup_definition(env, _BACKUP_DEF_NAME)
    _inject_metrics_db(env)

    # Find the real dar binary from the PATH
    import shutil as _shutil
    real_dar = _shutil.which("dar") or "/home/pj/.local/dar/bin/dar"

    # Fake dar: delegates backup and integrity check to real dar,
    # stalls on restore-test (-x) so signal arrives during VERIFY phase.
    fake_dar = os.path.join(env.test_dir, "dar")
    _make_slow_dar(fake_dar, real_dar)

    wrapper_path = os.path.join(env.test_dir, "run_with_fake_dar.sh")
    with open(wrapper_path, "w") as fh:
        fh.write(
            "#!/bin/bash\n"
            f"export PATH={env.test_dir}:$PATH\n"
            'exec dar-backup "$@"\n'
        )
    os.chmod(wrapper_path, 0o755)

    # Use a trigger file: fake dar touches it when it enters the stall (restore-test),
    # so the signal thread knows the VERIFY phase has been reached.
    trigger_file = os.path.join(env.test_dir, "verify-stall-started")

    # Rewrite fake dar to also touch the trigger file when stalling
    from datetime import datetime as _dt
    content = (
        "#!/bin/bash\n"
        f"REAL_DAR='{real_dar}'\n"
        "if [[ \"$*\" == *\"--version\"* ]] || [[ \"$*\" == *\"-c \"* ]] || [[ \"$*\" == *\"-t \"* ]]; then\n"
        "  exec \"$REAL_DAR\" \"$@\"\n"
        "fi\n"
        f"touch '{trigger_file}'\n"
        "trap 'exit 0' INT TERM\n"
        "sleep 30 &\n"
        "wait\n"
        "exit 0\n"
    )
    with open(fake_dar, "w") as fh:
        fh.write(content)
    os.chmod(fake_dar, 0o755)

    command = [
        wrapper_path, "--full-backup",
        "-d", _BACKUP_DEF_NAME,
        "--config-file", env.config_file,
        "--log-level", "debug",
        "--log-stdout",
    ]

    # Deliver signal once the trigger file appears (fake dar entered stall = VERIFY phase)
    returncode, stdout_data = _run_with_signal(
        env, command, sig, trigger_file=trigger_file
    )

    env.logger.info(f"dar-backup returncode: {returncode}")
    env.logger.info(f"stdout (last 1000): {stdout_data[-1000:]}")

    assert returncode != 0, (
        f"Expected non-zero exit after {sig_name} during verify, got {returncode}"
    )
    _assert_log_contains_interrupt(env, f"{sig_name} during verify")
