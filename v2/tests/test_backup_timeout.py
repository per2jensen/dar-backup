#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later

"""
Integration tests for the COMMAND_TIMEOUT_SECS / DAR_BACKUP_COMMAND_TIMEOUT_SECS
timeout path through the full dar-backup stack.

Strategy
--------
The environment variable DAR_BACKUP_COMMAND_TIMEOUT_SECS overrides the config
value and is inherited by child processes.  To trigger the timeout path without
waiting hours for a real dar run, we shadow the `dar` binary with a wrapper
script that sleeps indefinitely.  dar-backup finds the fake `dar` first because
we prepend a temp directory to PATH.

Two tests:
  positive — genuine short backup with a generous timeout succeeds (returncode=0)
  negative — stalling fake `dar` + 3-second timeout causes dar-backup to report
             failure quickly (returncode != 0, elapsed well under 60 s)
"""

import os
import sys
import stat
import time
import pytest

pytestmark = [pytest.mark.integration, pytest.mark.slow]

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from dar_backup.command_runner import CommandRunner, CommandResult
from tests.envdata import EnvData
from testdata_verification import run_backup_script

_TIMEOUT_ENV_VAR = "DAR_BACKUP_COMMAND_TIMEOUT_SECS"
_STALL_TIMEOUT_SECS = "3"     # timeout set on dar-backup when dar is stalling
_SAFETY_MARGIN_SECS = 30      # wall-clock ceiling for the negative test


def _install_fake_dar(bin_dir: str, script_body: str) -> None:
    """Write an executable `dar` script into bin_dir."""
    dar_path = os.path.join(bin_dir, "dar")
    with open(dar_path, "w") as f:
        f.write(script_body)
    os.chmod(dar_path, stat.S_IRWXU)


def test_backup_completes_within_generous_timeout(setup_environment, env: EnvData):
    """
    A normal small backup completes successfully when DAR_BACKUP_COMMAND_TIMEOUT_SECS
    is set to a generous value, proving the env-var override wiring is intact and
    does not break a healthy backup.
    """
    original = os.environ.get(_TIMEOUT_ENV_VAR)
    try:
        os.environ[_TIMEOUT_ENV_VAR] = "120"
        result = run_backup_script("--full-backup", env)
        assert result.returncode == 0
    finally:
        if original is None:
            os.environ.pop(_TIMEOUT_ENV_VAR, None)
        else:
            os.environ[_TIMEOUT_ENV_VAR] = original


def test_stalled_dar_is_killed_by_timeout(setup_environment, env: EnvData):
    """
    When dar stalls indefinitely, DAR_BACKUP_COMMAND_TIMEOUT_SECS kills it and
    dar-backup exits with a non-zero code well within the safety margin.
    """
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)

    # Create a temp bin directory containing a fake `dar` that sleeps forever
    fake_bin = os.path.join(env.test_dir, "fake_bin")
    os.makedirs(fake_bin, exist_ok=True)
    # dar-backup calls `get_binary_info('dar')` at startup, which runs
    # `dar --version` with no timeout via subprocess.run().  The fake dar must
    # respond to --version immediately; only backup invocations (which pass -c)
    # should stall.
    #
    # `exec sleep 300` replaces bash with sleep so SIGKILL from CommandRunner
    # hits one process: the pipe file descriptors close immediately and the
    # stream threads see EOF.  Without exec, bash forks sleep as a child;
    # killing bash leaves sleep alive holding the write-end of the pipes open,
    # which blocks Python's shutdown via non-daemon stream threads.
    fake_dar_script = (
        "#!/bin/bash\n"
        "for arg in \"$@\"; do\n"
        "    if [ \"$arg\" = '--version' ]; then\n"
        "        echo 'dar version 2.7.15 (built with libdar 6.7.9)'; exit 0\n"
        "    fi\n"
        "done\n"
        "exec sleep 300\n"
    )
    _install_fake_dar(fake_bin, fake_dar_script)

    original_path = os.environ.get("PATH", "")
    original_timeout = os.environ.get(_TIMEOUT_ENV_VAR)

    try:
        os.environ["PATH"] = fake_bin + os.pathsep + original_path
        os.environ[_TIMEOUT_ENV_VAR] = _STALL_TIMEOUT_SECS

        command = [
            "dar-backup", "--full-backup",
            "-d", "example",
            "--config-file", env.config_file,
            "--log-level", "debug",
            "--log-stdout",
        ]

        start = time.monotonic()
        result: CommandResult = runner.run(command, timeout=_SAFETY_MARGIN_SECS)
        elapsed = time.monotonic() - start

        env.logger.info(f"dar-backup returncode: {result.returncode}")
        env.logger.info(f"Elapsed: {elapsed:.1f} s")
        env.logger.info(f"stdout (tail): {result.stdout[-1000:]}")

        assert result.returncode != 0, (
            "Expected dar-backup to fail because dar was killed by timeout"
        )
        assert elapsed < _SAFETY_MARGIN_SECS, (
            f"dar-backup took {elapsed:.1f} s — timeout did not fire in time"
        )

    finally:
        os.environ["PATH"] = original_path
        if original_timeout is None:
            os.environ.pop(_TIMEOUT_ENV_VAR, None)
        else:
            os.environ[_TIMEOUT_ENV_VAR] = original_timeout
