#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later

"""
Test that dar-backup handles a write-space failure gracefully during a full backup.

A bash wrapper script is used to set `ulimit -f` (maximum file size in 512-byte
blocks) before exec-ing dar-backup.  Source data larger than the limit is created
so that dar runs out of allowed file space while writing the archive.

The ulimit approach requires no root access and no FUSE/guestmount kernel
support, making it portable across all CI and developer environments.

Assertions:
  - dar-backup exits with a non-zero return code.
  - The command output contains a recognisable error keyword.
"""

import os
import sys
import pytest

pytestmark = [pytest.mark.integration, pytest.mark.slow]

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from dar_backup.command_runner import CommandRunner, CommandResult
from tests.envdata import EnvData

# ulimit -f is in 512-byte blocks.  2 048 blocks × 512 = 1 048 576 bytes = 1 MB.
# The dar archive of 8 MB of random (incompressible) data will far exceed this.
_ULIMIT_F_BLOCKS = 2048           # 1 MB file-size ceiling for dar
_SOURCE_DATA_SIZE_BYTES = 8 * 1024 * 1024   # 8 MB of random data


def test_enospc_during_full_backup(setup_environment, env: EnvData):
    """
    Apply a 1 MB per-file write limit via `ulimit -f` and attempt a full backup
    of 8 MB of incompressible data.  dar must fail and dar-backup must propagate
    that failure as a non-zero exit code.
    """
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)

    # ------------------------------------------------------------------ #
    # Create source data larger than the write limit                      #
    # Random bytes resist compression, so dar cannot shrink them < 1 MB  #
    # ------------------------------------------------------------------ #
    chunk = os.urandom(64 * 1024)   # 64 KB chunk, reused for speed
    source_file = os.path.join(env.data_dir, "large_incompressible.bin")
    written = 0
    with open(source_file, "wb") as fh:
        while written < _SOURCE_DATA_SIZE_BYTES:
            fh.write(chunk)
            written += len(chunk)
    env.logger.info(f"Wrote {written} bytes of incompressible source data: {source_file}")

    # ------------------------------------------------------------------ #
    # Wrapper script: set file-size limit then exec dar-backup            #
    # ulimit -f is inherited by all child processes (including dar)       #
    # ------------------------------------------------------------------ #
    wrapper_path = os.path.join(env.test_dir, "dar_backup_limited.sh")
    wrapper_content = (
        "#!/bin/bash\n"
        f"ulimit -f {_ULIMIT_F_BLOCKS}\n"
        'exec dar-backup "$@"\n'
    )
    with open(wrapper_path, "w") as f:
        f.write(wrapper_content)
    os.chmod(wrapper_path, 0o755)

    # ------------------------------------------------------------------ #
    # Run the limited dar-backup; expect failure                          #
    # ------------------------------------------------------------------ #
    command = [
        wrapper_path, "--full-backup",
        "-d", "example",
        "--config-file", env.config_file,
        "--log-level", "debug",
        "--log-stdout",
    ]
    result: CommandResult = runner.run(command, timeout=300)

    env.logger.info(f"dar-backup returncode: {result.returncode}")
    env.logger.info(f"dar-backup stdout (last 2000 chars): {result.stdout[-2000:]}")
    env.logger.info(f"dar-backup stderr (last 2000 chars): {result.stderr[-2000:]}")

    assert result.returncode != 0, (
        "Expected dar-backup to fail because the per-file write limit was exceeded, "
        "but it returned success"
    )

    combined_output = (result.stdout + result.stderr).lower()
    assert "partial backup on disk" in combined_output, (
        "Expected 'PARTIAL BACKUP on disk' warning in command output, got:\n"
        f"stdout: {result.stdout[-1000:]}\nstderr: {result.stderr[-1000:]}"
    )
