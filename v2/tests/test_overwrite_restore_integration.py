# SPDX-License-Identifier: GPL-3.0-or-later

"""Real-DAR integration coverage for in-place overwrite restores."""

import logging
import os
import stat
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

import dar_backup.dar_backup as dar_backup_module
from dar_backup.command_runner import CommandRunner
from dar_backup.dar_backup import restore_backup
from dar_backup.util import RestoreError


pytestmark = [pytest.mark.integration, pytest.mark.smoke]


def _create_archive(archive: Path, source: Path) -> None:
    """Create a real FULL DAR archive rooted at source.

    Args:
        archive: Archive base path without a slice suffix.
        source: Source directory whose contents are archived.

    Returns:
        None.

    Raises:
        AssertionError: If DAR cannot create the archive.
    """
    result = subprocess.run(
        ["dar", "-c", str(archive), "-R", str(source), "--noconf", "-Q"],
        check=False,
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
    )
    assert result.returncode == 0, (
        f"DAR archive creation failed (rc={result.returncode}): "
        f"stdout={result.stdout!r} stderr={result.stderr!r}"
    )


def test_real_dar_overwrite_restores_private_fake_home_in_place(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A real user can overwrite a private fake home while unrelated data survives."""
    source = tmp_path / "source"
    source.mkdir(mode=0o700)
    (source / "profile.txt").write_text("restored version", encoding="utf-8")

    backup_dir = tmp_path / "backups"
    backup_dir.mkdir(mode=0o700)
    backup_name = "example_FULL_2026-07-25"
    _create_archive(backup_dir / backup_name, source)

    fake_home = tmp_path / "home"
    fake_home.mkdir()
    fake_home.chmod(0o775)
    (fake_home / "profile.txt").write_text("old version", encoding="utf-8")
    (fake_home / "unrelated.txt").write_text("must survive", encoding="utf-8")
    outside = tmp_path / "outside.txt"
    outside.write_text("outside sentinel", encoding="utf-8")

    target_before = fake_home.stat()
    target_mode_before = stat.S_IMODE(target_before.st_mode)
    darrc = tmp_path / ".darrc"
    darrc.write_text("restore-options:\n", encoding="utf-8")
    config = SimpleNamespace(
        backup_dir=str(backup_dir),
        command_timeout_secs=60,
    )
    command_logger = logging.getLogger("overwrite_restore_integration_commands")
    real_runner = CommandRunner(
        logger=logging.getLogger("main_logger"),
        command_logger=command_logger,
        default_timeout=60,
    )

    previous_runner = dar_backup_module.runner
    previous_logger = dar_backup_module.logger
    dar_backup_module.runner = real_runner
    dar_backup_module.logger = logging.getLogger("main_logger")
    try:
        with pytest.raises(RestoreError, match="not empty"):
            restore_backup(
                backup_name,
                config,
                str(fake_home),
                str(darrc),
                ignore_ownership=True,
            )
        assert (fake_home / "profile.txt").read_text(encoding="utf-8") == "old version"

        with caplog.at_level(logging.INFO, logger="main_logger"):
            restore_backup(
                backup_name,
                config,
                str(fake_home),
                str(darrc),
                ignore_ownership=True,
                overwrite_restore_target=True,
            )
    finally:
        dar_backup_module.runner = previous_runner
        dar_backup_module.logger = previous_logger

    target_after = fake_home.stat()
    assert (target_after.st_dev, target_after.st_ino) == (
        target_before.st_dev,
        target_before.st_ino,
    )
    assert target_after.st_uid == os.geteuid()
    assert stat.S_IMODE(target_after.st_mode) == target_mode_before
    assert (fake_home / "profile.txt").read_text(encoding="utf-8") == "restored version"
    assert (fake_home / "unrelated.txt").read_text(encoding="utf-8") == "must survive"
    assert outside.read_text(encoding="utf-8") == "outside sentinel"

    messages = [record.getMessage() for record in caplog.records]
    preflight_index = next(
        index for index, message in enumerate(messages)
        if "Starting overwrite safety preflight" in message
    )
    dar_index = next(
        index for index, message in enumerate(messages)
        if "Running restore command" in message
    )
    assert preflight_index < dar_index
