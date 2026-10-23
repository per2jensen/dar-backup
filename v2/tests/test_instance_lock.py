# SPDX-License-Identifier: GPL-3.0-or-later
"""Real-filesystem and subprocess tests for dar-backup instance locking."""

from __future__ import annotations

import os
import pwd
import subprocess
import sys
from pathlib import Path

import pytest

from dar_backup.instance_lock import InstanceLockError
from dar_backup.instance_lock import _default_lock_directory
from dar_backup.instance_lock import _prepare_private_directory
from dar_backup.instance_lock import acquire_instance_lock


pytestmark = pytest.mark.unit


def test_default_lock_directory_root_uses_run_lock() -> None:
    """Root must always select the historical system lock directory."""
    directory, private = _default_lock_directory(0, "")

    assert directory == Path("/run/lock")
    assert private is False


def test_default_lock_directory_non_root_uses_registered_home() -> None:
    """A normal user must always select state storage below the registered home."""
    directory, private = _default_lock_directory(1000, "/home/backup-user")

    assert directory == Path("/home/backup-user/.local/state/dar-backup/locks")
    assert private is True


def test_default_lock_directory_relative_home_raises() -> None:
    """An invalid registered home must fail instead of selecting another directory."""
    with pytest.raises(ValueError, match="must be an absolute path"):
        _default_lock_directory(1000, "relative/home")


def test_default_lock_directory_real_subprocess_ignores_environment() -> None:
    """HOME and XDG differences must not create separate lock domains."""
    child_script = (
        "from dar_backup.instance_lock import _resolve_default_lock_directory\n"
        "directory, private = _resolve_default_lock_directory()\n"
        "print(f'{directory}|{private}')\n"
    )
    first_environment = os.environ.copy()
    first_environment["HOME"] = "/tmp/first-home"
    first_environment["XDG_RUNTIME_DIR"] = "/tmp/first-runtime"
    second_environment = os.environ.copy()
    second_environment["HOME"] = "/tmp/second-home"
    second_environment.pop("XDG_RUNTIME_DIR", None)

    first = subprocess.run(
        [sys.executable, "-c", child_script],
        capture_output=True,
        text=True,
        check=False,
        env=first_environment,
    )
    second = subprocess.run(
        [sys.executable, "-c", child_script],
        capture_output=True,
        text=True,
        check=False,
        env=second_environment,
    )

    assert first.returncode == 0, first.stderr
    assert second.returncode == 0, second.stderr
    assert first.stdout == second.stdout
    if os.geteuid() != 0:
        registered_home = Path(pwd.getpwuid(os.geteuid()).pw_dir)
        assert first.stdout.strip() == (
            f"{registered_home / '.local/state/dar-backup/locks'}|True"
        )


def test_prepare_private_directory_unavailable_path_raises_without_fallback(
    tmp_path: Path,
) -> None:
    """An unusable selected directory must fail immediately.

    Args:
        tmp_path: Isolated filesystem directory provided by pytest.
    """
    blocking_file = tmp_path / "not-a-directory"
    blocking_file.write_text("block directory creation", encoding="utf-8")

    with pytest.raises(InstanceLockError, match="Cannot prepare private lock directory"):
        _prepare_private_directory(blocking_file / "locks")


def test_acquire_instance_lock_configured_directory_takes_precedence(
    tmp_path: Path,
) -> None:
    """An explicit safe directory must be used instead of either default.

    Args:
        tmp_path: Isolated filesystem directory provided by pytest.
    """
    configured_lock_dir = tmp_path / "configured-locks"
    configured_lock_dir.mkdir()

    instance_lock = acquire_instance_lock(
        str(tmp_path / "dar-backup.conf"),
        str(configured_lock_dir),
    )
    try:
        assert instance_lock.path.parent == configured_lock_dir
    finally:
        instance_lock.release()


def test_acquire_instance_lock_symlink_directory_raises(
    tmp_path: Path,
) -> None:
    """An explicitly configured directory symlink must fail closed.

    Args:
        tmp_path: Isolated filesystem directory provided by pytest.
    """
    real_directory = tmp_path / "real-locks"
    real_directory.mkdir()
    directory_link = tmp_path / "linked-locks"
    directory_link.symlink_to(real_directory, target_is_directory=True)

    with pytest.raises(InstanceLockError, match="Cannot open lock directory"):
        acquire_instance_lock(str(tmp_path / "dar-backup.conf"), str(directory_link))


def test_acquire_instance_lock_world_writable_configured_directory_raises(
    tmp_path: Path,
) -> None:
    """A world-writable configured directory without sticky protection must fail.

    Args:
        tmp_path: Isolated filesystem directory provided by pytest.
    """
    configured_lock_dir = tmp_path / "unsafe-locks"
    configured_lock_dir.mkdir()
    configured_lock_dir.chmod(0o777)

    with pytest.raises(InstanceLockError, match="world-writable without the sticky bit"):
        acquire_instance_lock(str(tmp_path / "dar-backup.conf"), str(configured_lock_dir))


def test_acquire_instance_lock_symlink_file_raises(
    tmp_path: Path,
) -> None:
    """A lock-file symlink must never be followed.

    Args:
        tmp_path: Isolated filesystem directory provided by pytest.
    """
    configured_lock_dir = tmp_path / "locks"
    configured_lock_dir.mkdir()
    first_lock = acquire_instance_lock(
        str(tmp_path / "dar-backup.conf"),
        str(configured_lock_dir),
    )
    lock_path = first_lock.path
    first_lock.release()
    lock_path.unlink()
    lock_path.symlink_to(tmp_path / "attacker-target")

    with pytest.raises(InstanceLockError, match="Cannot open existing instance lock"):
        acquire_instance_lock(str(tmp_path / "dar-backup.conf"), str(configured_lock_dir))


def test_acquire_instance_lock_hard_linked_file_raises(
    tmp_path: Path,
) -> None:
    """A lock file with another hard link must fail descriptor validation.

    Args:
        tmp_path: Isolated filesystem directory provided by pytest.
    """
    configured_lock_dir = tmp_path / "locks"
    configured_lock_dir.mkdir()
    first_lock = acquire_instance_lock(
        str(tmp_path / "dar-backup.conf"),
        str(configured_lock_dir),
    )
    lock_path = first_lock.path
    first_lock.release()
    os.link(lock_path, tmp_path / "second-link")

    with pytest.raises(InstanceLockError, match="exactly one hard link"):
        acquire_instance_lock(str(tmp_path / "dar-backup.conf"), str(configured_lock_dir))


def test_acquire_instance_lock_existing_read_only_file_is_reused_without_truncation(
    tmp_path: Path,
) -> None:
    """An existing readable lock inode must coordinate without modifying its data.

    Args:
        tmp_path: Isolated filesystem directory provided by pytest.
    """
    configured_lock_dir = tmp_path / "locks"
    configured_lock_dir.mkdir()
    first_lock = acquire_instance_lock(
        str(tmp_path / "dar-backup.conf"),
        str(configured_lock_dir),
    )
    lock_path = first_lock.path
    first_lock.release()
    lock_path.write_text("preserve this marker\n", encoding="utf-8")
    lock_path.chmod(0o444)

    second_lock = acquire_instance_lock(
        str(tmp_path / "dar-backup.conf"),
        str(configured_lock_dir),
    )
    second_lock.release()

    assert lock_path.read_text(encoding="utf-8") == "preserve this marker\n"


def test_acquire_instance_lock_real_subprocess_blocks_then_succeeds(
    tmp_path: Path,
) -> None:
    """Two real processes must exclude each other and permit reuse after release.

    Args:
        tmp_path: Isolated filesystem directory provided by pytest.
    """
    configured_lock_dir = tmp_path / "locks"
    configured_lock_dir.mkdir()
    config_path = tmp_path / "dar-backup.conf"
    parent_lock = acquire_instance_lock(str(config_path), str(configured_lock_dir))
    child_script = (
        "import sys\n"
        "from dar_backup.instance_lock import InstanceLockHeldError, acquire_instance_lock\n"
        "try:\n"
        "    lock = acquire_instance_lock(sys.argv[1], sys.argv[2])\n"
        "except InstanceLockHeldError:\n"
        "    raise SystemExit(23)\n"
        "lock.release()\n"
    )
    command = [
        sys.executable,
        "-c",
        child_script,
        str(config_path),
        str(configured_lock_dir),
    ]

    try:
        blocked = subprocess.run(command, capture_output=True, text=True, check=False)
        assert blocked.returncode == 23, blocked.stderr
    finally:
        parent_lock.release()

    after_release = subprocess.run(command, capture_output=True, text=True, check=False)
    assert after_release.returncode == 0, after_release.stderr
