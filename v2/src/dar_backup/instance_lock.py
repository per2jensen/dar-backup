# SPDX-License-Identifier: GPL-3.0-or-later
"""Secure per-configuration instance locking for backup runs."""

from __future__ import annotations

import fcntl
import os
import pwd
import stat
from dataclasses import dataclass
from pathlib import Path


class InstanceLockError(RuntimeError):
    """Raised when an instance lock cannot be created or validated safely."""


class InstanceLockHeldError(InstanceLockError):
    """Raised when another process already holds the requested instance lock."""


@dataclass
class InstanceLock:
    """Own one acquired advisory lock and its open file descriptor.

    Attributes:
        path: Absolute path naming the locked file.
    """

    path: Path
    _file_descriptor: int
    _released: bool = False

    def release(self) -> None:
        """Release the advisory lock and close its file descriptor.

        Returns:
            None.

        Raises:
            OSError: If unlocking or closing the descriptor fails.
        """
        if self._released:
            return

        fcntl.flock(self._file_descriptor, fcntl.LOCK_UN)
        os.close(self._file_descriptor)
        self._released = True


def _lock_filename(config_file: str) -> str:
    """Build the backward-compatible lock filename for a configuration path.

    Args:
        config_file: Configuration file identifying the backup operation.

    Returns:
        Filename used by existing dar-backup releases.

    Raises:
        ValueError: If the configuration path is empty or not a string.
    """
    if not isinstance(config_file, str) or not config_file.strip():
        raise ValueError("config_file must be a non-empty string")

    config_absolute = os.path.realpath(config_file)
    return config_absolute.replace("/", "_").replace(" ", "_").lstrip("_") + ".lock"


def _default_lock_directory(effective_uid: int, account_home: str) -> tuple[Path, bool]:
    """Select one default lock directory solely from the effective identity.

    Args:
        effective_uid: Effective user ID of the backup process.
        account_home: Registered home directory for a non-root account.

    Returns:
        Selected path and whether it is a private per-user directory.

    Raises:
        ValueError: If the effective user ID or account home is invalid.
    """
    if isinstance(effective_uid, bool) or not isinstance(effective_uid, int):
        # Input validation consistently reports invalid values through ValueError.
        raise ValueError("effective_uid must be an integer")  # noqa: TRY004
    if effective_uid < 0:
        raise ValueError("effective_uid must not be negative")
    if effective_uid == 0:
        return Path("/run/lock"), False

    if not isinstance(account_home, str) or not account_home.strip():
        raise ValueError("account_home must be a non-empty string for a non-root user")
    home_path = Path(account_home)
    if not home_path.is_absolute():
        raise ValueError(f"account_home must be an absolute path: {account_home!r}")
    return home_path / ".local" / "state" / "dar-backup" / "locks", True


def _resolve_default_lock_directory() -> tuple[Path, bool]:
    """Resolve the deterministic default for the current effective user.

    Returns:
        Selected path and whether it is a private per-user directory.

    Raises:
        InstanceLockError: If the effective non-root account cannot be resolved
            or its registered home directory is invalid.
    """
    effective_uid = os.geteuid()
    account_home = ""
    if effective_uid != 0:
        try:
            account_home = pwd.getpwuid(effective_uid).pw_dir
        except KeyError as exc:
            raise InstanceLockError(
                f"Cannot resolve a home directory for effective uid {effective_uid}"
            ) from exc

    try:
        return _default_lock_directory(effective_uid, account_home)
    except ValueError as exc:
        raise InstanceLockError(f"Cannot select the default lock directory: {exc}") from exc


def _prepare_private_directory(path: Path) -> None:
    """Create and validate a private per-user lock directory.

    Args:
        path: Absolute directory to create or validate.

    Returns:
        None.

    Raises:
        InstanceLockError: If the path is unsafe, has an unexpected owner, or
            grants any group or other permissions.
    """
    if not path.is_absolute():
        raise InstanceLockError(f"Private lock directory must be absolute: {path}")

    try:
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        path_status = path.lstat()
    except OSError as exc:
        raise InstanceLockError(f"Cannot prepare private lock directory {path}: {exc}") from exc

    if stat.S_ISLNK(path_status.st_mode) or not stat.S_ISDIR(path_status.st_mode):
        raise InstanceLockError(f"Private lock directory is not a real directory: {path}")
    if path_status.st_uid != os.geteuid():
        raise InstanceLockError(
            f"Private lock directory {path} is owned by uid {path_status.st_uid}, "
            f"expected {os.geteuid()}"
        )
    if stat.S_IMODE(path_status.st_mode) & 0o077:
        raise InstanceLockError(
            f"Private lock directory {path} must not grant group or other permissions"
        )


def _open_directory(path: Path, *, private: bool, configured: bool) -> int:
    """Open and validate a lock directory without following its final symlink.

    Args:
        path: Absolute directory to open.
        private: Whether private ownership and mode requirements apply.
        configured: Whether this is an operator-supplied directory.

    Returns:
        Open directory file descriptor.

    Raises:
        InstanceLockError: If the directory is unsafe or cannot be opened.
    """
    if not path.is_absolute():
        raise InstanceLockError(f"Lock directory must be absolute: {path}")

    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        directory_fd = os.open(path, flags)
    except OSError as exc:
        raise InstanceLockError(f"Cannot open lock directory {path}: {exc}") from exc

    try:
        directory_status = os.fstat(directory_fd)
        if not stat.S_ISDIR(directory_status.st_mode):
            raise InstanceLockError(f"Lock path is not a directory: {path}")
        if private:
            if directory_status.st_uid != os.geteuid():
                raise InstanceLockError(
                    f"Private lock directory {path} is owned by uid "
                    f"{directory_status.st_uid}, expected {os.geteuid()}"
                )
            if stat.S_IMODE(directory_status.st_mode) & 0o077:
                raise InstanceLockError(
                    f"Private lock directory {path} must not grant group or other permissions"
                )
        if configured:
            mode = stat.S_IMODE(directory_status.st_mode)
            if directory_status.st_uid not in {0, os.geteuid()}:
                raise InstanceLockError(
                    f"Configured lock directory {path} must be owned by root or uid {os.geteuid()}"
                )
            if mode & stat.S_IWOTH and not mode & stat.S_ISVTX:
                raise InstanceLockError(
                    f"Configured lock directory {path} is world-writable without the sticky bit"
                )
    except BaseException:
        os.close(directory_fd)
        raise

    return directory_fd


def _open_lock_file(
    directory_fd: int,
    directory: Path,
    filename: str,
) -> int:
    """Open or create one lock file relative to a validated directory.

    Args:
        directory_fd: Open descriptor for the containing directory.
        directory: Human-readable absolute directory path for diagnostics.
        filename: Lock filename without path separators.
    Returns:
        Open lock-file descriptor.

    Raises:
        InstanceLockError: If the file is unsafe or cannot be opened.
    """
    flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        return os.open(filename, flags, 0o644, dir_fd=directory_fd)
    except OSError as create_error:
        try:
            existing_status = os.stat(filename, dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            existing_status = None
        except OSError as stat_error:
            raise InstanceLockError(
                f"Cannot inspect instance lock {directory / filename}: {stat_error}"
            ) from stat_error

        if existing_status is not None:
            try:
                return os.open(
                    filename,
                    os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                    dir_fd=directory_fd,
                )
            except OSError as read_error:
                raise InstanceLockError(
                    f"Cannot open existing instance lock {directory / filename}: {read_error}"
                ) from read_error

        raise InstanceLockError(
            f"Cannot create instance lock {directory / filename}: {create_error}"
        ) from create_error


def _acquire_from_directory(
    directory: Path,
    filename: str,
    *,
    private: bool,
    configured: bool,
) -> InstanceLock:
    """Securely open and acquire a lock below one candidate directory.

    Args:
        directory: Absolute lock directory.
        filename: Lock filename identifying the configuration.
        private: Whether strict private-directory checks apply.
        configured: Whether the operator explicitly selected this directory.
    Returns:
        Acquired instance lock owned by the caller.

    Raises:
        InstanceLockError: If validation or acquisition fails.
        InstanceLockHeldError: If another process holds the same lock.
    """
    directory_fd = _open_directory(directory, private=private, configured=configured)
    try:
        lock_fd = _open_lock_file(
            directory_fd,
            directory,
            filename,
        )
    finally:
        os.close(directory_fd)

    lock_path = directory / filename
    try:
        lock_status = os.fstat(lock_fd)
        if not stat.S_ISREG(lock_status.st_mode):
            raise InstanceLockError(f"Instance lock is not a regular file: {lock_path}")
        if lock_status.st_nlink != 1:
            raise InstanceLockError(
                f"Instance lock must have exactly one hard link: {lock_path}"
            )
        # Lock files contain no data. Keeping an owner-created file readable
        # allows another account in an administrator-provisioned shared
        # directory to open the same inode and participate in flock().
        if lock_status.st_uid == os.geteuid() and stat.S_IMODE(lock_status.st_mode) & 0o444 != 0o444:
            os.fchmod(lock_fd, stat.S_IMODE(lock_status.st_mode) | 0o444)
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise InstanceLockHeldError(
                f"Another dar-backup instance is already running (lock: {lock_path})"
            ) from exc
    except BaseException:
        os.close(lock_fd)
        raise

    return InstanceLock(path=lock_path, _file_descriptor=lock_fd)


def acquire_instance_lock(
    config_file: str,
    configured_lock_dir: str | None = None,
) -> InstanceLock:
    """Acquire the deterministic instance lock for one configuration.

    Args:
        config_file: Configuration file identifying mutually exclusive runs.
        configured_lock_dir: Optional operator-selected shared lock directory.

    Returns:
        Acquired lock that the caller must release in a ``finally`` block.

    Raises:
        ValueError: If ``config_file`` is invalid.
        InstanceLockError: If no safe lock can be acquired.
        InstanceLockHeldError: If another process already holds the lock.
    """
    filename = _lock_filename(config_file)

    if configured_lock_dir is not None:
        if not isinstance(configured_lock_dir, str):
            raise InstanceLockError("Configured lock directory must be a string")
        configured_value = configured_lock_dir.strip()
        if not configured_value:
            raise InstanceLockError("Configured lock directory must not be empty")
        return _acquire_from_directory(
            Path(configured_value),
            filename,
            private=False,
            configured=True,
        )

    default_directory, private = _resolve_default_lock_directory()
    if private:
        _prepare_private_directory(default_directory)
    return _acquire_from_directory(
        default_directory,
        filename,
        private=private,
        configured=False,
    )
