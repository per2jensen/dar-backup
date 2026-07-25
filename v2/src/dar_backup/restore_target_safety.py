# SPDX-License-Identifier: GPL-3.0-or-later

"""Shared restore-target protection, locking, and overwrite checks."""

import errno
import fcntl
import logging
import os
import stat
from contextlib import contextmanager
from dataclasses import dataclass
from enum import Enum
from typing import Iterator, Sequence


logger = logging.getLogger("main_logger")


class ExistingDataPolicy(Enum):
    """Policy for data already present below a restore target."""

    REQUIRE_EMPTY = "require_empty"
    REJECT_SELECTED_PATHS = "reject_selected_paths"
    ALLOW_OVERWRITE = "allow_overwrite"


@dataclass(frozen=True)
class RestoreTargetPolicy:
    """Independent location and existing-data policies for a restore target.

    Attributes:
        existing_data: How existing entries below the target are handled.
        allow_protected_target: Whether protected system directories are
            permitted. No CLI currently enables this.
    """

    existing_data: ExistingDataPolicy
    allow_protected_target: bool = False


class RestoreTargetError(RuntimeError):
    """Raised when a restore target fails a safety or locking check."""


@dataclass(frozen=True)
class RestoreTargetHandle:
    """Stable reference to a validated restore target.

    Attributes:
        requested_path: Restore path supplied by the caller.
        canonical_path: Resolved path opened during target preparation.
        directory_fd: Open descriptor for the validated target directory.
        dar_root: Descriptor-backed path to pass to DAR as its filesystem root.
    """

    requested_path: str
    canonical_path: str
    directory_fd: int
    dar_root: str

    @property
    def pass_fds(self) -> tuple[int, ...]:
        """Return descriptors that must be inherited by the DAR process.

        Returns:
            A one-item tuple containing the restore target descriptor.
        """
        return (self.directory_fd,)


def restore_target_unsafe_reason(target: str) -> str | None:
    """Return why a restore target is protected, if applicable.

    Args:
        target: Restore target path to validate.

    Returns:
        A human-readable rejection reason, or None when the location is
        permitted by the default protection policy.

    Raises:
        ValueError: If target is empty.
    """
    if not target:
        raise ValueError("target must not be empty")

    # realpath() follows target symlinks and normalizes traversal components,
    # preventing a path under an allowed prefix from disguising /etc or another
    # protected destination.
    target_norm = os.path.realpath(target)
    allow_prefixes = (
        "/tmp",  # noqa: S108
        "/var/tmp",  # noqa: S108
        "/home",
    )
    if target_norm in allow_prefixes or any(target_norm.startswith(prefix + os.sep) for prefix in allow_prefixes):
        return None

    protected_prefixes = (
        "/bin",
        "/sbin",
        "/usr",
        "/etc",
        "/lib",
        "/lib64",
        "/boot",
        "/proc",
        "/sys",
        "/dev",
        "/var",
        "/root",
    )
    if target_norm == "/" or target_norm in protected_prefixes:
        return f"Restore target '{target_norm}' is a protected system directory. Choose a safer location."
    if any(target_norm.startswith(prefix + os.sep) for prefix in protected_prefixes):
        return f"Restore target '{target_norm}' is under a protected system directory. Choose a safer location."
    return None


def validate_restore_target_location(target: str, policy: RestoreTargetPolicy) -> str:
    """Validate target location policy without creating or opening the target.

    Args:
        target: Restore target path to validate.
        policy: Protection and existing-data policy for the operation.

    Returns:
        Canonical target path.

    Raises:
        ValueError: If target is empty.
        TypeError: If policy has the wrong type.
        RestoreTargetError: If the target is protected by policy.
    """
    if not target:
        raise ValueError("target must not be empty")
    if not isinstance(policy, RestoreTargetPolicy):
        raise TypeError("policy must be a RestoreTargetPolicy")

    canonical_target = os.path.realpath(target)
    if policy.allow_protected_target:
        return canonical_target

    unsafe_reason = restore_target_unsafe_reason(target)
    if unsafe_reason:
        raise RestoreTargetError(unsafe_reason)
    return canonical_target


def _normalize_selected_paths(selected_paths: Sequence[str]) -> tuple[str, ...]:
    """Validate and normalize selected archive paths.

    Args:
        selected_paths: Relative paths expected to be written below the target.

    Returns:
        Normalized relative paths.

    Raises:
        ValueError: If a path is empty, absolute, or contains ``..``.
    """
    normalized: list[str] = []
    for path in selected_paths:
        if not path or not path.strip():
            raise ValueError("selected paths must not contain empty values")
        if os.path.isabs(path):
            raise ValueError(f"selected path must be relative: {path}")
        if ".." in path.split(os.sep):
            raise ValueError(f"selected path must not contain '..': {path}")
        normalized.append(os.path.normpath(path))
    return tuple(normalized)


def _extended_acl_present(directory_fd: int) -> bool:
    """Return whether a directory has an extended POSIX access/default ACL.

    Args:
        directory_fd: Open descriptor for the directory to inspect.

    Returns:
        True when an extended ACL is present; False when ACLs are absent or
        unsupported by the filesystem.

    Raises:
        OSError: If ACL metadata exists but cannot be inspected safely.
    """
    absent_errnos = {
        errno.ENODATA,
        errno.ENOTSUP,
        getattr(errno, "EOPNOTSUPP", errno.ENOTSUP),
    }
    for attribute in ("system.posix_acl_access", "system.posix_acl_default"):
        try:
            if os.getxattr(directory_fd, attribute):
                return True
        except OSError as exc:
            if exc.errno in absent_errnos:
                continue
            raise
    return False


def _exclusive_control_reason(directory_fd: int, display_path: str, effective_uid: int) -> str | None:
    """Return why a privileged restore directory is not exclusively controlled.

    Args:
        directory_fd: Open descriptor for the directory to inspect.
        display_path: Operator-facing path used in any error.
        effective_uid: UID performing the restore.

    Returns:
        A human-readable rejection reason, or None when the directory is owned
        by the restoring UID and is not writable by group/other identities.

    Raises:
        OSError: If directory metadata or ACLs cannot be inspected.
    """
    directory_stat = os.fstat(directory_fd)
    if directory_stat.st_uid != effective_uid:
        return (
            f"Privileged restore path '{display_path}' is owned by uid "
            f"{directory_stat.st_uid}, not the restoring uid {effective_uid}. "
            "Use a restore target exclusively controlled by the restoring user, "
            "run the restore as the target owner, or stop other writers."
        )
    if stat.S_IMODE(directory_stat.st_mode) & 0o022:
        return (
            f"Privileged restore path '{display_path}' is writable by its group "
            "or other users. Remove group/other write access or stop other writers "
            "before restoring."
        )
    if _extended_acl_present(directory_fd):
        return (
            f"Privileged restore path '{display_path}' has an extended POSIX ACL, "
            "so exclusive control cannot be established. Remove the ACL or use a "
            "private restore target."
        )
    return None


def _inspect_selected_path(
    target: str,
    target_fd: int,
    rel_path: str,
    effective_uid: int,
) -> tuple[str | None, bool]:
    """Inspect one selected path without reopening the restore target pathname.

    Args:
        target: Operator-facing canonical restore target.
        target_fd: Open descriptor for the restore target.
        rel_path: Normalized relative selected path.
        effective_uid: UID performing the restore.

    Returns:
        A tuple of ``(unsafe_reason, exists)``. ``unsafe_reason`` is populated
        for a symlink or privileged-control violation. ``exists`` is True when
        the selected path or a blocking non-directory component already exists.

    Raises:
        OSError: If an existing component cannot be inspected or opened safely.
    """
    current_fd = os.dup(target_fd)
    current_display = target
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    try:
        parts = [part for part in rel_path.split(os.sep) if part and part != "."]
        for index, part in enumerate(parts):
            component_display = os.path.join(current_display, part)
            try:
                component_stat = os.stat(part, dir_fd=current_fd, follow_symlinks=False)
            except FileNotFoundError:
                return None, False

            if stat.S_ISLNK(component_stat.st_mode):
                return (
                    f"'{component_display}' inside the restore target is a symlink — restoring through it "
                    "could write outside the target. Remove it or use a clean/empty target.",
                    True,
                )

            is_last = index == len(parts) - 1
            if not stat.S_ISDIR(component_stat.st_mode):
                return None, True
            if is_last and effective_uid != 0:
                return None, True

            next_fd = os.open(part, directory_flags, dir_fd=current_fd)
            os.close(current_fd)
            current_fd = next_fd
            current_display = component_display

            if effective_uid == 0:
                control_reason = _exclusive_control_reason(current_fd, current_display, effective_uid)
                if control_reason:
                    return control_reason, True
            if is_last:
                return None, True
        return None, False
    finally:
        os.close(current_fd)


def _validate_existing_data(
    target: str,
    target_fd: int,
    policy: RestoreTargetPolicy,
    selected_paths: Sequence[str],
) -> None:
    """Apply existing-data and selected-path symlink policy.

    Args:
        target: Existing, locked restore target directory.
        target_fd: Open descriptor for the restore target.
        policy: Existing-data policy for the restore.
        selected_paths: Relative paths expected to be written.

    Raises:
        ValueError: If selected paths are invalid or required but absent.
        OSError: If the target cannot be scanned.
        RestoreTargetError: If existing data or a symlink conflicts with
            policy.
    """
    normalized_paths = _normalize_selected_paths(selected_paths)
    effective_uid = os.geteuid()

    if policy.existing_data is ExistingDataPolicy.REQUIRE_EMPTY:
        with os.scandir(target_fd) as entries:
            if next(entries, None) is not None:
                raise RestoreTargetError(
                    f"Restore target '{target}' is not empty. This restore can write anywhere under the target, "
                    f"so it refuses to continue. Use a clean/empty target."
                )
        return

    if policy.existing_data is ExistingDataPolicy.REJECT_SELECTED_PATHS:
        if not normalized_paths:
            raise ValueError("selected_paths are required when rejecting selected paths")
        existing: list[str] = []
        for rel_path in normalized_paths:
            if rel_path == ".":
                raise ValueError("archive-root path '.' requires the empty-target policy")
            unsafe_reason, path_exists = _inspect_selected_path(target, target_fd, rel_path, effective_uid)
            if unsafe_reason:
                raise RestoreTargetError(unsafe_reason)
            if path_exists:
                existing.append(rel_path)
        if existing:
            sample = ", ".join(existing[:3])
            extra = f" (+{len(existing) - 3} more)" if len(existing) > 3 else ""
            raise RestoreTargetError(
                f"Restore target '{target}' already contains path(s) to restore: {sample}{extra}. "
                f"For safety, restores abort without overwriting existing files. Use a clean/empty target."
            )
        return

    if policy.existing_data is ExistingDataPolicy.ALLOW_OVERWRITE:
        for rel_path in normalized_paths:
            unsafe_reason, _path_exists = _inspect_selected_path(target, target_fd, rel_path, effective_uid)
            if unsafe_reason:
                raise RestoreTargetError(unsafe_reason)
        return

    raise ValueError(f"Unsupported existing-data policy: {policy.existing_data!r}")


@contextmanager
def prepare_restore_target(
    target: str,
    policy: RestoreTargetPolicy,
    selected_paths: Sequence[str] = (),
) -> Iterator[RestoreTargetHandle]:
    """Validate, create, lock, and hold a restore target for an operation.

    Args:
        target: Restore destination directory.
        policy: Location and existing-data policy for the operation.
        selected_paths: Relative paths expected to be written. Required for
            ``REJECT_SELECTED_PATHS``.

    Yields:
        A stable target handle while the directory lock is held.

    Raises:
        ValueError: If inputs are invalid.
        RestoreTargetError: If target validation, creation, locking, or
            existing-data checks fail.
    """
    canonical_target = validate_restore_target_location(target, policy)

    try:
        os.makedirs(target, exist_ok=True)
    except OSError as exc:
        raise RestoreTargetError(f"Could not create restore target '{target}': {exc}") from exc

    # Resolve again after creation so a replacement during makedirs() cannot
    # retain the pre-creation location decision.
    canonical_target = validate_restore_target_location(target, policy)
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        raise RestoreTargetError("This platform lacks O_NOFOLLOW/O_DIRECTORY support required for safe restores.")

    try:
        expected_stat = os.stat(canonical_target, follow_symlinks=False)
    except OSError as exc:
        raise RestoreTargetError(f"Could not inspect restore target '{target}' before opening it: {exc}") from exc
    if not stat.S_ISDIR(expected_stat.st_mode):
        raise RestoreTargetError(f"Restore target '{target}' is not a directory.")

    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    try:
        lock_fd = os.open(canonical_target, flags)
    except OSError as exc:
        raise RestoreTargetError(f"Could not open restore target '{target}' for locking: {exc}") from exc

    locked = False
    try:
        opened_stat = os.fstat(lock_fd)
        if (opened_stat.st_dev, opened_stat.st_ino) != (expected_stat.st_dev, expected_stat.st_ino):
            raise RestoreTargetError(
                f"Restore target '{target}' changed while it was being opened; refusing to continue."
            )

        dar_root = f"/proc/self/fd/{lock_fd}"
        try:
            os.readlink(dar_root)
        except OSError as exc:
            raise RestoreTargetError(
                "The /proc/self/fd interface required for safe restores is unavailable."
            ) from exc
        opened_path = os.path.realpath(dar_root)
        if opened_path != canonical_target:
            raise RestoreTargetError(
                f"Restore target '{target}' changed from '{canonical_target}' to "
                f"'{opened_path}' while it was being prepared; refusing to continue."
            )
        validate_restore_target_location(opened_path, policy)

        effective_uid = os.geteuid()
        if effective_uid == 0:
            control_reason = _exclusive_control_reason(lock_fd, opened_path, effective_uid)
            if control_reason:
                raise RestoreTargetError(control_reason)

        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            locked = True
        except BlockingIOError as exc:
            raise RestoreTargetError(f"Restore target '{target}' is locked by a concurrent restore; refusing to continue.") from exc
        except OSError as exc:
            raise RestoreTargetError(f"Could not lock restore target '{target}': {exc}") from exc

        try:
            _validate_existing_data(target, lock_fd, policy, selected_paths)
        except OSError as exc:
            raise RestoreTargetError(f"Could not inspect restore target '{target}': {exc}") from exc

        yield RestoreTargetHandle(
            requested_path=target,
            canonical_path=opened_path,
            directory_fd=lock_fd,
            dar_root=dar_root,
        )
    finally:
        if locked:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
            except OSError as exc:
                logger.warning("Could not unlock restore target '%s': %s", target, exc)
        try:
            os.close(lock_fd)
        except OSError as exc:
            logger.warning("Could not close restore target lock for '%s': %s", target, exc)
