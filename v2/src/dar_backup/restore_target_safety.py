# SPDX-License-Identifier: GPL-3.0-or-later

"""Shared restore-target protection, locking, and overwrite checks."""

import fcntl
import logging
import os
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


def _symlink_component_reason(target: str, rel_path: str) -> str | None:
    """Return why an existing selected-path component is unsafe.

    Args:
        target: Existing restore target directory.
        rel_path: Normalized relative selected path.

    Returns:
        A human-readable rejection reason, or None when no component is a
        symlink.
    """
    current = target
    for part in rel_path.split(os.sep):
        if not part or part == ".":
            continue
        current = os.path.join(current, part)
        if os.path.islink(current):
            return (
                f"'{current}' inside the restore target is a symlink — restoring through it "
                f"could write outside the target. Remove it or use a clean/empty target."
            )
    return None


def _validate_existing_data(
    target: str,
    policy: RestoreTargetPolicy,
    selected_paths: Sequence[str],
) -> None:
    """Apply existing-data and selected-path symlink policy.

    Args:
        target: Existing, locked restore target directory.
        policy: Existing-data policy for the restore.
        selected_paths: Relative paths expected to be written.

    Raises:
        ValueError: If selected paths are invalid or required but absent.
        OSError: If the target cannot be scanned.
        RestoreTargetError: If existing data or a symlink conflicts with
            policy.
    """
    normalized_paths = _normalize_selected_paths(selected_paths)

    if policy.existing_data is ExistingDataPolicy.REQUIRE_EMPTY:
        with os.scandir(target) as entries:
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
            symlink_reason = _symlink_component_reason(target, rel_path)
            if symlink_reason:
                raise RestoreTargetError(symlink_reason)
            if os.path.lexists(os.path.join(target, rel_path)):
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
            symlink_reason = _symlink_component_reason(target, rel_path)
            if symlink_reason:
                raise RestoreTargetError(symlink_reason)
        return

    raise ValueError(f"Unsupported existing-data policy: {policy.existing_data!r}")


@contextmanager
def prepare_restore_target(
    target: str,
    policy: RestoreTargetPolicy,
    selected_paths: Sequence[str] = (),
) -> Iterator[None]:
    """Validate, create, lock, and hold a restore target for an operation.

    Args:
        target: Restore destination directory.
        policy: Location and existing-data policy for the operation.
        selected_paths: Relative paths expected to be written. Required for
            ``REJECT_SELECTED_PATHS``.

    Yields:
        Control while the target directory lock is held.

    Raises:
        ValueError: If inputs are invalid.
        RestoreTargetError: If target validation, creation, locking, or
            existing-data checks fail.
    """
    validate_restore_target_location(target, policy)

    try:
        os.makedirs(target, exist_ok=True)
    except OSError as exc:
        raise RestoreTargetError(f"Could not create restore target '{target}': {exc}") from exc
    if not os.path.isdir(target):
        raise RestoreTargetError(f"Restore target '{target}' is not a directory.")

    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    try:
        lock_fd = os.open(target, flags)
    except OSError as exc:
        raise RestoreTargetError(f"Could not open restore target '{target}' for locking: {exc}") from exc

    try:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise RestoreTargetError(f"Restore target '{target}' is locked by a concurrent restore; refusing to continue.") from exc
        except OSError as exc:
            raise RestoreTargetError(f"Could not lock restore target '{target}': {exc}") from exc

        try:
            _validate_existing_data(target, policy, selected_paths)
        except OSError as exc:
            raise RestoreTargetError(f"Could not inspect restore target '{target}': {exc}") from exc

        yield
    finally:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
        except OSError as exc:
            logger.warning("Could not unlock restore target '%s': %s", target, exc)
        try:
            os.close(lock_fd)
        except OSError as exc:
            logger.warning("Could not close restore target lock for '%s': %s", target, exc)
