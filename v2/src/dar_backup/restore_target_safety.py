# SPDX-License-Identifier: GPL-3.0-or-later

"""Shared restore-target protection, locking, and overwrite checks."""

import errno
import fcntl
import grp
import logging
import os
import pwd
import stat
import time
from contextlib import contextmanager
from dataclasses import dataclass
from enum import Enum
from typing import Iterator, Sequence


logger = logging.getLogger("main_logger")

MAX_OVERWRITE_PREFLIGHT_PROBLEMS = 100


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
        force_unsafe_restore_target: Whether root explicitly chose to continue
            past policy findings from an overwrite preflight. Structural
            restore-target protections are never bypassed.
    """

    existing_data: ExistingDataPolicy
    allow_protected_target: bool = False
    force_unsafe_restore_target: bool = False


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


class RestoreSafetyFindingKind(Enum):
    """Classification of one overwrite preflight safety finding."""

    UNTRUSTED_OWNER = "untrusted_owner"
    UNSAFE_GROUP_WRITE = "unsafe_group_write"
    OTHER_WRITE = "other_write"
    EXTENDED_ACL = "extended_acl"
    INSPECTION_FAILURE = "inspection_failure"
    SELECTED_PATH_SYMLINK = "selected_path_symlink"


@dataclass(frozen=True)
class RestoreSafetyFinding:
    """One typed overwrite preflight finding.

    Attributes:
        kind: Stable category used to enforce the override boundary.
        message: Operator-facing explanation of the problem.
        root_overridable: Whether root's explicit break-glass option may waive
            this finding after the complete bounded audit.
    """

    kind: RestoreSafetyFindingKind
    message: str
    root_overridable: bool


@dataclass(frozen=True)
class NssUser:
    """Minimal immutable passwd identity used during snapshot resolution.

    Attributes:
        name: Login name.
        uid: Numeric user identifier.
        primary_gid: Numeric primary group identifier.
    """

    name: str
    uid: int
    primary_gid: int


@dataclass(frozen=True)
class NssGroup:
    """Minimal immutable group identity used during snapshot resolution.

    Attributes:
        name: Group name.
        gid: Numeric group identifier.
        explicit_members: Supplementary member names from the group database.
    """

    name: str
    gid: int
    explicit_members: tuple[str, ...]


@dataclass(frozen=True)
class GroupIdentity:
    """Resolved membership for one NSS group.

    Attributes:
        gid: Numeric group identifier.
        name: NSS group name, or a display placeholder when ambiguous.
        members: Distinct ``(username, uid)`` identities in the group, including
            primary-GID and explicit supplementary membership.
        resolution_error: Why membership could not be resolved unambiguously.
    """

    gid: int
    name: str
    members: tuple[tuple[str, int], ...]
    resolution_error: str | None = None


@dataclass(frozen=True)
class IdentitySnapshot:
    """Immutable per-preflight snapshot of NSS user and group membership.

    Attributes:
        groups: Resolved groups indexed by lookup through :meth:`group_for_gid`.
        resolution_error: Snapshot-wide ambiguity or lookup failure.
    """

    groups: tuple[GroupIdentity, ...]
    resolution_error: str | None = None

    def group_for_gid(self, gid: int) -> GroupIdentity | None:
        """Return the resolved group for a numeric GID.

        Args:
            gid: Numeric group identifier to find.

        Returns:
            The matching group, or None when NSS did not enumerate it.

        Raises:
            ValueError: If gid is negative.
        """
        if gid < 0:
            raise ValueError("gid must not be negative")
        return next((group for group in self.groups if group.gid == gid), None)


@dataclass(frozen=True)
class OverwritePreflightStats:
    """Summary of an overwrite restore-target preflight.

    Attributes:
        entries: Number of filesystem entries inspected.
        directories: Number of directories inspected, including the target.
        symlinks: Number of symlinks observed without following them.
        elapsed_seconds: Elapsed preflight time.
        findings: Distinct safety problems found during the audit.
        problem_limit_reached: Whether scanning stopped at the configured
            problem limit and additional problems may exist.
    """

    entries: int
    directories: int
    symlinks: int
    elapsed_seconds: float
    findings: tuple[RestoreSafetyFinding, ...]
    problem_limit_reached: bool


def _build_identity_snapshot() -> IdentitySnapshot:
    """Build one immutable NSS snapshot for an overwrite preflight.

    Primary group membership from the passwd database is combined with
    supplementary membership from the group database. Ambiguous identities
    fail closed instead of making a best-effort security decision.

    Returns:
        An immutable snapshot of groups and their resolved member UIDs.
    """
    try:
        users = tuple(
            NssUser(
                name=user.pw_name,
                uid=user.pw_uid,
                primary_gid=user.pw_gid,
            )
            for user in pwd.getpwall()
        )
        groups = tuple(
            NssGroup(
                name=group.gr_name,
                gid=group.gr_gid,
                explicit_members=tuple(group.gr_mem),
            )
            for group in grp.getgrall()
        )
    except OSError as exc:
        return IdentitySnapshot(
            groups=(),
            resolution_error=f"could not enumerate NSS identities: {exc}",
        )

    return _resolve_identity_snapshot(users, groups)


def _resolve_identity_snapshot(
    users: Sequence[NssUser],
    groups: Sequence[NssGroup],
) -> IdentitySnapshot:
    """Resolve immutable passwd/group records into exact group membership.

    Args:
        users: Frozen passwd identities from one NSS enumeration.
        groups: Frozen group identities from the same preflight.

    Returns:
        An immutable, fail-closed group-membership snapshot.
    """
    if not users:
        return IdentitySnapshot(groups=(), resolution_error="NSS returned no user identities")
    if not groups:
        return IdentitySnapshot(groups=(), resolution_error="NSS returned no group identities")

    users_by_name: dict[str, list[tuple[str, int, int]]] = {}
    users_by_uid: dict[int, list[tuple[str, int, int]]] = {}
    for user in users:
        identity = (user.name, user.uid, user.primary_gid)
        users_by_name.setdefault(user.name, []).append(identity)
        users_by_uid.setdefault(user.uid, []).append(identity)

    duplicate_names = sorted(name for name, records in users_by_name.items() if len(records) != 1)
    duplicate_uids = sorted(uid for uid, records in users_by_uid.items() if len(records) != 1)
    if duplicate_names or duplicate_uids:
        details: list[str] = []
        if duplicate_names:
            details.append(f"duplicate username(s): {', '.join(duplicate_names)}")
        if duplicate_uids:
            details.append(f"duplicate uid(s): {', '.join(str(uid) for uid in duplicate_uids)}")
        return IdentitySnapshot(
            groups=(),
            resolution_error=f"NSS user identities are ambiguous ({'; '.join(details)})",
        )

    groups_by_gid: dict[int, list[NssGroup]] = {}
    for group in groups:
        groups_by_gid.setdefault(group.gid, []).append(group)

    resolved_groups: list[GroupIdentity] = []
    for gid, group_records in sorted(groups_by_gid.items()):
        if len(group_records) != 1:
            names = ", ".join(sorted(group.name for group in group_records))
            resolved_groups.append(
                GroupIdentity(
                    gid=gid,
                    name=f"gid {gid}",
                    members=(),
                    resolution_error=f"NSS returned multiple groups for gid {gid}: {names}",
                )
            )
            continue

        group = group_records[0]
        member_identities: dict[int, str] = {
            user.uid: user.name
            for user in users
            if user.primary_gid == gid
        }
        member_errors: list[str] = []
        for member_name in group.explicit_members:
            member_records = users_by_name.get(member_name, [])
            if len(member_records) != 1:
                member_errors.append(
                    f"member '{member_name}' did not resolve to exactly one user"
                )
                continue
            resolved_name, member_uid, _primary_gid = member_records[0]
            member_identities[member_uid] = resolved_name

        resolved_groups.append(
            GroupIdentity(
                gid=gid,
                name=group.name,
                members=tuple(
                    sorted(
                        ((name, uid) for uid, name in member_identities.items()),
                        key=lambda member: (member[1], member[0]),
                    )
                ),
                resolution_error="; ".join(member_errors) if member_errors else None,
            )
        )

    return IdentitySnapshot(groups=tuple(resolved_groups))


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


def _exclusive_control_reasons(
    directory_fd: int,
    display_path: str,
    trusted_uids: frozenset[int],
    identity_snapshot: IdentitySnapshot,
    group_write_cache: dict[tuple[int, int], RestoreSafetyFinding | None],
) -> tuple[RestoreSafetyFinding, ...]:
    """Return every exclusive-control problem found for one directory.

    Args:
        directory_fd: Open descriptor for the directory to inspect.
        display_path: Operator-facing path used in any error.
        trusted_uids: UIDs permitted to own directories in the restore target.
        identity_snapshot: Immutable NSS identity view for this preflight.
        group_write_cache: Per-preflight group-policy result cache keyed by
            ``(gid, owner_uid)``.

    Returns:
        Typed rejection findings. The tuple is empty when the
        directory owner is trusted and group, other, and extended ACL access
        cannot write it, except for a group whose sole resolved member is the
        directory owner.

    Raises:
        ValueError: If trusted_uids is empty.
        OSError: If directory metadata or ACLs cannot be inspected.
    """
    if not trusted_uids:
        raise ValueError("trusted_uids must not be empty")

    findings: list[RestoreSafetyFinding] = []
    directory_stat = os.fstat(directory_fd)
    if directory_stat.st_uid not in trusted_uids:
        trusted_display = ", ".join(str(uid) for uid in sorted(trusted_uids))
        findings.append(
            RestoreSafetyFinding(
                kind=RestoreSafetyFindingKind.UNTRUSTED_OWNER,
                message=(
                    f"directory '{display_path}' is owned by untrusted uid "
                    f"{directory_stat.st_uid}; trusted uid(s): {trusted_display}."
                ),
                root_overridable=True,
            )
        )

    mode = stat.S_IMODE(directory_stat.st_mode)
    if mode & stat.S_IWGRP:
        cache_key = (directory_stat.st_gid, directory_stat.st_uid)
        group_finding = group_write_cache.get(cache_key)
        if cache_key not in group_write_cache:
            group_finding = _unsafe_group_write_finding(
                gid=directory_stat.st_gid,
                owner_uid=directory_stat.st_uid,
                identity_snapshot=identity_snapshot,
            )
            group_write_cache[cache_key] = group_finding
        if group_finding:
            findings.append(
                RestoreSafetyFinding(
                    kind=group_finding.kind,
                    message=f"directory '{display_path}' {group_finding.message}",
                    root_overridable=group_finding.root_overridable,
                )
            )

    if mode & stat.S_IWOTH:
        findings.append(
            RestoreSafetyFinding(
                kind=RestoreSafetyFindingKind.OTHER_WRITE,
                message=(
                    f"directory '{display_path}' is writable by other users "
                    "(the other-write permission is set)."
                ),
                root_overridable=True,
            )
        )
    if _extended_acl_present(directory_fd):
        findings.append(
            RestoreSafetyFinding(
                kind=RestoreSafetyFindingKind.EXTENDED_ACL,
                message=(
                    f"directory '{display_path}' has an extended POSIX ACL, so "
                    "exclusive control cannot be established."
                ),
                root_overridable=True,
            )
        )
    return tuple(findings)


def _unsafe_group_write_finding(
    gid: int,
    owner_uid: int,
    identity_snapshot: IdentitySnapshot,
) -> RestoreSafetyFinding | None:
    """Evaluate whether group write grants access to another identity.

    Args:
        gid: Directory group identifier.
        owner_uid: Directory owner identifier.
        identity_snapshot: Immutable NSS identity view for this preflight.

    Returns:
        A policy finding when group write is unsafe or cannot be resolved;
        otherwise None when the owner is the group's sole member.

    Raises:
        ValueError: If gid or owner_uid is negative.
    """
    if gid < 0:
        raise ValueError("gid must not be negative")
    if owner_uid < 0:
        raise ValueError("owner_uid must not be negative")

    if identity_snapshot.resolution_error:
        return RestoreSafetyFinding(
            kind=RestoreSafetyFindingKind.UNSAFE_GROUP_WRITE,
            message=(
                f"is group-writable through gid {gid}, but membership could not "
                f"be verified: {identity_snapshot.resolution_error}."
            ),
            root_overridable=True,
        )

    group = identity_snapshot.group_for_gid(gid)
    if group is None:
        return RestoreSafetyFinding(
            kind=RestoreSafetyFindingKind.UNSAFE_GROUP_WRITE,
            message=(
                f"is group-writable through unresolved gid {gid}; exclusive "
                "control cannot be established."
            ),
            root_overridable=True,
        )
    if group.resolution_error:
        return RestoreSafetyFinding(
            kind=RestoreSafetyFindingKind.UNSAFE_GROUP_WRITE,
            message=(
                f"is group-writable through group '{group.name}' (gid {gid}), "
                f"but membership is ambiguous: {group.resolution_error}."
            ),
            root_overridable=True,
        )

    member_uids = frozenset(uid for _name, uid in group.members)
    if member_uids == frozenset({owner_uid}):
        return None

    if group.members:
        members_display = ", ".join(
            f"{name} (uid {uid})"
            for name, uid in group.members
        )
    else:
        members_display = "no resolved members"
    return RestoreSafetyFinding(
        kind=RestoreSafetyFindingKind.UNSAFE_GROUP_WRITE,
        message=(
            f"is group-writable through group '{group.name}' (gid {gid}), whose "
            f"membership is not limited to owner uid {owner_uid}: {members_display}."
        ),
        root_overridable=True,
    )


def _exclusive_control_reason(
    directory_fd: int,
    display_path: str,
    trusted_uids: frozenset[int],
) -> str | None:
    """Return the first exclusive-control problem for one directory.

    This focused helper is retained for callers and tests that need a single
    answer. A fresh immutable NSS snapshot prevents membership changes during
    the decision.

    Args:
        directory_fd: Open descriptor for the directory to inspect.
        display_path: Operator-facing path used in any error.
        trusted_uids: UIDs permitted to own the directory.

    Returns:
        The first rejection reason, or None when the directory passes.

    Raises:
        ValueError: If trusted_uids is empty.
        OSError: If directory metadata or ACLs cannot be inspected.
    """
    findings = _exclusive_control_reasons(
        directory_fd,
        display_path,
        trusted_uids,
        _build_identity_snapshot(),
        {},
    )
    return findings[0].message if findings else None


def _inspect_selected_path(
    target: str,
    target_fd: int,
    rel_path: str,
    trusted_uids: frozenset[int],
    identity_snapshot: IdentitySnapshot,
    group_write_cache: dict[tuple[int, int], RestoreSafetyFinding | None],
) -> tuple[tuple[RestoreSafetyFinding, ...], bool]:
    """Inspect one selected path without reopening the restore target pathname.

    Args:
        target: Operator-facing canonical restore target.
        target_fd: Open descriptor for the restore target.
        rel_path: Normalized relative selected path.
        trusted_uids: UIDs permitted to own existing directories.
        identity_snapshot: Immutable NSS identity view for this preflight.
        group_write_cache: Per-preflight group-policy result cache.

    Returns:
        A tuple of ``(findings, exists)``. Findings include symlink and
        privileged-control violations. ``exists`` is True when the selected
        path or a blocking non-directory component already exists.

    Raises:
        OSError: If an existing component cannot be inspected or opened safely.
    """
    current_fd = os.dup(target_fd)
    current_display = target
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    findings: list[RestoreSafetyFinding] = []
    try:
        parts = [part for part in rel_path.split(os.sep) if part and part != "."]
        for index, part in enumerate(parts):
            component_display = os.path.join(current_display, part)
            try:
                component_stat = os.stat(part, dir_fd=current_fd, follow_symlinks=False)
            except FileNotFoundError:
                return tuple(findings), False

            if stat.S_ISLNK(component_stat.st_mode):
                findings.append(
                    RestoreSafetyFinding(
                        kind=RestoreSafetyFindingKind.SELECTED_PATH_SYMLINK,
                        message=(
                            f"'{component_display}' inside the restore target is a "
                            "symlink — restoring through it could write outside the "
                            "target. Remove it or use a clean/empty target."
                        ),
                        root_overridable=False,
                    )
                )
                return tuple(findings), True

            is_last = index == len(parts) - 1
            if not stat.S_ISDIR(component_stat.st_mode):
                return tuple(findings), True
            if is_last and os.geteuid() != 0:
                return tuple(findings), True

            next_fd = os.open(part, directory_flags, dir_fd=current_fd)
            os.close(current_fd)
            current_fd = next_fd
            current_display = component_display

            if os.geteuid() == 0:
                findings.extend(
                    _exclusive_control_reasons(
                        current_fd,
                        current_display,
                        trusted_uids,
                        identity_snapshot,
                        group_write_cache,
                    )
                )
            if is_last:
                return tuple(findings), True
        return tuple(findings), False
    finally:
        os.close(current_fd)


def _add_overwrite_preflight_finding(
    findings: list[RestoreSafetyFinding],
    seen_findings: set[RestoreSafetyFinding],
    finding: RestoreSafetyFinding,
) -> bool:
    """Add one distinct finding without exceeding the reporting limit.

    The caller owns both mutable collections; they are created fresh for each
    preflight and never shared between restore operations.

    Args:
        findings: Ordered findings collected for the current preflight.
        seen_findings: Exact typed findings already collected.
        finding: Typed operator-facing problem description.

    Returns:
        True when the 100-problem limit has been reached.

    Raises:
        ValueError: If finding is empty.
    """
    if not isinstance(finding, RestoreSafetyFinding):
        raise TypeError("finding must be a RestoreSafetyFinding")
    if not finding.message or not finding.message.strip():
        raise ValueError("finding message must not be empty")
    if finding in seen_findings:
        return len(findings) >= MAX_OVERWRITE_PREFLIGHT_PROBLEMS
    if len(findings) >= MAX_OVERWRITE_PREFLIGHT_PROBLEMS:
        return True

    seen_findings.add(finding)
    findings.append(finding)
    return len(findings) >= MAX_OVERWRITE_PREFLIGHT_PROBLEMS


def _format_overwrite_preflight_failure(stats: OverwritePreflightStats) -> str:
    """Format all collected overwrite blockers as one bounded error.

    Args:
        stats: Completed or problem-limited overwrite preflight result.

    Returns:
        Multiline operator-facing failure message.

    Raises:
        ValueError: If stats contains no findings.
    """
    if not stats.findings:
        raise ValueError("stats must contain at least one finding")

    if stats.problem_limit_reached:
        summary = (
            f"Overwrite safety preflight failed and stopped after reaching "
            f"{MAX_OVERWRITE_PREFLIGHT_PROBLEMS} problems while inspecting "
            f"{stats.entries:,} entries; additional problems may exist."
        )
    else:
        summary = (
            f"Overwrite safety preflight failed: found {len(stats.findings):,} "
            f"problem(s) after inspecting {stats.entries:,} entries."
        )
    details = "\n".join(
        f"  {index}. {finding.message}"
        for index, finding in enumerate(stats.findings, start=1)
    )
    return f"{summary}\n{details}\nNo restore data was written."


def _inspection_failure(message: str) -> RestoreSafetyFinding:
    """Create a root-overridable preflight inspection failure.

    Args:
        message: Operator-facing failure description.

    Returns:
        A typed inspection finding.

    Raises:
        ValueError: If message is empty.
    """
    if not message or not message.strip():
        raise ValueError("message must not be empty")
    return RestoreSafetyFinding(
        kind=RestoreSafetyFindingKind.INSPECTION_FAILURE,
        message=message,
        root_overridable=True,
    )


def _run_overwrite_preflight(
    target: str,
    target_fd: int,
    trusted_uids: frozenset[int],
    identity_snapshot: IdentitySnapshot,
    group_write_cache: dict[tuple[int, int], RestoreSafetyFinding | None],
    initial_findings: Sequence[RestoreSafetyFinding] = (),
) -> OverwritePreflightStats:
    """Audit an overwrite target without following directory symlinks.

    The complete existing target tree is inspected. This intentionally favors
    a clear safety boundary over guessing which paths a DAR selection might
    affect.

    Args:
        target: Operator-facing restore target path.
        target_fd: Open and locked descriptor for the restore target.
        trusted_uids: UIDs permitted to own directories below the target.
        identity_snapshot: Immutable NSS identity view for this preflight.
        group_write_cache: Per-preflight group-policy result cache.
        initial_findings: Problems found by selected-path checks before the
            whole-target traversal.

    Returns:
        Counts and elapsed time for the completed audit.

    Raises:
        ValueError: If target or trusted_uids is empty.
    """
    if not target:
        raise ValueError("target must not be empty")
    if not trusted_uids:
        raise ValueError("trusted_uids must not be empty")

    started_at = time.monotonic()
    last_progress_at = started_at
    entry_count = 0
    directory_count = 0
    symlink_count = 0
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    pending: list[tuple[int, str]] = []
    findings: list[RestoreSafetyFinding] = []
    seen_findings: set[RestoreSafetyFinding] = set()
    problem_limit_reached = False

    for initial_finding in initial_findings:
        problem_limit_reached = _add_overwrite_preflight_finding(
            findings,
            seen_findings,
            initial_finding,
        )
        if problem_limit_reached:
            break

    if not problem_limit_reached:
        try:
            pending.append((os.dup(target_fd), target))
        except OSError as exc:
            problem_limit_reached = _add_overwrite_preflight_finding(
                findings,
                seen_findings,
                _inspection_failure(
                    f"could not duplicate the locked target descriptor for '{target}': {exc}"
                ),
            )

    try:
        while pending and not problem_limit_reached:
            directory_fd, display_path = pending.pop()
            try:
                directory_count += 1
                try:
                    control_reasons = _exclusive_control_reasons(
                        directory_fd,
                        display_path,
                        trusted_uids,
                        identity_snapshot,
                        group_write_cache,
                    )
                except OSError as exc:
                    problem_limit_reached = _add_overwrite_preflight_finding(
                        findings,
                        seen_findings,
                        _inspection_failure(
                            f"could not inspect ownership, permissions, or ACLs for "
                            f"directory '{display_path}': {exc}"
                        ),
                    )
                else:
                    for control_reason in control_reasons:
                        problem_limit_reached = _add_overwrite_preflight_finding(
                            findings,
                            seen_findings,
                            control_reason,
                        )
                        if problem_limit_reached:
                            break
                if problem_limit_reached:
                    continue

                try:
                    entries_context = os.scandir(directory_fd)
                    with entries_context as entries:
                        for entry in entries:
                            entry_count += 1
                            entry_path = os.path.join(display_path, entry.name)
                            try:
                                entry_stat = entry.stat(follow_symlinks=False)
                            except OSError as exc:
                                problem_limit_reached = _add_overwrite_preflight_finding(
                                    findings,
                                    seen_findings,
                                    _inspection_failure(
                                        f"could not inspect entry '{entry_path}': {exc}"
                                    ),
                                )
                                if problem_limit_reached:
                                    break
                                continue

                            if stat.S_ISLNK(entry_stat.st_mode):
                                symlink_count += 1
                            elif stat.S_ISDIR(entry_stat.st_mode):
                                try:
                                    child_fd = os.open(
                                        entry.name,
                                        directory_flags,
                                        dir_fd=directory_fd,
                                    )
                                except OSError as exc:
                                    problem_limit_reached = _add_overwrite_preflight_finding(
                                        findings,
                                        seen_findings,
                                        _inspection_failure(
                                            f"could not open directory '{entry_path}' safely: {exc}"
                                        ),
                                    )
                                    if problem_limit_reached:
                                        break
                                else:
                                    pending.append((child_fd, entry_path))

                            now = time.monotonic()
                            if now - last_progress_at >= 10.0:
                                logger.info(
                                    "Overwrite safety preflight progress: inspected %s entries, "
                                    "found %s problem(s); currently '%s'.",
                                    f"{entry_count:,}",
                                    f"{len(findings):,}",
                                    entry_path,
                                )
                                last_progress_at = now
                except OSError as exc:
                    problem_limit_reached = _add_overwrite_preflight_finding(
                        findings,
                        seen_findings,
                        _inspection_failure(
                            f"could not scan directory '{display_path}': {exc}"
                        ),
                    )
            finally:
                try:
                    os.close(directory_fd)
                except OSError as exc:
                    logger.warning(
                        "Could not close overwrite preflight directory descriptor for '%s': %s",
                        display_path,
                        exc,
                    )
    finally:
        for pending_fd, _pending_path in pending:
            try:
                os.close(pending_fd)
            except OSError as exc:
                logger.warning("Could not close overwrite preflight directory descriptor: %s", exc)

    return OverwritePreflightStats(
        entries=entry_count,
        directories=directory_count,
        symlinks=symlink_count,
        elapsed_seconds=time.monotonic() - started_at,
        findings=tuple(findings),
        problem_limit_reached=problem_limit_reached,
    )


def validate_restore_target_identity(target_handle: RestoreTargetHandle, phase: str) -> None:
    """Verify that the requested pathname still names the held target inode.

    Args:
        target_handle: Descriptor-bound restore target to verify.
        phase: Operator-facing description of when the check is performed.

    Raises:
        TypeError: If target_handle has the wrong type.
        ValueError: If inputs are invalid.
        RestoreTargetError: If the pathname disappeared, changed type, or now
            resolves to a different inode.
    """
    if not isinstance(target_handle, RestoreTargetHandle):
        raise TypeError("target_handle must be a RestoreTargetHandle")
    if not phase or not phase.strip():
        raise ValueError("phase must not be empty")

    try:
        path_stat = os.stat(target_handle.requested_path, follow_symlinks=True)
        descriptor_stat = os.fstat(target_handle.directory_fd)
    except OSError as exc:
        raise RestoreTargetError(
            f"Restore target identity check {phase} failed for "
            f"'{target_handle.requested_path}': {exc}"
        ) from exc

    if not stat.S_ISDIR(path_stat.st_mode):
        raise RestoreTargetError(
            f"Restore target identity check {phase} failed: "
            f"'{target_handle.requested_path}' is no longer a directory."
        )
    if (path_stat.st_dev, path_stat.st_ino) != (descriptor_stat.st_dev, descriptor_stat.st_ino):
        raise RestoreTargetError(
            f"Restore target identity check {phase} failed: "
            f"'{target_handle.requested_path}' no longer names the locked restore directory. "
            "Descriptor binding prevented redirection outside the original directory, "
            "but that original directory may have been renamed."
        )


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
    if (
        policy.force_unsafe_restore_target
        and policy.existing_data is not ExistingDataPolicy.ALLOW_OVERWRITE
    ):
        raise ValueError(
            "force_unsafe_restore_target requires the overwrite existing-data policy"
        )
    if policy.force_unsafe_restore_target and effective_uid != 0:
        raise RestoreTargetError(
            "The unsafe restore-target override is restricted to root (effective uid 0)."
        )

    target_stat = os.fstat(target_fd)
    trusted_uid_values = {effective_uid}
    if effective_uid == 0 and policy.existing_data is ExistingDataPolicy.ALLOW_OVERWRITE:
        # Root must be able to recover a private user-owned home without
        # classifying every original user-owned directory as hostile.
        trusted_uid_values.add(target_stat.st_uid)
    trusted_uids = frozenset(trusted_uid_values)

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
        identity_snapshot = _build_identity_snapshot()
        group_write_cache: dict[tuple[int, int], RestoreSafetyFinding | None] = {}
        existing: list[str] = []
        for rel_path in normalized_paths:
            if rel_path == ".":
                raise ValueError("archive-root path '.' requires the empty-target policy")
            findings, path_exists = _inspect_selected_path(
                target,
                target_fd,
                rel_path,
                trusted_uids,
                identity_snapshot,
                group_write_cache,
            )
            if findings:
                raise RestoreTargetError(findings[0].message)
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
        logger.info(
            "Starting overwrite safety preflight for '%s'. Existing target data is being inspected; "
            "this can take a long time and no restore data will be written until it completes.",
            target,
        )
        identity_snapshot = _build_identity_snapshot()
        group_write_cache = {}
        selected_findings: list[RestoreSafetyFinding] = []
        seen_selected_findings: set[RestoreSafetyFinding] = set()
        for rel_path in normalized_paths:
            try:
                path_findings, _path_exists = _inspect_selected_path(
                    target,
                    target_fd,
                    rel_path,
                    trusted_uids,
                    identity_snapshot,
                    group_write_cache,
                )
            except OSError as exc:
                _add_overwrite_preflight_finding(
                    selected_findings,
                    seen_selected_findings,
                    _inspection_failure(
                        f"could not inspect selected restore path '{rel_path}' below "
                        f"'{target}': {exc}"
                    ),
                )
            else:
                for finding in path_findings:
                    if not finding.root_overridable:
                        immediate_stats = OverwritePreflightStats(
                            entries=0,
                            directories=0,
                            symlinks=1,
                            elapsed_seconds=0.0,
                            findings=(finding,),
                            problem_limit_reached=False,
                        )
                        raise RestoreTargetError(
                            _format_overwrite_preflight_failure(immediate_stats)
                        )
                    _add_overwrite_preflight_finding(
                        selected_findings,
                        seen_selected_findings,
                        finding,
                    )

        stats = _run_overwrite_preflight(
            target,
            target_fd,
            trusted_uids,
            identity_snapshot,
            group_write_cache,
            initial_findings=selected_findings,
        )
        if stats.findings:
            non_overridable = tuple(
                finding
                for finding in stats.findings
                if not finding.root_overridable
            )
            if non_overridable or not policy.force_unsafe_restore_target:
                raise RestoreTargetError(_format_overwrite_preflight_failure(stats))

            details = "\n".join(
                f"  {index}. {finding.message}"
                for index, finding in enumerate(stats.findings, start=1)
            )
            truncation_warning = (
                f" The audit stopped at {MAX_OVERWRITE_PREFLIGHT_PROBLEMS} "
                "reported problems; additional problems may exist."
                if stats.problem_limit_reached
                else ""
            )
            logger.critical(
                "ROOT BREAK-GLASS OVERRIDE ACTIVE for '%s': continuing despite "
                "%s overwrite safety problem(s) after inspecting %s entries.%s\n"
                "%s\nConcurrent writers can redirect or corrupt this restore. "
                "Stop services and users that can modify the target before continuing. "
                "No automatic rollback is available.",
                target,
                f"{len(stats.findings):,}",
                f"{stats.entries:,}",
                truncation_warning,
                details,
            )
        elif policy.force_unsafe_restore_target:
            logger.warning(
                "Root unsafe restore-target override was requested for '%s', but "
                "the overwrite preflight found no policy problems.",
                target,
            )
        logger.info(
            "Overwrite safety preflight completed: inspected %s entries in %s directories "
            "(%s symlinks) in %.1f seconds.",
            f"{stats.entries:,}",
            f"{stats.directories:,}",
            f"{stats.symlinks:,}",
            stats.elapsed_seconds,
        )
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
        if effective_uid == 0 and policy.existing_data is not ExistingDataPolicy.ALLOW_OVERWRITE:
            trusted_uids = {effective_uid}
            identity_snapshot = _build_identity_snapshot()
            control_findings = _exclusive_control_reasons(
                lock_fd,
                opened_path,
                frozenset(trusted_uids),
                identity_snapshot,
                {},
            )
            if control_findings:
                raise RestoreTargetError(control_findings[0].message)

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
