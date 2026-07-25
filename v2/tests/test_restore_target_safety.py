# SPDX-License-Identifier: GPL-3.0-or-later

"""Policy-matrix tests for shared restore-target safety."""

import os
from pathlib import Path
from typing import Iterator

import pytest

from dar_backup.restore_target_safety import _exclusive_control_reason
from dar_backup.restore_target_safety import _resolve_identity_snapshot
from dar_backup.restore_target_safety import _unsafe_group_write_finding
from dar_backup.restore_target_safety import ExistingDataPolicy
from dar_backup.restore_target_safety import GroupIdentity
from dar_backup.restore_target_safety import IdentitySnapshot
from dar_backup.restore_target_safety import NssGroup
from dar_backup.restore_target_safety import NssUser
from dar_backup.restore_target_safety import RestoreTargetError
from dar_backup.restore_target_safety import RestoreTargetPolicy
from dar_backup.restore_target_safety import prepare_restore_target
from dar_backup.restore_target_safety import validate_restore_target_identity
from dar_backup.restore_target_safety import validate_restore_target_location


pytestmark = pytest.mark.unit


@pytest.mark.parametrize("allow_protected_target", [False, True], ids=["protected-rejected", "protected-allowed"])
@pytest.mark.parametrize("existing_data", list(ExistingDataPolicy), ids=lambda policy: policy.value)
def test_policy_matrix_protected_location_is_independent(
    existing_data: ExistingDataPolicy,
    allow_protected_target: bool,
) -> None:
    """Every existing-data policy independently honors target protection."""
    policy = RestoreTargetPolicy(
        existing_data=existing_data,
        allow_protected_target=allow_protected_target,
    )

    if allow_protected_target:
        assert validate_restore_target_location("/root", policy) == "/root"
        return

    with pytest.raises(RestoreTargetError, match="protected system directory"):
        validate_restore_target_location("/root", policy)


@pytest.mark.parametrize("allow_protected_target", [False, True], ids=["default-protection", "protection-bypassed"])
@pytest.mark.parametrize(
    ("existing_data", "should_succeed"),
    [
        (ExistingDataPolicy.REQUIRE_EMPTY, False),
        (ExistingDataPolicy.REJECT_SELECTED_PATHS, False),
        (ExistingDataPolicy.ALLOW_OVERWRITE, True),
    ],
    ids=["require-empty", "reject-selected", "allow-overwrite"],
)
def test_policy_matrix_existing_data_is_independent(
    tmp_path: Path,
    existing_data: ExistingDataPolicy,
    should_succeed: bool,
    allow_protected_target: bool,
) -> None:
    """All six policy combinations retain their existing-data behavior."""
    target = tmp_path / f"target-{existing_data.value}-{allow_protected_target}"
    selected_file = target / "data" / "file.txt"
    selected_file.parent.mkdir(parents=True)
    target.chmod(0o700)
    selected_file.parent.chmod(0o700)
    selected_file.write_text("existing", encoding="utf-8")
    policy = RestoreTargetPolicy(
        existing_data=existing_data,
        allow_protected_target=allow_protected_target,
    )

    if should_succeed:
        with prepare_restore_target(str(target), policy, ["data/file.txt"]):
            assert selected_file.read_text(encoding="utf-8") == "existing"
        return

    with pytest.raises(RestoreTargetError):
        with prepare_restore_target(str(target), policy, ["data/file.txt"]):
            pytest.fail("unsafe target unexpectedly passed policy checks")


@pytest.mark.parametrize(
    "existing_data",
    [
        ExistingDataPolicy.REQUIRE_EMPTY,
        ExistingDataPolicy.REJECT_SELECTED_PATHS,
        ExistingDataPolicy.ALLOW_OVERWRITE,
    ],
    ids=lambda policy: policy.value,
)
def test_each_existing_data_policy_allows_its_safe_case(
    tmp_path: Path,
    existing_data: ExistingDataPolicy,
) -> None:
    """Each existing-data policy has positive coverage for its intended use."""
    target = tmp_path / existing_data.value
    target.mkdir()
    selected_paths: list[str] = []

    if existing_data is ExistingDataPolicy.REJECT_SELECTED_PATHS:
        (target / "unrelated.txt").write_text("unrelated", encoding="utf-8")
        selected_paths = ["data/file.txt"]
    elif existing_data is ExistingDataPolicy.ALLOW_OVERWRITE:
        selected_file = target / "data" / "file.txt"
        selected_file.parent.mkdir()
        target.chmod(0o700)
        selected_file.parent.chmod(0o700)
        selected_file.write_text("existing", encoding="utf-8")
        selected_paths = ["data/file.txt"]

    policy = RestoreTargetPolicy(existing_data=existing_data)
    with prepare_restore_target(str(target), policy, selected_paths):
        assert target.is_dir()


@pytest.mark.parametrize(
    "existing_data",
    [ExistingDataPolicy.REJECT_SELECTED_PATHS, ExistingDataPolicy.ALLOW_OVERWRITE],
    ids=lambda policy: policy.value,
)
def test_selected_path_symlink_is_rejected_even_when_overwrite_is_allowed(
    tmp_path: Path,
    existing_data: ExistingDataPolicy,
) -> None:
    """Overwrite permission never permits writes through target symlinks."""
    target = tmp_path / "target"
    target.mkdir()
    (target / "data").symlink_to(tmp_path / "outside", target_is_directory=True)
    policy = RestoreTargetPolicy(existing_data=existing_data)

    with pytest.raises(RestoreTargetError, match="is a symlink"):
        with prepare_restore_target(str(target), policy, ["data/file.txt"]):
            pytest.fail("symlinked selected path unexpectedly passed safety checks")


def test_prepare_restore_target_handle_survives_path_replacement(tmp_path: Path) -> None:
    """The yielded handle remains bound to the opened target after replacement."""
    target = tmp_path / "target"
    held_target = tmp_path / "held-target"
    outside = tmp_path / "outside"
    target.mkdir()
    outside.mkdir()
    policy = RestoreTargetPolicy(existing_data=ExistingDataPolicy.REQUIRE_EMPTY)

    with prepare_restore_target(str(target), policy) as handle:
        target.rename(held_target)
        target.symlink_to(outside, target_is_directory=True)

        assert os.path.samefile(handle.dar_root, held_target)
        assert not os.path.samefile(handle.dar_root, outside)
        assert handle.pass_fds == (handle.directory_fd,)
        os.fstat(handle.directory_fd)

    with pytest.raises(OSError):
        os.fstat(handle.directory_fd)


def test_prepare_restore_target_replacement_during_open_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An inode replacement between stat and open fails closed."""
    target = tmp_path / "target"
    displaced_target = tmp_path / "displaced-target"
    target.mkdir()
    policy = RestoreTargetPolicy(existing_data=ExistingDataPolicy.REQUIRE_EMPTY)
    real_open = os.open
    replacement_done = False

    # This monkeypatch synchronizes an OS-level path-replacement race that
    # cannot be triggered reliably using scheduler timing.
    def replace_before_open(
        path: str,
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        """Replace the target immediately before the production os.open call.

        Args:
            path: Path passed to os.open.
            flags: File-open flags.
            mode: Creation mode used when a creation flag is present.
            dir_fd: Optional descriptor relative to which path is resolved.

        Returns:
            Descriptor returned by the real os.open.
        """
        nonlocal replacement_done
        if path == str(target) and dir_fd is None and not replacement_done:
            target.rename(displaced_target)
            target.mkdir()
            replacement_done = True
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(os, "open", replace_before_open)

    with pytest.raises(RestoreTargetError, match="changed while it was being opened"):
        with prepare_restore_target(str(target), policy):
            pytest.fail("replaced restore target unexpectedly passed preparation")


def test_exclusive_control_accepts_private_owner_directory(tmp_path: Path) -> None:
    """Exclusive-control validation accepts a private directory owned by the UID."""
    target = tmp_path / "target"
    target.mkdir(mode=0o700)
    directory_fd = os.open(target, os.O_RDONLY | os.O_DIRECTORY)
    try:
        assert _exclusive_control_reason(directory_fd, str(target), frozenset({os.geteuid()})) is None
    finally:
        os.close(directory_fd)


def test_exclusive_control_accepts_target_owner_as_second_trusted_uid(tmp_path: Path) -> None:
    """A root-style trusted set accepts a private directory owned by the target user."""
    target = tmp_path / "target"
    target.mkdir(mode=0o700)
    directory_fd = os.open(target, os.O_RDONLY | os.O_DIRECTORY)
    try:
        reason = _exclusive_control_reason(
            directory_fd,
            str(target),
            frozenset({0, target.stat().st_uid}),
        )
    finally:
        os.close(directory_fd)

    assert reason is None


def test_exclusive_control_rejects_different_owner(tmp_path: Path) -> None:
    """Exclusive-control validation rejects ownership by another identity."""
    target = tmp_path / "target"
    target.mkdir(mode=0o700)
    directory_fd = os.open(target, os.O_RDONLY | os.O_DIRECTORY)
    try:
        reason = _exclusive_control_reason(directory_fd, str(target), frozenset({os.geteuid() + 1}))
    finally:
        os.close(directory_fd)

    assert reason is not None
    assert "owned by untrusted uid" in reason


def test_exclusive_control_accepts_owner_only_group_writable_directory(tmp_path: Path) -> None:
    """A private primary group does not falsely classify the owner as another user."""
    target = tmp_path / "target"
    target.mkdir()
    target.chmod(0o770)
    directory_fd = os.open(target, os.O_RDONLY | os.O_DIRECTORY)
    try:
        reason = _exclusive_control_reason(directory_fd, str(target), frozenset({os.geteuid()}))
    finally:
        os.close(directory_fd)

    assert reason is None


def test_group_write_policy_accepts_generic_owner_as_group_sole_member() -> None:
    """Names need not match when the directory owner UID is the sole group member."""
    snapshot = IdentitySnapshot(
        groups=(
            GroupIdentity(
                gid=2400,
                name="photo-operators",
                members=(("restore-user", 1700),),
            ),
        )
    )

    assert _unsafe_group_write_finding(2400, 1700, snapshot) is None


def test_group_write_policy_rejects_group_with_second_identity() -> None:
    """One additional group member makes group write unsafe."""
    snapshot = IdentitySnapshot(
        groups=(
            GroupIdentity(
                gid=2400,
                name="photo-operators",
                members=(("restore-user", 1700), ("second-user", 1701)),
            ),
        )
    )

    finding = _unsafe_group_write_finding(2400, 1700, snapshot)

    assert finding is not None
    assert "second-user (uid 1701)" in finding.message


def test_group_write_policy_rejects_unresolved_membership() -> None:
    """An NSS resolution ambiguity fails closed."""
    snapshot = IdentitySnapshot(
        groups=(),
        resolution_error="simulated ambiguous NSS data",
    )

    finding = _unsafe_group_write_finding(2400, 1700, snapshot)

    assert finding is not None
    assert "membership could not be verified" in finding.message


def test_identity_snapshot_combines_primary_and_supplementary_membership() -> None:
    """Resolution includes both passwd primary GIDs and group member lists."""
    snapshot = _resolve_identity_snapshot(
        users=(
            NssUser(name="owner", uid=1700, primary_gid=2400),
            NssUser(name="operator", uid=1701, primary_gid=2500),
        ),
        groups=(
            NssGroup(
                name="owner-private",
                gid=2400,
                explicit_members=("operator",),
            ),
            NssGroup(name="operator-private", gid=2500, explicit_members=()),
        ),
    )

    owner_group = snapshot.group_for_gid(2400)

    assert owner_group is not None
    assert owner_group.members == (("owner", 1700), ("operator", 1701))


def test_identity_snapshot_duplicate_uid_fails_closed() -> None:
    """Duplicate numeric identities make all group-write decisions unresolved."""
    snapshot = _resolve_identity_snapshot(
        users=(
            NssUser(name="owner", uid=1700, primary_gid=2400),
            NssUser(name="owner-alias", uid=1700, primary_gid=2400),
        ),
        groups=(NssGroup(name="owner-private", gid=2400, explicit_members=()),),
    )

    assert snapshot.resolution_error is not None
    assert "duplicate uid(s): 1700" in snapshot.resolution_error


def test_overwrite_preflight_private_tree_reports_completion(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A private existing tree passes the overwrite preflight before yielding."""
    target = tmp_path / "home"
    child = target / "Documents"
    child.mkdir(parents=True)
    target.chmod(0o700)
    child.chmod(0o700)
    (child / "existing.txt").write_text("old", encoding="utf-8")
    policy = RestoreTargetPolicy(existing_data=ExistingDataPolicy.ALLOW_OVERWRITE)

    with caplog.at_level("INFO", logger="main_logger"):
        with prepare_restore_target(str(target), policy, ["Documents/existing.txt"]):
            assert (child / "existing.txt").read_text(encoding="utf-8") == "old"

    messages = [record.getMessage() for record in caplog.records]
    assert any("Starting overwrite safety preflight" in message for message in messages)
    assert any("Overwrite safety preflight completed" in message for message in messages)


@pytest.mark.parametrize("mode", [0o770, 0o775], ids=["0770", "0775"])
def test_overwrite_preflight_accepts_real_owner_only_group_modes(
    tmp_path: Path,
    mode: int,
) -> None:
    """Real owner/primary-group directories pass when NSS shows only that owner."""
    target = tmp_path / "home"
    child = target / "photos"
    child.mkdir(parents=True)
    target.chmod(mode)
    child.chmod(mode)
    policy = RestoreTargetPolicy(existing_data=ExistingDataPolicy.ALLOW_OVERWRITE)

    with prepare_restore_target(str(target), policy):
        assert target.stat().st_mode & 0o777 == mode
        assert child.stat().st_mode & 0o777 == mode


def test_overwrite_preflight_other_writable_child_rejects_before_restore(
    tmp_path: Path,
) -> None:
    """A child writable by another identity aborts with an explicit no-write result."""
    target = tmp_path / "home"
    child = target / "shared"
    child.mkdir(parents=True)
    target.chmod(0o700)
    child.chmod(0o707)
    policy = RestoreTargetPolicy(existing_data=ExistingDataPolicy.ALLOW_OVERWRITE)

    with pytest.raises(
        RestoreTargetError,
        match=r"(?s)Overwrite safety preflight failed.*writable by other users.*No restore data was written",
    ):
        with prepare_restore_target(str(target), policy):
            pytest.fail("unsafe overwrite target unexpectedly passed preflight")


def test_overwrite_preflight_reports_multiple_problems_in_one_run(
    tmp_path: Path,
) -> None:
    """All blockers found below the cap are returned in one failure."""
    target = tmp_path / "home"
    target.mkdir(mode=0o700)
    unsafe_directories = [target / name for name in ("shared-a", "shared-b", "shared-c")]
    for directory in unsafe_directories:
        directory.mkdir()
        directory.chmod(0o707)
    policy = RestoreTargetPolicy(existing_data=ExistingDataPolicy.ALLOW_OVERWRITE)

    with pytest.raises(RestoreTargetError) as exc_info:
        with prepare_restore_target(str(target), policy):
            pytest.fail("unsafe overwrite target unexpectedly passed preflight")

    message = str(exc_info.value)
    assert "failed: found 3 problem(s)" in message
    for directory in unsafe_directories:
        assert str(directory) in message
    assert message.endswith("No restore data was written.")


def test_overwrite_preflight_stops_and_reports_at_one_hundred_problems(
    tmp_path: Path,
) -> None:
    """The bounded report stops at 100 findings and warns that more may exist."""
    target = tmp_path / "home"
    target.mkdir(mode=0o700)
    for index in range(105):
        directory = target / f"shared-{index:03d}"
        directory.mkdir()
        directory.chmod(0o707)
    policy = RestoreTargetPolicy(existing_data=ExistingDataPolicy.ALLOW_OVERWRITE)

    with pytest.raises(RestoreTargetError) as exc_info:
        with prepare_restore_target(str(target), policy):
            pytest.fail("problem-limited overwrite target unexpectedly passed preflight")

    message = str(exc_info.value)
    detail_lines = [
        line for line in message.splitlines()
        if line.startswith("  ") and line.partition(". ")[0].strip().isdigit()
    ]
    assert len(detail_lines) == 100
    assert detail_lines[-1].startswith("  100. ")
    assert "stopped after reaching 100 problems" in message
    assert "additional problems may exist" in message
    assert message.endswith("No restore data was written.")


def test_overwrite_preflight_deduplicates_repeated_selected_path_problem(
    tmp_path: Path,
) -> None:
    """Repeated selected paths do not consume multiple report slots."""
    target = tmp_path / "home"
    target.mkdir(mode=0o700)
    (target / "Documents").symlink_to(tmp_path / "outside", target_is_directory=True)
    policy = RestoreTargetPolicy(existing_data=ExistingDataPolicy.ALLOW_OVERWRITE)
    repeated_paths = ["Documents/file.txt"] * 3

    with pytest.raises(RestoreTargetError) as exc_info:
        with prepare_restore_target(str(target), policy, repeated_paths):
            pytest.fail("selected symlink unexpectedly passed preflight")

    message = str(exc_info.value)
    assert "failed: found 1 problem(s)" in message
    assert message.count("is a symlink") == 1


def test_overwrite_preflight_succeeds_after_all_reported_modes_are_fixed(
    tmp_path: Path,
) -> None:
    """A second complete preflight succeeds after every reported blocker is fixed."""
    target = tmp_path / "home"
    target.mkdir(mode=0o700)
    unsafe_directories = [target / "shared-a", target / "shared-b"]
    for directory in unsafe_directories:
        directory.mkdir()
        directory.chmod(0o707)
    policy = RestoreTargetPolicy(existing_data=ExistingDataPolicy.ALLOW_OVERWRITE)

    with pytest.raises(RestoreTargetError) as exc_info:
        with prepare_restore_target(str(target), policy):
            pytest.fail("unsafe overwrite target unexpectedly passed preflight")
    first_message = str(exc_info.value)
    assert all(str(directory) in first_message for directory in unsafe_directories)

    for directory in unsafe_directories:
        directory.chmod(0o700)

    with prepare_restore_target(str(target), policy):
        assert all(directory.is_dir() for directory in unsafe_directories)


def test_overwrite_preflight_scan_error_reports_no_restore_data(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An OS-level scan failure is reported as a pre-DAR preflight failure."""
    target = tmp_path / "home"
    target.mkdir(mode=0o700)
    policy = RestoreTargetPolicy(existing_data=ExistingDataPolicy.ALLOW_OVERWRITE)
    real_scandir = os.scandir

    # Monkeypatching is appropriate here because a deterministic readdir(2)
    # failure cannot be induced portably after the directory is already open.
    def fail_target_scan(path: int | str) -> Iterator[os.DirEntry[str]]:
        """Raise the OS-level failure being exercised.

        Args:
            path: Directory descriptor passed by the production code.

        Raises:
            OSError: Always, to emulate a failed directory scan.
        """
        if isinstance(path, int):
            raise OSError("simulated readdir failure")
        return real_scandir(path)

    monkeypatch.setattr(os, "scandir", fail_target_scan)

    with pytest.raises(
        RestoreTargetError,
        match=r"(?s)Overwrite safety preflight failed.*simulated readdir failure.*No restore data was written",
    ):
        with prepare_restore_target(str(target), policy):
            pytest.fail("unreadable overwrite target unexpectedly passed preflight")


def test_overwrite_preflight_continues_after_child_open_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An unreadable branch and a separate unsafe branch are reported together."""
    target = tmp_path / "home"
    blocked = target / "blocked"
    shared = target / "shared"
    blocked.mkdir(parents=True)
    shared.mkdir()
    target.chmod(0o700)
    blocked.chmod(0o700)
    shared.chmod(0o707)
    policy = RestoreTargetPolicy(existing_data=ExistingDataPolicy.ALLOW_OVERWRITE)
    real_open = os.open

    # Monkeypatching is appropriate because making an owner-controlled child
    # fail open(2) deterministically requires an OS/filesystem fault.
    def fail_blocked_open(
        path: str,
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        """Fail the descriptor-relative open for one child directory.

        Args:
            path: Path passed to os.open.
            flags: File-open flags.
            mode: Creation mode used when a creation flag is present.
            dir_fd: Optional descriptor relative to which path is resolved.

        Returns:
            Descriptor returned by the real os.open for other paths.

        Raises:
            PermissionError: When production code opens the blocked child.
        """
        if path == "blocked" and dir_fd is not None:
            raise PermissionError("simulated child open failure")
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(os, "open", fail_blocked_open)

    with pytest.raises(RestoreTargetError) as exc_info:
        with prepare_restore_target(str(target), policy):
            pytest.fail("partially unreadable overwrite target unexpectedly passed preflight")

    message = str(exc_info.value)
    assert "failed: found 2 problem(s)" in message
    assert f"could not open directory '{blocked}' safely" in message
    assert f"directory '{shared}' is writable by other users" in message


def test_force_unsafe_restore_target_root_continues_past_policy_finding(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Root's explicit override continues after auditing an overridable problem."""
    target = tmp_path / "home"
    target.mkdir()
    target.chmod(0o707)
    policy = RestoreTargetPolicy(
        existing_data=ExistingDataPolicy.ALLOW_OVERWRITE,
        force_unsafe_restore_target=True,
    )

    # Effective root identity is an OS condition that cannot be established
    # portably inside an unprivileged test process.
    monkeypatch.setattr(os, "geteuid", lambda: 0)

    with caplog.at_level("CRITICAL", logger="main_logger"):
        with prepare_restore_target(str(target), policy):
            assert target.is_dir()

    message = "\n".join(record.getMessage() for record in caplog.records)
    assert "ROOT BREAK-GLASS OVERRIDE ACTIVE" in message
    assert "writable by other users" in message
    assert "Stop services and users" in message


def test_force_unsafe_restore_target_root_logs_bounded_problem_report(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Break-glass remains bounded at 100 findings and warns of unknown extras."""
    target = tmp_path / "home"
    target.mkdir(mode=0o700)
    for index in range(105):
        directory = target / f"shared-{index:03d}"
        directory.mkdir()
        directory.chmod(0o707)
    policy = RestoreTargetPolicy(
        existing_data=ExistingDataPolicy.ALLOW_OVERWRITE,
        force_unsafe_restore_target=True,
    )

    # Effective root identity is an OS condition that cannot be established
    # portably inside an unprivileged test process.
    monkeypatch.setattr(os, "geteuid", lambda: 0)

    with caplog.at_level("CRITICAL", logger="main_logger"):
        with prepare_restore_target(str(target), policy):
            assert target.is_dir()

    message = "\n".join(record.getMessage() for record in caplog.records)
    detail_lines = [
        line
        for line in message.splitlines()
        if line.startswith("  ") and line.partition(". ")[0].strip().isdigit()
    ]
    assert len(detail_lines) == 100
    assert "additional problems may exist" in message


def test_force_unsafe_restore_target_non_root_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A non-root caller cannot activate the break-glass override."""
    target = tmp_path / "home"
    target.mkdir(mode=0o700)
    policy = RestoreTargetPolicy(
        existing_data=ExistingDataPolicy.ALLOW_OVERWRITE,
        force_unsafe_restore_target=True,
    )

    # Simulating euid is required because CI may itself run as root.
    monkeypatch.setattr(os, "geteuid", lambda: 1700)

    with pytest.raises(RestoreTargetError, match="restricted to root"):
        with prepare_restore_target(str(target), policy):
            pytest.fail("non-root break-glass override unexpectedly passed")


def test_force_unsafe_restore_target_requires_overwrite_policy(tmp_path: Path) -> None:
    """The break-glass setting cannot be attached to a non-overwrite restore."""
    target = tmp_path / "home"
    target.mkdir(mode=0o700)
    policy = RestoreTargetPolicy(
        existing_data=ExistingDataPolicy.REQUIRE_EMPTY,
        force_unsafe_restore_target=True,
    )

    with pytest.raises(ValueError, match="requires the overwrite existing-data policy"):
        with prepare_restore_target(str(target), policy):
            pytest.fail("break-glass without overwrite unexpectedly passed")


def test_force_unsafe_restore_target_does_not_bypass_selected_symlink(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Even root break-glass cannot waive a structural selected-path symlink."""
    target = tmp_path / "home"
    target.mkdir(mode=0o700)
    (target / "photos").symlink_to(tmp_path / "outside", target_is_directory=True)
    policy = RestoreTargetPolicy(
        existing_data=ExistingDataPolicy.ALLOW_OVERWRITE,
        force_unsafe_restore_target=True,
    )

    # Effective root identity is an OS condition that cannot be established
    # portably inside an unprivileged test process.
    monkeypatch.setattr(os, "geteuid", lambda: 0)

    with pytest.raises(RestoreTargetError, match="is a symlink"):
        with prepare_restore_target(str(target), policy, ["photos/file.nef"]):
            pytest.fail("root override unexpectedly bypassed a selected symlink")


def test_force_unsafe_restore_target_does_not_bypass_protected_location() -> None:
    """Protected system destinations remain rejected under break-glass."""
    policy = RestoreTargetPolicy(
        existing_data=ExistingDataPolicy.ALLOW_OVERWRITE,
        force_unsafe_restore_target=True,
    )

    with pytest.raises(RestoreTargetError, match="protected system directory"):
        validate_restore_target_location("/etc", policy)


def test_restore_target_identity_accepts_unchanged_path(tmp_path: Path) -> None:
    """The identity check accepts a pathname that still names the locked inode."""
    target = tmp_path / "home"
    target.mkdir(mode=0o700)
    policy = RestoreTargetPolicy(existing_data=ExistingDataPolicy.ALLOW_OVERWRITE)

    with prepare_restore_target(str(target), policy) as handle:
        validate_restore_target_identity(handle, "during test")


def test_restore_target_identity_rejects_replaced_path(tmp_path: Path) -> None:
    """Replacing the requested pathname is detected while the old inode stays held."""
    target = tmp_path / "home"
    displaced_target = tmp_path / "home-displaced"
    target.mkdir(mode=0o700)
    policy = RestoreTargetPolicy(existing_data=ExistingDataPolicy.ALLOW_OVERWRITE)

    with prepare_restore_target(str(target), policy) as handle:
        target.rename(displaced_target)
        target.mkdir(mode=0o700)
        with pytest.raises(RestoreTargetError, match="no longer names the locked restore directory"):
            validate_restore_target_identity(handle, "after replacement")
