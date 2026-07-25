# SPDX-License-Identifier: GPL-3.0-or-later

"""Policy-matrix tests for shared restore-target safety."""

import os
from pathlib import Path

import pytest

from dar_backup.restore_target_safety import _exclusive_control_reason
from dar_backup.restore_target_safety import ExistingDataPolicy
from dar_backup.restore_target_safety import RestoreTargetError
from dar_backup.restore_target_safety import RestoreTargetPolicy
from dar_backup.restore_target_safety import prepare_restore_target
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
        assert _exclusive_control_reason(directory_fd, str(target), os.geteuid()) is None
    finally:
        os.close(directory_fd)


def test_exclusive_control_rejects_different_owner(tmp_path: Path) -> None:
    """Exclusive-control validation rejects ownership by another identity."""
    target = tmp_path / "target"
    target.mkdir(mode=0o700)
    directory_fd = os.open(target, os.O_RDONLY | os.O_DIRECTORY)
    try:
        reason = _exclusive_control_reason(directory_fd, str(target), os.geteuid() + 1)
    finally:
        os.close(directory_fd)

    assert reason is not None
    assert "not the restoring uid" in reason


def test_exclusive_control_rejects_group_writable_directory(tmp_path: Path) -> None:
    """Exclusive-control validation rejects writes by another identity."""
    target = tmp_path / "target"
    target.mkdir()
    target.chmod(0o770)
    directory_fd = os.open(target, os.O_RDONLY | os.O_DIRECTORY)
    try:
        reason = _exclusive_control_reason(directory_fd, str(target), os.geteuid())
    finally:
        os.close(directory_fd)

    assert reason is not None
    assert "writable by its group or other users" in reason
