# SPDX-License-Identifier: GPL-3.0-or-later

"""Policy-matrix tests for shared restore-target safety."""

from pathlib import Path

import pytest

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
