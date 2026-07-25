# SPDX-License-Identifier: GPL-3.0-or-later

"""Real FULL-to-DIFF-to-INCR coverage for overwrite PITR restores."""

import os
import shutil
import stat
import subprocess
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from tests.envdata import EnvData

pytestmark = [pytest.mark.integration, pytest.mark.smoke]


def _run_command(
    env: EnvData,
    command: list[str],
) -> subprocess.CompletedProcess[str]:
    """Run and log a real integration-test command.

    Args:
        env: Paths and loggers for the isolated test environment.
        command: Executable and argument vector to run.

    Returns:
        Completed process with captured text output.
    """
    result = subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
        timeout=300,
    )
    env.logger.info(
        "Integration command completed (rc=%s): %s\nstdout:\n%s\nstderr:\n%s",
        result.returncode,
        command,
        result.stdout,
        result.stderr,
    )
    return result


def _create_and_register_archive(
    env: EnvData,
    archive_type: str,
    archive_time: datetime,
    sequence: int,
    reference_archive: Path | None = None,
) -> Path:
    """Create a real DAR archive and register it with the test catalog.

    Args:
        env: Paths and loggers for the isolated test environment.
        archive_type: Archive label used in its catalog-compatible filename.
        archive_time: Timestamp embedded in the archive filename.
        sequence: Stable same-type ordering suffix.
        reference_archive: FULL or DIFF reference archive for changed data.

    Returns:
        Archive base path without its slice suffix.

    Raises:
        AssertionError: If DAR creation or manager registration fails.
    """
    archive_base = Path(env.backup_dir) / (f"example_{archive_type}_{archive_time.strftime('%Y-%m-%d_%H%M%S')}_{sequence:02d}")
    backup_definition = Path(env.backup_d_dir) / "example"
    create_command = [
        "dar",
        "-c",
        str(archive_base),
        "-N",
        "-B",
        env.dar_rc,
        "-B",
        str(backup_definition),
        "-Q",
        "compress-exclusion",
        "verbose",
    ]
    if reference_archive is not None:
        create_command.extend(["-A", str(reference_archive)])

    create_result = _run_command(env, create_command)
    assert create_result.returncode == 0, f"DAR {archive_type} creation failed: {create_result.stderr}"

    register_result = _run_command(
        env,
        [
            "manager",
            "--add-specific-archive",
            str(archive_base),
            "--config-file",
            env.config_file,
            "--log-stdout",
        ],
    )
    assert register_result.returncode == 0, f"Manager registration of {archive_type} failed: {register_result.stderr}"
    return archive_base


def _replace_source_tree(source: Path) -> None:
    """Remove fixture data so the test controls the complete archive contents.

    Args:
        source: Isolated source directory owned by the test fixture.
    """
    for entry in source.iterdir():
        if entry.is_dir() and not entry.is_symlink():
            shutil.rmtree(entry)
        else:
            entry.unlink()


def _write_version(path: Path, content: str, modified_at: datetime) -> None:
    """Write one source version with a deterministic modification timestamp.

    Args:
        path: File to create or replace.
        content: Exact text stored in the file.
        modified_at: Modification timestamp recorded by DAR.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    timestamp = modified_at.timestamp()
    os.utime(path, (timestamp, timestamp))


def _snapshot_files(root: Path) -> dict[str, str]:
    """Return relative file contents below a test restore target.

    Args:
        root: Existing directory to inspect.

    Returns:
        Mapping of relative POSIX paths to UTF-8 text content.
    """
    return {path.relative_to(root).as_posix(): path.read_text(encoding="utf-8") for path in sorted(root.rglob("*")) if path.is_file()}


def _run_pitr_restore(
    env: EnvData,
    restore_path: str,
    restore_time: datetime,
    target: Path,
    *,
    overwrite: bool,
    no_deleted: bool = False,
) -> subprocess.CompletedProcess[str]:
    """Run the real manager PITR CLI with the requested overwrite policy.

    Args:
        env: Paths and loggers for the isolated test environment.
        restore_path: Catalog-relative directory to restore.
        restore_time: PITR archive-selection timestamp.
        target: Explicit restore target.
        overwrite: Whether to pass ``--overwrite-restore-target``.
        no_deleted: Whether to pass ``--no-deleted``.

    Returns:
        Completed manager process with captured text output.
    """
    command = [
        "manager",
        "--config-file",
        env.config_file,
        "--backup-def",
        "example",
        "--restore-path",
        restore_path,
        "--when",
        restore_time.strftime("%Y-%m-%d %H:%M:%S"),
        "--target",
        str(target),
        "--ignore-ownership",
        "--log-level",
        "debug",
        "--log-stdout",
    ]
    if overwrite:
        command.append("--overwrite-restore-target")
    if no_deleted:
        command.append("--no-deleted")
    return _run_command(env, command)


def _populate_existing_target(target: Path, restore_path: str) -> Path:
    """Create stale, deletable, and unrelated files in a restore target.

    Args:
        target: Restore root to populate.
        restore_path: Relative selected path restored below the target.

    Returns:
        Existing selected directory below the target.
    """
    target.mkdir(mode=0o750)
    selected_directory = target
    for component in Path(restore_path).parts:
        selected_directory /= component
        selected_directory.mkdir(mode=0o700)
        # Pin every traversed component explicitly: mkdir(parents=True) creates
        # intermediate parents with its default mode, which may be too broad
        # under an unusually permissive test umask.
        selected_directory.chmod(0o700)
    (selected_directory / "profile.txt").write_text(
        "stale target profile",
        encoding="utf-8",
    )
    (selected_directory / "deleted-after-full.txt").write_text(
        "stale target full deletion",
        encoding="utf-8",
    )
    (selected_directory / "deleted-after-diff.txt").write_text(
        "stale target diff deletion",
        encoding="utf-8",
    )
    (selected_directory / "target-only.txt").write_text(
        "target-only sentinel",
        encoding="utf-8",
    )
    return selected_directory


def test_real_pitr_overwrite_applies_full_diff_incr_chain_and_deletion_policy(
    setup_environment: object,
    env: EnvData,
) -> None:
    """Overwrite PITR restores a real chain while preserving unrelated data.

    Args:
        setup_environment: Fixture that prepares real DAR and manager state.
        env: Paths, configuration, and loggers for this test.
    """
    del setup_environment

    source = Path(env.data_dir)
    _replace_source_tree(source)
    # PITR archive names and manager comparisons deliberately use local naive
    # timestamps, matching the production archive-date contract.
    base_time = datetime.now().replace(microsecond=0) - timedelta(minutes=5)  # noqa: DTZ005

    _write_version(
        source / "profile.txt",
        "profile from FULL",
        base_time + timedelta(seconds=1),
    )
    _write_version(
        source / "unchanged.txt",
        "unchanged from FULL",
        base_time + timedelta(seconds=2),
    )
    _write_version(
        source / "deleted-after-full.txt",
        "file captured by FULL",
        base_time + timedelta(seconds=3),
    )
    full_time = base_time + timedelta(seconds=10)
    full_archive = _create_and_register_archive(
        env,
        "FULL",
        full_time,
        1,
    )

    _write_version(
        source / "profile.txt",
        "profile from DIFF",
        base_time + timedelta(seconds=11),
    )
    (source / "deleted-after-full.txt").unlink()
    _write_version(
        source / "deleted-after-diff.txt",
        "file captured by DIFF",
        base_time + timedelta(seconds=12),
    )
    diff_time = base_time + timedelta(seconds=20)
    diff_archive = _create_and_register_archive(
        env,
        "DIFF",
        diff_time,
        2,
        full_archive,
    )

    _write_version(
        source / "profile.txt",
        "profile from INCR",
        base_time + timedelta(seconds=21),
    )
    (source / "deleted-after-diff.txt").unlink()
    _write_version(
        source / "final-only.txt",
        "added by INCR",
        base_time + timedelta(seconds=22),
    )
    incr_time = base_time + timedelta(seconds=30)
    _create_and_register_archive(
        env,
        "INCR",
        incr_time,
        3,
        diff_archive,
    )

    restore_path = source.as_posix().lstrip("/")
    restore_time = incr_time + timedelta(seconds=1)
    target = Path(env.test_dir) / "overwrite-pitr-target"
    restored_directory = _populate_existing_target(target, restore_path)
    outside_sentinel = Path(env.test_dir) / "outside-overwrite-sentinel.txt"
    outside_sentinel.write_text("outside sentinel", encoding="utf-8")

    target_before = target.stat()
    target_mode_before = stat.S_IMODE(target_before.st_mode)
    original_snapshot = _snapshot_files(target)

    blocked_result = _run_pitr_restore(
        env,
        restore_path,
        restore_time,
        target,
        overwrite=False,
    )
    assert blocked_result.returncode != 0
    assert _snapshot_files(target) == original_snapshot
    assert outside_sentinel.read_text(encoding="utf-8") == "outside sentinel"

    overwrite_result = _run_pitr_restore(
        env,
        restore_path,
        restore_time,
        target,
        overwrite=True,
    )
    assert overwrite_result.returncode == 0, f"Overwrite PITR failed: stdout={overwrite_result.stdout!r} stderr={overwrite_result.stderr!r}"

    target_after = target.stat()
    assert (target_after.st_dev, target_after.st_ino) == (
        target_before.st_dev,
        target_before.st_ino,
    )
    assert target_after.st_uid == target_before.st_uid
    assert stat.S_IMODE(target_after.st_mode) == target_mode_before
    assert _snapshot_files(restored_directory) == {
        "final-only.txt": "added by INCR",
        "profile.txt": "profile from INCR",
        "target-only.txt": "target-only sentinel",
        "unchanged.txt": "unchanged from FULL",
    }
    assert outside_sentinel.read_text(encoding="utf-8") == "outside sentinel"

    restore_output = f"{overwrite_result.stdout}\n{overwrite_result.stderr}"
    preflight_index = restore_output.index("Starting overwrite safety preflight")
    first_archive_index = restore_output.index("Applying archive")
    assert preflight_index < first_archive_index
    assert restore_output.count("Applying archive") == 3

    no_deleted_target = Path(env.test_dir) / "overwrite-pitr-no-deleted-target"
    no_deleted_directory = _populate_existing_target(
        no_deleted_target,
        restore_path,
    )
    no_deleted_result = _run_pitr_restore(
        env,
        restore_path,
        restore_time,
        no_deleted_target,
        overwrite=True,
        no_deleted=True,
    )
    assert no_deleted_result.returncode == 0, (
        f"Overwrite PITR with --no-deleted failed: stdout={no_deleted_result.stdout!r} stderr={no_deleted_result.stderr!r}"
    )
    assert _snapshot_files(no_deleted_directory) == {
        "deleted-after-diff.txt": "file captured by DIFF",
        "deleted-after-full.txt": "file captured by FULL",
        "final-only.txt": "added by INCR",
        "profile.txt": "profile from INCR",
        "target-only.txt": "target-only sentinel",
        "unchanged.txt": "unchanged from FULL",
    }
    assert outside_sentinel.read_text(encoding="utf-8") == "outside sentinel"
