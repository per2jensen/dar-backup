#!/usr/bin/env python3
"""
Real integration tests for PITR restore, backup pipeline ordering,
startup restore-dir cleanup, alternate archive dir, and cleanup input safety.

Ten tests replacing the most mock-heavy unit tests in the suite:

  Group A — PITR (4 tests):
    1. test_pitr_restore_file_selects_archive_before_when
    2. test_pitr_restore_directory_applies_full_then_diff_chain
    3. test_pitr_report_first_aborts_when_archive_slice_missing
    4. test_pitr_report_first_restores_after_successful_report

  Group B — Backup pipeline (2 tests):
    5. test_full_backup_verify_runs_before_par2_and_both_complete
    6. test_full_backup_succeeds_when_metrics_db_is_unwritable

  Group C — CLI startup / restore-dir cleanup (2 tests):
    7. test_restore_cleans_test_restore_dir_before_restoring
    8. test_list_contents_does_not_clean_test_restore_dir

  Group D — Manager alternate archive dir (1 test):
    9. test_manager_alternate_archive_dir_redirects_catalog_and_slices

  Group E — Cleanup input safety (1 test):
    10. test_cleanup_rejects_unsafe_archive_name_and_exits_cleanly
"""

import os
import shutil
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import List

import pytest

pytestmark = [pytest.mark.integration, pytest.mark.slow]

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from dar_backup.config_settings import ConfigSettings
from tests.envdata import EnvData
from tests.testdata_verification import run_backup_script


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _find_archive_name(backup_dir: str, backup_type: str, backup_def: str) -> str:
    """
    Return archive base name (without .N.dar suffix) for the first match.

    Args:
        backup_dir: Directory containing .dar slice files.
        backup_type: One of FULL, DIFF, INCR.
        backup_def: Backup definition prefix (e.g. "example").

    Returns:
        Archive base name such as "example_FULL_2026-05-23".

    Raises:
        RuntimeError: If no matching archive is found.
    """
    marker = f"{backup_def}_{backup_type}_"
    for name in sorted(os.listdir(backup_dir)):
        if name.endswith(".1.dar") and marker in name:
            return name[: -len(".1.dar")]
    raise RuntimeError(
        f"No {backup_type} archive found for '{backup_def}' in '{backup_dir}'"
    )


def _run_manager(env: EnvData, extra_args: List[str]) -> subprocess.CompletedProcess:
    """
    Run the `manager` CLI with config/log args plus extra_args.

    Args:
        env: EnvData fixture.
        extra_args: Additional arguments appended after the base flags.

    Returns:
        CompletedProcess with stdout/stderr captured as text.
    """
    command = [
        "manager",
        "--config-file", env.config_file,
        "--log-level", "debug",
        "--log-stdout",
    ] + extra_args
    result = subprocess.run(command, capture_output=True, text=True)
    env.logger.info("manager stdout:\n%s", result.stdout)
    if result.returncode != 0:
        env.logger.warning("manager stderr:\n%s", result.stderr)
    return result


def _run_dar_backup(env: EnvData, extra_args: List[str]) -> subprocess.CompletedProcess:
    """
    Run the `dar-backup` CLI with config/log args plus extra_args.

    Args:
        env: EnvData fixture.
        extra_args: Additional arguments appended after the base flags.

    Returns:
        CompletedProcess with stdout/stderr captured as text.
    """
    command = [
        "dar-backup",
        "--config-file", env.config_file,
        "--log-level", "debug",
        "--log-stdout",
    ] + extra_args
    result = subprocess.run(command, capture_output=True, text=True)
    env.logger.info("dar-backup stdout:\n%s", result.stdout)
    if result.returncode != 0:
        env.logger.warning("dar-backup stderr:\n%s", result.stderr)
    return result


# ---------------------------------------------------------------------------
# Group A: PITR
# ---------------------------------------------------------------------------

def test_pitr_restore_file_selects_archive_before_when(setup_environment, env: EnvData) -> None:
    """
    PITR file restore with --when between FULL and DIFF must restore the
    FULL-archive version of file1.txt (original content), not the DIFF version.

    The selection uses dar_manager -f timestamps (file mtime as recorded in the
    archive). Recording t_between after FULL but before the file is modified
    guarantees only the FULL archive qualifies as a candidate.
    """
    run_backup_script("--full-backup", env)

    # Ensure t_between falls strictly between FULL mtime and DIFF mtime.
    time.sleep(2)
    t_between = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
    time.sleep(2)

    file1_path = os.path.join(env.data_dir, "file1.txt")
    with open(file1_path, "w") as fh:
        fh.write("MODIFIED FOR DIFF")

    run_backup_script("--differential-backup", env)

    file1_relative = os.path.join(env.data_dir.lstrip("/"), "file1.txt")
    target_dir = os.path.join(env.test_dir, "pitr_file_target")
    os.makedirs(target_dir, exist_ok=True)

    result = _run_manager(env, [
        "--backup-def", "example",
        "--restore-path", file1_relative,
        "--when", t_between,
        "--target", target_dir,
    ])
    assert result.returncode == 0, f"manager exited non-zero:\n{result.stderr}"

    restored = os.path.join(target_dir, file1_relative)
    assert os.path.isfile(restored), f"Restored file not found: {restored}"
    content = Path(restored).read_text()
    assert content == "This is file 1.", (
        f"Expected FULL-archive content 'This is file 1.' but got: {content!r}"
    )


def test_pitr_restore_directory_applies_full_then_diff_chain(setup_environment, env: EnvData) -> None:
    """
    PITR directory restore must apply FULL then DIFF archives in sequence,
    leaving both original files (from FULL) and the new file (from DIFF)
    in the target directory.

    _detect_directory returns True immediately because env.data_dir exists on
    the filesystem, so the archive-chain path is exercised without needing dar -l.
    """
    run_backup_script("--full-backup", env)

    new_file = os.path.join(env.data_dir, "new_file_for_diff.txt")
    with open(new_file, "w") as fh:
        fh.write("Added before DIFF backup")

    run_backup_script("--differential-backup", env)

    dir_relative = env.data_dir.lstrip("/")
    target_dir = os.path.join(env.test_dir, "pitr_dir_target")
    os.makedirs(target_dir, exist_ok=True)

    result = _run_manager(env, [
        "--backup-def", "example",
        "--restore-path", dir_relative,
        "--target", target_dir,
    ])
    assert result.returncode == 0, f"manager exited non-zero:\n{result.stderr}"

    restored_dir = os.path.join(target_dir, dir_relative)
    assert os.path.isdir(restored_dir), f"Restored directory not found: {restored_dir}"
    restored_files = os.listdir(restored_dir)
    assert "file1.txt" in restored_files, (
        f"file1.txt missing from FULL restore: {restored_files}"
    )
    assert "new_file_for_diff.txt" in restored_files, (
        f"new_file_for_diff.txt missing from DIFF restore: {restored_files}"
    )


def test_pitr_report_first_aborts_when_archive_slice_missing(setup_environment, env: EnvData) -> None:
    """
    --pitr-report-first must exit non-zero and leave the target directory empty
    when the required archive slice (.1.dar) is absent from disk.

    _pitr_chain_report detects the missing slice and returns 1; the CLI calls
    sys.exit(1) before restore_at is ever invoked.
    """
    run_backup_script("--full-backup", env)
    archive_name = _find_archive_name(env.backup_dir, "FULL", "example")
    os.remove(os.path.join(env.backup_dir, f"{archive_name}.1.dar"))

    file1_relative = os.path.join(env.data_dir.lstrip("/"), "file1.txt")
    target_dir = os.path.join(env.test_dir, "pitr_abort_target")
    os.makedirs(target_dir, exist_ok=True)

    result = _run_manager(env, [
        "--backup-def", "example",
        "--restore-path", file1_relative,
        "--pitr-report-first",
        "--when", "now",
        "--target", target_dir,
    ])
    assert result.returncode != 0, (
        f"Expected non-zero exit when slice is missing, got 0:\n{result.stdout}"
    )
    all_files = [f for _, _, files in os.walk(target_dir) for f in files]
    assert not all_files, (
        f"Target must be empty after aborted restore, but found: {all_files}"
    )


def test_pitr_report_first_restores_after_successful_report(setup_environment, env: EnvData) -> None:
    """
    --pitr-report-first must exit 0 and restore the file when all archive
    slices are present and the chain report confirms a valid archive exists.
    """
    run_backup_script("--full-backup", env)

    file1_relative = os.path.join(env.data_dir.lstrip("/"), "file1.txt")
    target_dir = os.path.join(env.test_dir, "pitr_success_target")
    os.makedirs(target_dir, exist_ok=True)

    result = _run_manager(env, [
        "--backup-def", "example",
        "--restore-path", file1_relative,
        "--pitr-report-first",
        "--target", target_dir,
    ])
    assert result.returncode == 0, f"manager exited non-zero:\n{result.stderr}"

    restored = os.path.join(target_dir, file1_relative)
    assert os.path.isfile(restored), (
        f"Restored file not found at '{restored}' after pitr-report-first succeeded"
    )


# ---------------------------------------------------------------------------
# Group B: Backup pipeline
# ---------------------------------------------------------------------------

def test_full_backup_verify_runs_before_par2_and_both_complete(setup_environment, env: EnvData) -> None:
    """
    A full backup run must log verify completion before the par2 generation
    message, and the par2 index file must exist on disk after the run.

    This confirms the perform_backup ordering invariant: generic_backup →
    verify → generate_par2_files.
    """
    result = run_backup_script("--full-backup", env)
    output = result.stdout

    assert "Archive integrity test passed" in output, (
        f"Verify log line not found in stdout:\n{output}"
    )

    archive_name = _find_archive_name(env.backup_dir, "FULL", "example")
    # Per-slice par2: any {archive_name}.N.dar.par2 file confirms par2 ran
    import re as _re
    sp = _re.compile(rf"{_re.escape(archive_name)}\.([0-9]+)\.dar\.par2$")
    slice_par2_files = [f for f in os.listdir(env.backup_dir) if sp.match(f)]
    assert slice_par2_files, (
        f"No per-slice par2 index files found for '{archive_name}' — par2 did not run"
    )

    verify_pos = output.find("Archive integrity test passed")
    par2_pos = output.find("Generate par2 redundancy files", verify_pos)
    assert par2_pos > verify_pos, (
        "par2 generation log appeared BEFORE verify completion — ordering violated"
    )


def test_full_backup_succeeds_when_metrics_db_is_unwritable(setup_environment, env: EnvData) -> None:
    """
    A full backup must complete with exit code 0 even when METRICS_DB_PATH
    points to an unwritable location and write_metrics_row raises an exception.

    The METRICS_DB_PATH key is injected into the [MISC] section of the
    test config before the backup runs.
    """
    with open(env.config_file) as fh:
        config_text = fh.read()
    # Inject METRICS_DB_PATH right after [MISC] so it falls in the correct section.
    config_text = config_text.replace(
        "[MISC]",
        "[MISC]\nMETRICS_DB_PATH = /nonexistent_dir_xyz/unwritable_metrics.db",
        1,
    )
    with open(env.config_file, "w") as fh:
        fh.write(config_text)

    result = _run_dar_backup(env, ["--full-backup", "-d", "example", "--verbose"])
    assert result.returncode == 0, (
        f"Backup failed despite metrics error — expected exit 0:\n{result.stderr}"
    )

    archive_name = _find_archive_name(env.backup_dir, "FULL", "example")
    assert os.path.isfile(os.path.join(env.backup_dir, f"{archive_name}.1.dar")), (
        "No FULL dar slice found after backup with unwritable metrics DB"
    )


# ---------------------------------------------------------------------------
# Group C: CLI startup / restore-dir cleanup
# ---------------------------------------------------------------------------

def test_restore_cleans_test_restore_dir_before_restoring(setup_environment, env: EnvData) -> None:
    """
    `dar-backup --restore` must wipe TEST_RESTORE_DIR before restoring so that
    stale files from a previous run do not survive into the next restore.

    should_clean_restore_test_directory returns True when no --restore-dir is
    given and the effective dir equals config_settings.test_restore_dir.
    """
    run_backup_script("--full-backup", env)
    archive_name = _find_archive_name(env.backup_dir, "FULL", "example")

    config = ConfigSettings(env.config_file)
    restore_dir = config.test_restore_dir
    os.makedirs(restore_dir, exist_ok=True)

    stale_file = os.path.join(restore_dir, "stale_marker.txt")
    with open(stale_file, "w") as fh:
        fh.write("I am stale and must be removed before restore")

    result = _run_dar_backup(env, ["--restore", archive_name])
    assert result.returncode == 0, f"dar-backup --restore failed:\n{result.stderr}"

    assert not os.path.isfile(stale_file), (
        "Stale marker file survived — clean_restore_test_directory was not called"
    )
    restored_files = [f for _, _, files in os.walk(restore_dir) for f in files]
    assert restored_files, "No files were restored into test_restore_dir after --restore"


def test_list_contents_does_not_clean_test_restore_dir(setup_environment, env: EnvData) -> None:
    """
    `dar-backup --list-contents` must NOT touch TEST_RESTORE_DIR — the
    directory wipe is exclusive to backup and restore operations.

    should_clean_restore_test_directory returns False for --list-contents,
    so any pre-existing files in the restore dir must remain intact.
    """
    run_backup_script("--full-backup", env)
    archive_name = _find_archive_name(env.backup_dir, "FULL", "example")

    config = ConfigSettings(env.config_file)
    restore_dir = config.test_restore_dir
    os.makedirs(restore_dir, exist_ok=True)

    marker_file = os.path.join(restore_dir, "preserved_marker.txt")
    with open(marker_file, "w") as fh:
        fh.write("I must survive --list-contents")

    result = _run_dar_backup(env, ["--list-contents", archive_name])
    assert result.returncode == 0, f"dar-backup --list-contents failed:\n{result.stderr}"

    assert os.path.isfile(marker_file), (
        "--list-contents removed the marker file — clean_restore_test_directory was wrongly called"
    )


# ---------------------------------------------------------------------------
# Group D: Manager alternate archive dir
# ---------------------------------------------------------------------------

def test_manager_alternate_archive_dir_redirects_catalog_and_slices(setup_environment, env: EnvData) -> None:
    """
    After moving all backup files (slices + catalog DB) to an alternate
    directory, --alternate-archive-dir must redirect both the catalog DB
    lookup (get_db_dir returns alt_dir) and archive path resolution so that
    --pitr-report succeeds.

    Without the flag the same command fails because the DB is absent from
    the now-empty backup_dir, proving the flag is actually needed.
    """
    run_backup_script("--full-backup", env)

    alt_dir = os.path.join(env.test_dir, "alt_backup_dir")
    os.makedirs(alt_dir, exist_ok=True)
    for fname in os.listdir(env.backup_dir):
        shutil.move(
            os.path.join(env.backup_dir, fname),
            os.path.join(alt_dir, fname),
        )

    # Relocate catalog entries from backup_dir → alt_dir using alt_dir for the DB lookup.
    reloc = _run_manager(env, [
        "--backup-def", "example",
        "--alternate-archive-dir", alt_dir,
        "--relocate-archive-path", env.backup_dir, alt_dir,
    ])
    assert reloc.returncode == 0, f"relocate failed:\n{reloc.stderr}"

    file1_relative = os.path.join(env.data_dir.lstrip("/"), "file1.txt")

    # Without --alternate-archive-dir the DB is not found in the empty backup_dir.
    no_alt = _run_manager(env, [
        "--backup-def", "example",
        "--pitr-report",
        "--restore-path", file1_relative,
        "--when", "now",
    ])
    assert no_alt.returncode != 0, (
        "Expected failure when --alternate-archive-dir is omitted and backup_dir is empty"
    )

    # With --alternate-archive-dir DB and slices are found in alt_dir.
    with_alt = _run_manager(env, [
        "--backup-def", "example",
        "--alternate-archive-dir", alt_dir,
        "--pitr-report",
        "--restore-path", file1_relative,
        "--when", "now",
    ])
    assert with_alt.returncode == 0, (
        f"Expected success with --alternate-archive-dir:\n{with_alt.stderr}"
    )


# ---------------------------------------------------------------------------
# Group E: Cleanup input safety
# ---------------------------------------------------------------------------

def test_cleanup_rejects_unsafe_archive_name_and_exits_cleanly(setup_environment, env: EnvData) -> None:
    """
    `cleanup --cleanup-specific-archives` with a path-traversal archive name
    must log a refusal and exit without deleting any real archive on disk.

    is_archive_name_allowed rejects names containing ".." before any deletion
    is attempted.
    """
    run_backup_script("--full-backup", env)
    archive_name = _find_archive_name(env.backup_dir, "FULL", "example")
    real_slice = os.path.join(env.backup_dir, f"{archive_name}.1.dar")
    assert os.path.isfile(real_slice)

    result = subprocess.run([
        "cleanup",
        "--test-mode",
        "--cleanup-specific-archives", "../../etc/passwd",
        "--config-file", env.config_file,
        "--log-level", "debug",
        "--log-stdout",
    ], capture_output=True, text=True)

    assert os.path.isfile(real_slice), (
        "Real archive slice was deleted despite passing an unsafe archive name"
    )
    assert "Refusing unsafe archive name" in result.stdout, (
        f"Expected refusal message in stdout, got:\n{result.stdout}"
    )
