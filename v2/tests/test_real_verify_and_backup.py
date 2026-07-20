#!/usr/bin/env python3
"""
Real integration tests for verify(), get_backed_up_files(), list_contents(),
generate_par2_files(), and the full backup pipeline.

Each test complements a mock-heavy unit test by driving the real dar and par2
binaries and asserting on observable filesystem state and program output rather
than on synthetic stubs.

Tests are paired with their mock counterparts:
  - test_verify_detects_real_file_corruption
      → complements test_verify_filecmp_mismatch_returns_false
  - test_full_backup_pipeline_runs_verify
      → complements test_perform_backup_handles_failed_verification
  - test_verify_replaces_stale_restore_file
      → complements test_verify_removes_existing_file_before_restore
  - test_get_backed_up_files_lists_real_archive_contents
      → complements test_get_backed_up_files_subprocess_success
  - test_par2_verify_detects_corrupt_dar_slice
      → complements test_generate_par2_files_verify_failure
  - test_list_contents_shows_real_archive_files
      → complements test_list_contents_subprocess_success
  - test_list_contents_raises_for_nonexistent_archive
      → complements test_list_contents_subprocess_error
  - test_backup_with_unreadable_files_exits_zero
      → complements test_generic_backup_warns_on_returncode_5
  - test_catalog_add_fails_when_db_is_readonly
      → complements test_catalog_add_failure_handled
  - test_verify_raises_on_corrupt_archive
      → complements test_verify_restore_command_nonzero_raises
"""

import contextlib
import logging
import os
import re
import sqlite3
import subprocess
import sys
import time
from contextlib import closing
from types import SimpleNamespace
from typing import Generator

import pytest

pytestmark = [pytest.mark.integration, pytest.mark.slow]

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

import dar_backup.dar_backup as db
from dar_backup.command_runner import CommandRunner
from dar_backup.config_settings import ConfigSettings
from tests.envdata import EnvData
from tests.testdata_verification import run_backup_script


# Content written to file1.txt by conftest.create_a_bit_of_testdata.
_FILE1_ORIGINAL_CONTENT = "This is file 1."


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


@contextlib.contextmanager
def _module_context(env: EnvData) -> Generator[None, None, None]:
    """
    Temporarily set dar_backup.dar_backup module-level logger and runner to
    real objects backed by the test-fixture loggers, then restore the originals.

    Args:
        env: EnvData fixture providing test loggers.

    Yields:
        None — callers import db directly and benefit from the globals being set.
    """
    old_logger = db.logger
    old_runner = db.runner
    try:
        db.logger = env.logger
        db.runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
        yield
    finally:
        db.logger = old_logger
        db.runner = old_runner


def _find_archive_name(backup_dir: str, backup_type: str, backup_def: str) -> str:
    """
    Return the base archive name (without .N.dar suffix) for the first match.

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


def _set_no_files_verification(env: EnvData, n: int) -> None:
    """
    Rewrite NO_FILES_VERIFICATION in the test config file to the given value.

    Setting it to a number larger than the count of test data files ensures that
    every backed-up file is always selected for restore verification, eliminating
    randomness from file selection.

    Args:
        env: EnvData fixture whose config_file will be modified.
        n: The new value for NO_FILES_VERIFICATION.
    """
    with open(env.config_file) as fh:
        content = fh.read()
    content = re.sub(
        r"NO_FILES_VERIFICATION\s*=\s*\d+",
        f"NO_FILES_VERIFICATION = {n}",
        content,
    )
    with open(env.config_file, "w") as fh:
        fh.write(content)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_verify_detects_real_file_corruption(setup_environment, env: EnvData) -> None:
    """
    verify() must return False when source files were modified after a backup.

    Steps:
      1. Create a real full backup (archive has original file content).
      2. Overwrite all source files with different content.
      3. Call verify() with a real runner — it restores files from the archive
         and compares them with the now-different sources.
      4. Assert restore_test_passed is False.

    Complements test_verify_filecmp_mismatch_returns_false.
    """
    run_backup_script("--full-backup", env)
    archive_name = _find_archive_name(env.backup_dir, "FULL", "example")
    backup_def_path = os.path.join(env.backup_d_dir, "example")
    config = ConfigSettings(env.config_file)

    # Modify every source file so any randomly selected file will fail the compare.
    for filename in os.listdir(env.data_dir):
        filepath = os.path.join(env.data_dir, filename)
        if os.path.isfile(filepath):
            with open(filepath, "w") as fh:
                fh.write("CORRUPTED — does not match archive content")

    args = SimpleNamespace(verbose=False, do_not_compare=False, darrc=env.dar_rc)

    archive_path = os.path.join(config.backup_dir, archive_name)

    with _module_context(env):
        result = db.verify(args, archive_path, backup_def_path, config)

    assert result.restore_test_passed is False, (
        "verify() must return False when source files were modified after backup"
    )


def test_full_backup_pipeline_runs_verify(setup_environment, env: EnvData) -> None:
    """
    The full backup pipeline must run verify() and restore sample files to
    test_restore_dir when given a real dar archive.

    Confirms that the real pipeline path (backup → verify → par2) runs end-to-end
    without mocking any stage.

    Complements test_perform_backup_handles_failed_verification.
    """
    result = run_backup_script("--full-backup", env)

    # Archive must exist on disk.
    _find_archive_name(env.backup_dir, "FULL", "example")

    # verify() restores sample files to test_restore_dir; at least one must be there.
    restored = [
        fname
        for _, _, files in os.walk(env.restore_dir)
        for fname in files
    ]
    assert restored, (
        "verify() should have restored at least one file to test_restore_dir"
    )

    # Log must confirm the archive integrity test ran.
    assert "Archive integrity test passed" in result.stdout, (
        "Expected 'Archive integrity test passed' in backup stdout"
    )


def test_verify_replaces_stale_restore_file(setup_environment, env: EnvData) -> None:
    """
    verify() must remove a pre-existing file from test_restore_dir and replace it
    with the restored version from the archive, not leave the stale content.

    Steps:
      1. Set NO_FILES_VERIFICATION high enough to guarantee file1.txt is always
         selected for restore.
      2. Create a real full backup.
      3. Plant stale content at the restore path where file1.txt will be restored.
      4. Call verify() — it must delete the stale file before restoring.
      5. Assert the restored file has the original content, not the stale content.

    Complements test_verify_removes_existing_file_before_restore.
    """
    # 20 exceeds the 10 test data files, ensuring all are always selected.
    _set_no_files_verification(env, 20)

    run_backup_script("--full-backup", env)
    archive_name = _find_archive_name(env.backup_dir, "FULL", "example")
    backup_def_path = os.path.join(env.backup_d_dir, "example")
    config = ConfigSettings(env.config_file)

    # Compute the restore path for file1.txt.
    # The backup definition uses -R / and stores env.data_dir without its leading '/'.
    file1_relative = os.path.join(env.data_dir.lstrip("/"), "file1.txt")
    stale_restore_path = os.path.join(config.test_restore_dir, file1_relative)
    os.makedirs(os.path.dirname(stale_restore_path), exist_ok=True)
    with open(stale_restore_path, "w") as fh:
        fh.write("STALE CONTENT — must be replaced by verify()")

    args = SimpleNamespace(verbose=False, do_not_compare=False, darrc=env.dar_rc)

    archive_path = os.path.join(config.backup_dir, archive_name)

    with _module_context(env):
        verify_result = db.verify(args, archive_path, backup_def_path, config)

    # Archive + unchanged sources → verify passes overall.
    assert verify_result.restore_test_passed is True, (
        "verify() should pass: archive has original content, source is unchanged"
    )

    # The stale file must have been replaced with the original content.
    with open(stale_restore_path) as fh:
        restored_content = fh.read()

    assert restored_content == _FILE1_ORIGINAL_CONTENT, (
        f"Restored file must have original content but got: {restored_content!r}"
    )
    assert "STALE" not in restored_content, (
        "Stale content must have been removed before restore"
    )


def test_get_backed_up_files_lists_real_archive_contents(
    setup_environment, env: EnvData
) -> None:
    """
    get_backed_up_files() must stream real file paths from a real dar archive
    and return the expected test data filenames in the (path, size) tuples.

    Complements test_get_backed_up_files_subprocess_success.
    """
    run_backup_script("--full-backup", env)
    archive_name = _find_archive_name(env.backup_dir, "FULL", "example")
    config = ConfigSettings(env.config_file)

    with _module_context(env):
        files = list(db.get_backed_up_files(archive_name, config.backup_dir, timeout=120))

    assert files, "get_backed_up_files() must return at least one entry"

    basenames = [os.path.basename(path) for path, _ in files]

    for expected in ("file1.txt", "file2.txt", "file3.txt"):
        assert expected in basenames, (
            f"Expected '{expected}' in archive listing, got basenames: {basenames}"
        )

    # Every entry must carry a non-None size string.
    for path, size in files:
        assert path, "File path must be non-empty"
        assert size is not None, f"File '{path}' must have a size"


def test_par2_verify_detects_corrupt_dar_slice(
    setup_environment, env: EnvData
) -> None:
    """
    par2 verify must exit nonzero when a dar slice has been corrupted after
    the par2 recovery data was created.

    This confirms the real-world detection path that
    test_generate_par2_files_verify_failure validates through a mock.

    Steps:
      1. Run a full backup (creates archive + par2 files).
      2. Corrupt the first dar slice by overwriting bytes.
      3. Run par2 verify against the par2 index file.
      4. Assert par2 exits nonzero.

    Complements test_generate_par2_files_verify_failure.
    """
    run_backup_script("--full-backup", env)
    archive_name = _find_archive_name(env.backup_dir, "FULL", "example")

    # Per-slice par2: index file is named {slice_file}.par2, e.g. example_FULL_…1.dar.par2
    import re as _re
    sp = _re.compile(rf"{_re.escape(archive_name)}\.([0-9]+)\.dar\.par2$")
    slice_par2_files = sorted(
        [f for f in os.listdir(env.backup_dir) if sp.match(f)],
        key=lambda x: int(sp.match(x).group(1))
    )
    assert slice_par2_files, (
        f"No per-slice par2 index files found for '{archive_name}' in "
        f"'{env.backup_dir}' — is PAR2.ENABLED = True in config?"
    )
    # Corrupt and verify slice 1
    par2_path = os.path.join(env.backup_dir, slice_par2_files[0])

    slice_path = os.path.join(env.backup_dir, f"{archive_name}.1.dar")
    assert os.path.exists(slice_path), f"Expected dar slice at '{slice_path}'"

    slice_size = os.path.getsize(slice_path)
    assert slice_size > 200, (
        f"Dar slice is too small to corrupt meaningfully: {slice_size} bytes"
    )

    # Overwrite data well past the file header so par2 detects the CRC mismatch.
    with open(slice_path, "r+b") as fh:
        fh.seek(100)
        fh.write(b"XCORRUPTED_DATA_XCORRUPTED_DATA_" * 4)

    result = subprocess.run(
        ["par2", "verify", "-B", env.backup_dir, par2_path],
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0, (
        "par2 verify must exit nonzero when a dar slice has been corrupted"
    )


def test_list_contents_shows_real_archive_files(
    setup_environment, env: EnvData
) -> None:
    """
    dar-backup --list-contents must print [Saved] lines for every backed-up
    test data file in a real archive.

    Complements test_list_contents_subprocess_success.
    """
    run_backup_script("--full-backup", env)
    archive_name = _find_archive_name(env.backup_dir, "FULL", "example")

    result = subprocess.run(
        [
            "dar-backup",
            "--list-contents", archive_name,
            "--config-file", env.config_file,
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, (
        f"dar-backup --list-contents failed:\n{result.stderr}"
    )

    output = result.stdout
    assert "[Saved]" in output, "Expected at least one [Saved] entry in output"

    for expected_file in ("file1.txt", "file2.txt", "file3.txt"):
        assert expected_file in output, (
            f"Expected '{expected_file}' in list-contents output:\n{output[:400]}"
        )


def test_list_contents_raises_for_nonexistent_archive(
    setup_environment, env: EnvData
) -> None:
    """
    list_contents() must raise RuntimeError with a message containing
    'Error listing contents' when asked to list a nonexistent archive.

    Complements test_list_contents_subprocess_error.
    """
    config = ConfigSettings(env.config_file)

    with _module_context(env):
        with pytest.raises(RuntimeError, match="listing contents"):
            db.list_contents("does_not_exist_archive_xyz", config.backup_dir)


def test_backup_with_unreadable_files_exits_zero(
    setup_environment, env: EnvData
) -> None:
    """
    dar-backup must exit 0 and still create an archive when dar exits 5 because
    some source files are unreadable.  The log must contain the 'some files were
    not saved' warning.

    dar exit code 5 is treated as a non-fatal warning: the archive and par2 files
    are created for the files dar could read; the pipeline reports SUCCESS.

    Complements test_generic_backup_warns_on_returncode_5.
    """
    unreadable_file = os.path.join(env.data_dir, "file1.txt")
    os.chmod(unreadable_file, 0o000)
    try:
        # run_backup_script raises if dar-backup exits nonzero.
        result = run_backup_script("--full-backup", env)

        # Archive must still be created for the files dar could read.
        _find_archive_name(env.backup_dir, "FULL", "example")

        # Log must contain the dar rc=5 warning message.
        assert "some files were not saved" in result.stdout, (
            "Expected 'some files were not saved' warning in backup stdout"
        )
    finally:
        os.chmod(unreadable_file, 0o644)


def test_catalog_add_fails_when_db_is_readonly(
    setup_environment, env: EnvData
) -> None:
    """
    When the catalog database is read-only, the dar DIFF archive must be created
    on disk but dar-backup must exit nonzero because the catalog update fails.

    Steps:
      1. Run a full backup (creates the FULL archive and the catalog DB).
      2. Make the catalog DB file read-only.
      3. Run a DIFF backup — dar creates and verifies the DIFF archive, but the
         deferred catalog phase cannot write to the read-only database, so
         dar-backup exits 1.
      4. Assert: DIFF slices exist on disk, exit code is 1.
      5. Restore DB permissions and verify the DIFF archive is not in the catalog.

    Complements test_catalog_add_failure_handled.
    """
    run_backup_script("--full-backup", env)
    _find_archive_name(env.backup_dir, "FULL", "example")

    db_path = os.path.join(env.backup_dir, "example.db")
    assert os.path.exists(db_path), f"Catalog DB not found at '{db_path}'"

    os.chmod(db_path, 0o444)
    try:
        diff_result = subprocess.run(
            [
                "dar-backup",
                "--differential-backup",
                "-d", "example",
                "--config-file", env.config_file,
                "--log-level", "debug",
                "--log-stdout",
            ],
            capture_output=True,
            text=True,
        )
        # dar-backup must exit nonzero because the catalog update failed.
        assert diff_result.returncode != 0, (
            "Expected dar-backup to exit nonzero when catalog DB is readonly, "
            f"but got 0.\nstdout: {diff_result.stdout[:500]}"
        )
    finally:
        os.chmod(db_path, 0o644)

    # DIFF archive must be on disk (dar backed it up before the catalog step failed).
    diff_slices = [
        f for f in os.listdir(env.backup_dir)
        if "_DIFF_" in f and f.endswith(".1.dar")
    ]
    assert diff_slices, (
        "DIFF archive slices must exist on disk even though catalog update failed"
    )

    # The catalog must not contain the DIFF archive (write was blocked).
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
    listing = runner.run(
        ["dar_manager", "--base", db_path, "--list"],
        timeout=60,
    )
    diff_archive_name = diff_slices[0][: -len(".1.dar")]
    assert diff_archive_name not in listing.stdout, (
        f"DIFF archive '{diff_archive_name}' must not be in the readonly catalog"
    )


def test_verify_raises_on_corrupt_archive(setup_environment, env: EnvData) -> None:
    """
    verify() must raise an exception when the dar archive fails the integrity
    test because a slice has been truncated.

    dar -t on a truncated archive exits nonzero; verify() converts that to an
    Exception.  This confirms the real exception-raise path that the mock test
    test_verify_restore_command_nonzero_raises validates synthetically.

    Complements test_verify_restore_command_nonzero_raises.
    """
    run_backup_script("--full-backup", env)
    archive_name = _find_archive_name(env.backup_dir, "FULL", "example")
    backup_def_path = os.path.join(env.backup_d_dir, "example")
    config = ConfigSettings(env.config_file)

    # Truncate the first slice to 10 bytes — the archive header is destroyed.
    slice_path = os.path.join(env.backup_dir, f"{archive_name}.1.dar")
    with open(slice_path, "r+b") as fh:
        fh.truncate(10)

    args = SimpleNamespace(verbose=False, do_not_compare=False, darrc=env.dar_rc)

    archive_path = os.path.join(config.backup_dir, archive_name)

    with _module_context(env):
        with pytest.raises(Exception):
            db.verify(args, archive_path, backup_def_path, config)


# ---------------------------------------------------------------------------
# Helpers for restore-test failure → metrics DB tests
# ---------------------------------------------------------------------------

# Must NOT be "example" — perform_backup() skips metrics for that name.
_RESTORE_TEST_DEF_NAME = "restore-test-check"


def _inject_metrics_db(env: EnvData) -> str:
    """Insert METRICS_DB_PATH into [MISC] in the test config; return the db path."""
    db_path = os.path.join(env.test_dir, "dar-backup-metrics.db")
    with open(env.config_file) as fh:
        content = fh.read()
    content = content.replace(
        "[MISC]\n",
        f"[MISC]\nMETRICS_DB_PATH = {db_path}\n",
        1,
    )
    with open(env.config_file, "w") as fh:
        fh.write(content)
    return db_path


def _latest_metrics_row(db_path: str) -> sqlite3.Row:
    """Return the most-recently written backup_runs row, or None."""
    with closing(sqlite3.connect(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        return conn.execute(
            "SELECT * FROM backup_runs ORDER BY id DESC LIMIT 1"
        ).fetchone()


def _create_restore_test_definition(env: EnvData) -> None:
    """Write a backup definition pointing at env.data_dir and create its catalog."""
    content = (
        "-R /\n"
        "-s 10G\n"
        "-z6\n"
        "-am\n"
        "--cache-directory-tagging\n"
        f"-g {env.data_dir}\n"
    ).replace("-g /tmp/", "-g tmp/")
    def_path = os.path.join(env.backup_d_dir, _RESTORE_TEST_DEF_NAME)
    with open(def_path, "w") as fh:
        fh.write(content)
    from dar_backup.command_runner import CommandRunner as _CR
    _CR(logger=env.logger, command_logger=env.command_logger).run(
        ["manager", "--create-db", "--config-file", env.config_file, "--log-level", "debug"],
        timeout=60,
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_verify_restore_test_failure_logs_error(
    setup_environment, env: EnvData
) -> None:
    """
    verify() must emit at least one ERROR log entry containing 'did not match'
    when restored files differ from their sources.

    Steps:
      1. Create a real full backup (archive has original content).
      2. Overwrite all source files with different content.
      3. Call verify() directly with a real runner.
      4. Assert restore_test_passed is False.
      5. Assert an ERROR was logged about the mismatch.

    This test calls verify() directly and is not subject to any timing issues.
    """
    run_backup_script("--full-backup", env)
    archive_name = _find_archive_name(env.backup_dir, "FULL", "example")
    backup_def_path = os.path.join(env.backup_d_dir, "example")
    config = ConfigSettings(env.config_file)

    for filename in os.listdir(env.data_dir):
        filepath = os.path.join(env.data_dir, filename)
        if os.path.isfile(filepath):
            with open(filepath, "w") as fh:
                fh.write("CORRUPTED — does not match archive content")

    captured_errors: list[str] = []

    class _ErrorCapture(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            if record.levelno >= logging.ERROR:
                captured_errors.append(record.getMessage())

    handler = _ErrorCapture()
    args = SimpleNamespace(verbose=False, do_not_compare=False, darrc=env.dar_rc)
    archive_path = os.path.join(config.backup_dir, archive_name)

    with _module_context(env):
        env.logger.addHandler(handler)
        try:
            result = db.verify(args, archive_path, backup_def_path, config)
        finally:
            env.logger.removeHandler(handler)

    assert result.restore_test_passed is False, (
        "verify() must return False when source files were modified after backup"
    )
    assert any("did not match" in msg for msg in captured_errors), (
        f"Expected ERROR containing 'did not match the original' but captured: {captured_errors}"
    )


def test_verify_missing_source_file_is_fail_not_skip(
    setup_environment, env: EnvData,
) -> None:
    """
    verify() must record a missing source file as FAIL (not SKIP) and log at ERROR level.

    When a source file is deleted between backup and verify, the file cannot be
    restored to its original state — that is a verification failure, not a benign
    skip.  Prior to the fix, FileNotFoundError set sample["result"]="SKIP" while
    still setting result=False, creating a contradictory metrics record.

    Steps:
      1. Set NO_FILES_VERIFICATION high enough to guarantee file1.txt is selected.
      2. Create a real full backup (file1.txt is archived).
      3. Delete file1.txt from the source directory.
      4. Call verify() directly with a real runner.
      5. Assert restore_test_passed is False.
      6. Assert an ERROR (not WARNING) was logged containing 'failed' and
         'source file missing' — confirming FAIL, not the old SKIP path.

    Complements test_verify_restore_test_failure_logs_error.
    """
    _set_no_files_verification(env, 20)

    run_backup_script("--full-backup", env)
    archive_name = _find_archive_name(env.backup_dir, "FULL", "example")
    backup_def_path = os.path.join(env.backup_d_dir, "example")
    config = ConfigSettings(env.config_file)

    # Delete file1.txt — it was backed up but no longer exists on source.
    os.remove(os.path.join(env.data_dir, "file1.txt"))

    captured: list[logging.LogRecord] = []

    class _Capture(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            captured.append(record)

    handler = _Capture()
    args = SimpleNamespace(verbose=False, do_not_compare=False, darrc=env.dar_rc)
    archive_path = os.path.join(config.backup_dir, archive_name)

    with _module_context(env):
        env.logger.addHandler(handler)
        try:
            result = db.verify(args, archive_path, backup_def_path, config)
        finally:
            env.logger.removeHandler(handler)

    assert result.restore_test_passed is False, (
        "verify() must return False when a source file is missing"
    )

    # Missing source must produce an ERROR saying "failed" + "source file missing".
    errors = [r for r in captured if r.levelno >= logging.ERROR]
    assert any(
        "failed" in r.getMessage() and "source file missing" in r.getMessage()
        for r in errors
    ), (
        f"Expected ERROR containing 'failed' and 'source file missing'; "
        f"got errors: {[r.getMessage() for r in errors]}"
    )

    # Must NOT be logged as a benign WARNING "skipped" (old behaviour).
    warnings = [r for r in captured if r.levelno == logging.WARNING]
    assert not any(
        "skipped" in r.getMessage() and "source file missing" in r.getMessage()
        for r in warnings
    ), "Missing source file must not be logged as a benign skip"


def test_restore_test_failure_writes_failure_to_metrics_db(
    setup_environment, env: EnvData
) -> None:
    """
    When the restore-test fails, dar-backup must exit non-zero and the metrics
    DB row must show status='FAILURE' with restore_test_passed=0.

    Steps:
      1. Inject METRICS_DB_PATH into the test config.
      2. Create a non-'example' backup definition (metrics are skipped for 'example').
      3. Add a 512 KB random-data file to the source to lengthen the backup phase.
      4. Launch dar-backup --full-backup as a non-blocking subprocess.
      5. Poll until the .1.dar slice size has been stable for 150 ms, which is
         the precise signal that dar has finished writing and closed the archive.
      6. Overwrite every source file with different content so that verify()'s
         restore-test detects a mismatch.
      7. Wait for dar-backup to exit.
      8. Assert: non-zero exit code.
      9. Assert: metrics row has status='FAILURE' and restore_test_passed=0.
      10. Assert: the rejected archive was never published to the PITR catalog.

    TIMING NOTE: stability is detected via 3 consecutive size-equal polls (50 ms
    each). After dar closes the archive, the subsequent dar -t, listing, and
    dar -x calls give the corruption time to land before verify() reads source
    files.
    """
    db_path = _inject_metrics_db(env)
    _create_restore_test_definition(env)

    # 512 KB of random (incompressible) data to ensure the backup phase
    # takes long enough for the corruption step to win the race.
    padding = os.path.join(env.data_dir, "padding.bin")
    with open(padding, "wb") as fh:
        fh.write(os.urandom(512 * 1024))

    proc = subprocess.Popen(
        [
            "dar-backup", "--full-backup",
            "-d", _RESTORE_TEST_DEF_NAME,
            "--config-file", env.config_file,
            "--log-level", "debug", "--log-stdout",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    # Poll until the .1.dar slice has stopped growing for 150 ms (3 × 50 ms polls).
    # Detecting the file appearing is not enough — on a fast NVMe dar can finish
    # writing and complete verify() before Python's poll loop fires.  Waiting for
    # size stability is the precise signal that dar just closed the archive; the
    # subsequent dar -t, listing, and dar -x calls give the source-file
    # corruption time to land before verify() reads them.
    deadline = time.time() + 120
    dar_appeared = False
    last_size = -1
    stable_count = 0
    while time.time() < deadline:
        try:
            slices = [f for f in os.listdir(env.backup_dir) if f.endswith(".1.dar")]
        except FileNotFoundError:
            slices = []
        if slices:
            current_size = os.path.getsize(os.path.join(env.backup_dir, slices[0]))
            if current_size == last_size:
                stable_count += 1
            else:
                last_size = current_size
                stable_count = 0
            if stable_count >= 3:
                dar_appeared = True
                # Corrupt every source file before verify() can read them.
                for filename in os.listdir(env.data_dir):
                    filepath = os.path.join(env.data_dir, filename)
                    if os.path.isfile(filepath):
                        with open(filepath, "w") as fh:
                            fh.write("CORRUPTED AFTER BACKUP — content mismatch expected")
                break
        time.sleep(0.05)

    stdout, stderr = proc.communicate(timeout=120)

    assert dar_appeared, (
        "Backup .dar slice never appeared — test setup failed, not a timing issue"
    )
    assert proc.returncode != 0, (
        f"dar-backup must exit non-zero when restore-test fails.\n"
        f"stdout (last 1000): {stdout[-1000:]}"
    )

    row = _latest_metrics_row(db_path)
    assert row is not None, "No metrics row was written to the DB"
    assert row["status"] == "FAILURE", (
        f"Expected status='FAILURE' but got '{row['status']}'. "
        "If this is 'WARNING', the results.append exit-code change from 2→1 "
        "in perform_backup() is missing or the timing race was lost."
    )
    assert row["restore_test_passed"] == 0, (
        f"Expected restore_test_passed=0 but got {row['restore_test_passed']}"
    )
    assert row["catalog_updated"] == 0, (
        "A verification-failed archive must record catalog_updated=0"
    )

    archive_name = _find_archive_name(
        env.backup_dir,
        "FULL",
        _RESTORE_TEST_DEF_NAME,
    )
    catalog_path = os.path.join(env.backup_dir, f"{_RESTORE_TEST_DEF_NAME}.db")
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
    catalog_result = runner.run(
        ["dar_manager", "--base", catalog_path, "--list"],
        timeout=60,
    )
    assert catalog_result.returncode == 0, catalog_result.stderr
    assert archive_name not in catalog_result.stdout, (
        f"verification-failed archive '{archive_name}' must remain outside PITR catalog"
    )
