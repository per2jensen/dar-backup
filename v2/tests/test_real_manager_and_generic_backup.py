#!/usr/bin/env python3
"""
Real integration tests for generic_backup(), manager catalog operations,
error paths in verify(), and the metrics DB pipeline.

Each test exercises real dar / dar_manager binaries and asserts on observable
filesystem or database state rather than on mocked stubs.

Tests are paired with their mock counterparts:
  - test_generic_backup_creates_archive_without_publishing_before_verification
      → complements test_generic_backup_success_returns_dar_result_without_catalog_registration
  - test_generic_backup_dar_stats_come_from_real_dar_output
      → complements test_generic_backup_dar_stats_parsed
  - test_manager_add_specific_archive_registers_in_catalog
      → complements test_manager_main_add_specific_archive_returns
  - test_manager_add_dir_populates_catalog
      → complements test_manager_main_add_dir_returns
  - test_manager_list_catalogs_shows_real_archive
      → complements test_manager_main_list_catalogs_returns
  - test_manager_find_file_locates_real_file
      → complements test_manager_main_find_file_returns
  - test_manager_list_archive_contents_shows_files
      → complements test_manager_main_list_archive_contents_returns
  - test_verify_raises_when_restore_dir_is_blocked
      → complements test_verify_restore_dir_create_error
  - test_dar_backup_alternate_reference_missing_exits_nonzero
      → complements test_perform_backup_alternate_reference_missing
  - test_metrics_db_row_written_after_real_backup
      → complements test_write_metrics_row_inserts_one_row
"""

import contextlib
import os
import re
import shlex
import shutil
import sqlite3
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Generator

import pytest

pytestmark = [pytest.mark.integration, pytest.mark.slow]

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

import dar_backup.dar_backup as db
from dar_backup.command_runner import CommandRunner
from dar_backup.config_settings import ConfigSettings
from dar_backup.dar_backup import create_backup_command
from dar_backup.util import BackupError
from tests.envdata import EnvData
from tests.testdata_verification import run_backup_script


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


@contextlib.contextmanager
def _module_context(env: EnvData) -> Generator[None, None, None]:
    """
    Temporarily wire dar_backup module-level logger and runner to real
    test-fixture objects, then restore the originals on exit.

    Args:
        env: EnvData fixture providing test loggers.

    Yields:
        None — callers import db directly and benefit from the globals.
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


def _run_manager(env: EnvData, extra_args: list) -> subprocess.CompletedProcess:
    """
    Run the manager CLI with the test config and capture stdout/stderr.

    Args:
        env: EnvData fixture providing config_file and logger.
        extra_args: Additional CLI arguments appended after --config-file.

    Returns:
        CompletedProcess from subprocess.run.
    """
    command = ["manager", "--config-file", env.config_file] + extra_args
    result = subprocess.run(command, capture_output=True, text=True)
    env.logger.info("manager stdout:\n%s", result.stdout)
    if result.returncode != 0:
        env.logger.error("manager stderr:\n%s", result.stderr)
    return result


def _run_dar_backup(env: EnvData, extra_args: list) -> subprocess.CompletedProcess:
    """
    Run the dar-backup CLI with the test config and capture stdout/stderr.

    Args:
        env: EnvData fixture providing config_file and logger.
        extra_args: Additional CLI arguments appended after --config-file.

    Returns:
        CompletedProcess from subprocess.run.
    """
    command = [
        "dar-backup",
        "--config-file", env.config_file,
        "--log-stdout",
        "--log-level", "debug",
    ] + extra_args
    result = subprocess.run(command, capture_output=True, text=True)
    env.logger.info("dar-backup stdout:\n%s", result.stdout)
    if result.returncode != 0:
        env.logger.error("dar-backup stderr:\n%s", result.stderr)
    return result


def _catalog_contains(env: EnvData, archive_name: str) -> bool:
    """
    Return True when the dar_manager catalog lists the given archive name.

    Args:
        env: EnvData fixture providing config_file and logger.
        archive_name: Archive base name to search for in list output.

    Returns:
        True if archive_name appears in the catalog listing.
    """
    result = _run_manager(env, ["--list-catalogs", "-d", "example", "--log-stdout"])
    return archive_name in result.stdout


# ---------------------------------------------------------------------------
# Group A — generic_backup() with real dar
# ---------------------------------------------------------------------------


def test_generic_backup_creates_archive_without_publishing_before_verification(
    setup_environment,
    env: EnvData,
) -> None:
    """
    generic_backup() called directly with a real dar command must create
    the .1.dar slice on disk without registering it in dar_manager.

    Catalog publication belongs to perform_backup() after verification, so a
    direct DAR-phase call must not expose an unverified restore point to PITR.
    """
    from datetime import datetime

    config = ConfigSettings(env.config_file)
    date = datetime.now().strftime("%Y-%m-%d")
    backup_file = os.path.join(config.backup_dir, f"example_FULL_{date}")
    backup_def_path = os.path.join(env.backup_d_dir, "example")
    args = SimpleNamespace(config_file=env.config_file, darrc=env.dar_rc)
    command = create_backup_command("FULL", backup_file, env.dar_rc, backup_def_path)

    with _module_context(env):
        result = db.generic_backup(
            "FULL",
            command,
            backup_file,
            backup_def_path,
            env.dar_rc,
            config,
            args,
        )

    assert os.path.exists(backup_file + ".1.dar"), (
        f"Expected .1.dar slice on disk after generic_backup: {backup_file}.1.dar"
    )
    assert result.dar_exit_code == 0
    assert not _catalog_contains(env, os.path.basename(backup_file)), (
        "generic_backup() must not publish an archive before verification"
    )


def test_generic_backup_exit_4_valid_archive_remains_outside_catalog(
    setup_environment,
    env: EnvData,
) -> None:
    """An aborted DAR result must not publish even a structurally valid archive.

    A real wrapper runs DAR to successful completion, leaving a valid archive,
    then deliberately exits 4. This deterministically exercises the dangerous
    case without mocking subprocess behavior: the old implementation added the
    valid archive to dar_manager despite the aborted status.
    """
    real_dar = shutil.which("dar")
    assert real_dar is not None, "dar must be installed for this integration test"

    wrapper = Path(env.test_dir) / "dar-exit-4-wrapper"
    wrapper.write_text(
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        f"{shlex.quote(real_dar)} \"$@\"\n"
        "exit 4\n",
        encoding="utf-8",
    )
    wrapper.chmod(0o755)

    config = ConfigSettings(env.config_file)
    date = db.datetime.now().strftime("%Y-%m-%d")
    backup_file = os.path.join(config.backup_dir, f"example_FULL_{date}")
    backup_def_path = os.path.join(env.backup_d_dir, "example")
    args = SimpleNamespace(config_file=env.config_file, darrc=env.dar_rc)
    command = create_backup_command("FULL", backup_file, env.dar_rc, backup_def_path)
    command[0] = str(wrapper)

    with _module_context(env), pytest.raises(BackupError) as exc_info:
        db.generic_backup(
            "FULL",
            command,
            backup_file,
            backup_def_path,
            env.dar_rc,
            config,
            args,
        )

    assert exc_info.value.dar_exit_code == 4
    assert os.path.exists(backup_file + ".1.dar"), (
        "the wrapper must leave a real archive so catalog exclusion is meaningful"
    )
    assert not _catalog_contains(env, os.path.basename(backup_file)), (
        "an archive from a DAR process that exited 4 must remain outside PITR catalog"
    )


def test_generic_backup_dar_stats_come_from_real_dar_output(setup_environment, env: EnvData) -> None:
    """
    generic_backup() must parse real inode statistics from dar's summary output.

    After a successful FULL backup, dar_stats["inodes_saved"] must be a
    non-negative integer (not None), confirming that parse_dar_stats() matched
    the real locale-formatted output produced by dar.

    Complements the mock-only test that checks the dict structure in isolation.
    """
    from datetime import datetime

    config = ConfigSettings(env.config_file)
    date = datetime.now().strftime("%Y-%m-%d")
    backup_file = os.path.join(config.backup_dir, f"example_FULL_{date}")
    backup_def_path = os.path.join(env.backup_d_dir, "example")
    args = SimpleNamespace(config_file=env.config_file, darrc=env.dar_rc)
    command = create_backup_command("FULL", backup_file, env.dar_rc, backup_def_path)

    with _module_context(env):
        result = db.generic_backup(
            "FULL",
            command,
            backup_file,
            backup_def_path,
            env.dar_rc,
            config,
            args,
        )

    inodes_saved = result.dar_stats.get("inodes_saved")
    assert inodes_saved is not None, (
        "parse_dar_stats() must extract inodes_saved from real dar output; "
        f"got None — check LANG setting or dar output format. "
        f"Full dar_stats: {result.dar_stats}"
    )
    assert int(inodes_saved) >= 0, (
        f"inodes_saved must be non-negative, got: {inodes_saved}"
    )


# ---------------------------------------------------------------------------
# Group B — manager catalog operations via CLI
# ---------------------------------------------------------------------------


def test_manager_add_specific_archive_registers_in_catalog(setup_environment, env: EnvData) -> None:
    """
    `manager --add-specific-archive` must add an on-disk archive to the
    dar_manager catalog so it appears in `--list-catalogs` output.

    Steps:
      1. Create a real FULL backup (archive on disk + in catalog).
      2. Remove it from the catalog with --remove-specific-archive.
      3. Confirm it is gone from the catalog.
      4. Re-add it with --add-specific-archive.
      5. Confirm it appears in --list-catalogs output.

    Complements test_manager_main_add_specific_archive_returns which only
    asserts the function was called.
    """
    run_backup_script("--full-backup", env)
    archive_name = _find_archive_name(env.backup_dir, "FULL", "example")
    archive_path = os.path.join(env.backup_dir, archive_name)

    # Remove from catalog so we can prove --add-specific-archive works
    remove_result = _run_manager(
        env,
        ["--remove-specific-archive", archive_name, "--log-stdout"],
    )
    assert remove_result.returncode == 0, (
        f"--remove-specific-archive failed:\n{remove_result.stderr}"
    )

    assert not _catalog_contains(env, archive_name), (
        f"Archive '{archive_name}' still in catalog after --remove-specific-archive"
    )

    # Re-add via CLI
    add_result = _run_manager(
        env,
        ["--add-specific-archive", archive_path, "--log-stdout"],
    )
    assert add_result.returncode == 0, (
        f"--add-specific-archive failed:\n{add_result.stderr}"
    )

    assert _catalog_contains(env, archive_name), (
        f"Archive '{archive_name}' not found in catalog after --add-specific-archive"
    )


def test_manager_add_dir_populates_catalog(setup_environment, env: EnvData) -> None:
    """
    `manager --add-dir` must scan the given directory and register every
    .dar archive it finds in the catalog.

    Steps:
      1. Create a real FULL backup (archive on disk + in catalog).
      2. Remove from catalog with --remove-specific-archive.
      3. Re-populate via --add-dir pointing at the backup directory.
      4. Assert the archive appears in --list-catalogs.

    Complements test_manager_main_add_dir_returns which only asserts the
    function was called.
    """
    run_backup_script("--full-backup", env)
    archive_name = _find_archive_name(env.backup_dir, "FULL", "example")

    # Clear the catalog entry so --add-dir has something to prove
    remove_result = _run_manager(
        env,
        ["--remove-specific-archive", archive_name, "--log-stdout"],
    )
    assert remove_result.returncode == 0, (
        f"--remove-specific-archive failed:\n{remove_result.stderr}"
    )

    assert not _catalog_contains(env, archive_name), (
        f"Archive '{archive_name}' still in catalog after --remove-specific-archive"
    )

    # Re-populate via --add-dir
    add_dir_result = _run_manager(
        env,
        ["--add-dir", env.backup_dir, "--log-stdout"],
    )
    assert add_dir_result.returncode == 0, (
        f"--add-dir failed:\n{add_dir_result.stderr}"
    )

    assert _catalog_contains(env, archive_name), (
        f"Archive '{archive_name}' not in catalog after --add-dir"
    )


def test_manager_list_catalogs_shows_real_archive(setup_environment, env: EnvData) -> None:
    """
    `manager --list-catalogs -d example` must print the FULL archive base
    name to stdout after a real backup has been created.

    Complements test_manager_main_list_catalogs_returns which only asserts
    the function was called.
    """
    run_backup_script("--full-backup", env)
    archive_name = _find_archive_name(env.backup_dir, "FULL", "example")

    result = _run_manager(
        env,
        ["--list-catalogs", "-d", "example", "--log-stdout"],
    )
    assert result.returncode == 0, (
        f"--list-catalogs failed:\n{result.stderr}"
    )
    assert archive_name in result.stdout, (
        f"Expected '{archive_name}' in --list-catalogs output:\n{result.stdout}"
    )


def test_manager_find_file_locates_real_file(setup_environment, env: EnvData) -> None:
    """
    `manager --find-file <relative-path> -d example` must return exit code 0
    and include the filename in its output when the file is in a real catalog.

    dar_manager -f expects the full path as stored in the archive (relative to
    the archive root `/`), e.g. "tmp/.../data/file1.txt", not just "file1.txt".

    Complements test_manager_main_find_file_returns which only asserts the
    function was called.
    """
    run_backup_script("--full-backup", env)

    # Compute path as stored in the dar archive (relative to archive root /)
    file_rel_path = os.path.relpath(
        os.path.join(env.data_dir, "file1.txt"), "/"
    )

    result = _run_manager(
        env,
        ["--find-file", file_rel_path, "-d", "example", "--log-stdout"],
    )
    assert result.returncode == 0, (
        f"--find-file exited non-zero (file not found in catalog):\n{result.stderr}"
    )
    # dar_manager -f prints archive-number / date / save-status per matching archive.
    # "saved" confirms the file entry exists and was saved in the archive.
    assert "saved" in result.stdout, (
        f"Expected 'saved' status in --find-file output:\n{result.stdout}"
    )


def test_manager_list_archive_contents_shows_files(setup_environment, env: EnvData) -> None:
    """
    `manager --list-archive-contents <archive>` must print the saved file
    entries from a real catalog, including at least one "[ Saved ]" line
    referencing a known test file.

    Complements test_manager_main_list_archive_contents_returns which only
    asserts the function was called.
    """
    run_backup_script("--full-backup", env)
    archive_name = _find_archive_name(env.backup_dir, "FULL", "example")

    result = _run_manager(
        env,
        ["--list-archive-contents", archive_name, "--log-stdout"],
    )
    assert result.returncode == 0, (
        f"--list-archive-contents exited non-zero:\n{result.stderr}"
    )
    # dar_manager -u output lines for saved files begin with "[ Saved ]"
    saved_lines = [
        line for line in result.stdout.splitlines()
        if "[ Saved ]" in line or "file1.txt" in line
    ]
    assert saved_lines, (
        f"Expected at least one '[ Saved ]' or 'file1.txt' line in output:\n{result.stdout}"
    )


# ---------------------------------------------------------------------------
# Group C — error paths
# ---------------------------------------------------------------------------


def test_verify_raises_when_restore_dir_is_blocked(setup_environment, env: EnvData) -> None:
    """
    verify() must raise BackupError("Cannot create restore directory …") when
    the test_restore_dir path is occupied by a regular file (making os.makedirs
    fail with OSError).

    Steps:
      1. Run a real FULL backup so a valid archive exists.
      2. Replace test_restore_dir with a regular file at the same path.
      3. Call db.verify() — os.makedirs raises OSError → BackupError.
      4. Confirm the error message matches the expected prefix.

    Complements test_verify_restore_dir_create_error which monkeypatches
    os.makedirs.
    """
    from dar_backup.util import BackupError

    run_backup_script("--full-backup", env)
    archive_name = _find_archive_name(env.backup_dir, "FULL", "example")
    config = ConfigSettings(env.config_file)
    archive_path = os.path.join(config.backup_dir, archive_name)
    backup_def_path = os.path.join(env.backup_d_dir, "example")
    args = SimpleNamespace(verbose=False, do_not_compare=False, darrc=env.dar_rc)

    # config paths may include a trailing slash; strip it so open() treats the
    # name as a file, not as a directory reference.
    restore_dir = config.test_restore_dir.rstrip("/")
    try:
        # Replace the directory with a regular file so os.makedirs(…, exist_ok=True)
        # raises OSError (the path exists but is not a directory).
        if os.path.isdir(restore_dir):
            shutil.rmtree(restore_dir)
        with open(restore_dir, "w") as fh:
            fh.write("blocking file — not a directory\n")

        with _module_context(env):
            with pytest.raises(BackupError, match="Cannot create restore directory"):
                db.verify(args, archive_path, backup_def_path, config)
    finally:
        # Restore a usable directory so teardown can proceed cleanly
        if os.path.isfile(restore_dir):
            os.remove(restore_dir)
        os.makedirs(restore_dir, exist_ok=True)


def test_dar_backup_alternate_reference_missing_exits_nonzero(setup_environment, env: EnvData) -> None:
    """
    dar-backup --differential-backup with --alternate-reference-archive pointing
    to a non-existent archive must exit non-zero and log the expected error message.

    Steps:
      1. Run a real FULL backup to satisfy normal differential prerequisites.
      2. Run dar-backup --differential-backup --alternate-reference-archive nonexistent.
      3. Assert non-zero exit code.
      4. Assert the error message about the missing alternate reference appears
         in stdout (log sent to stdout via --log-stdout).

    Complements test_perform_backup_alternate_reference_missing which
    monkeypatches the logger.
    """
    run_backup_script("--full-backup", env)

    result = _run_dar_backup(
        env,
        ["--differential-backup", "--alternate-reference-archive", "nonexistent_archive"],
    )

    assert result.returncode != 0, (
        "Expected non-zero exit when alternate reference archive does not exist, "
        f"got returncode={result.returncode}"
    )
    combined = result.stdout + result.stderr
    assert "Alternate reference archive" in combined or "nonexistent_archive" in combined, (
        f"Expected error message about missing alternate reference in output:\n{combined}"
    )


# ---------------------------------------------------------------------------
# Group D — metrics DB
# ---------------------------------------------------------------------------


def test_metrics_db_row_written_after_real_backup(setup_environment, env: EnvData) -> None:
    """
    A real FULL backup run must write one SUCCESS row to the metrics SQLite DB
    when METRICS_DB_PATH is configured.

    dar-backup skips metrics collection for the literal backup definition named
    "example" (it is treated as a demo/template). A second definition "mtest"
    with identical content avoids that exclusion and ensures the row is written.

    Steps:
      1. Create an alternate backup definition "mtest" (same content as "example").
      2. Create its catalog DB via manager --create-db.
      3. Inject METRICS_DB_PATH under [MISC] in the config file.
      4. Run dar-backup --full-backup -d mtest.
      5. Assert exactly one SUCCESS row exists in the metrics SQLite DB.

    Complements test_write_metrics_row_inserts_one_row which uses a hand-crafted
    dict and never runs a real backup.
    """
    metrics_db = os.path.join(env.backup_dir, "metrics.db")

    # Create an alternate backup definition so metrics are not skipped
    alt_def = "mtest"
    example_def_path = os.path.join(env.backup_d_dir, "example")
    alt_def_path = os.path.join(env.backup_d_dir, alt_def)
    with open(example_def_path) as fh:
        example_content = fh.read()
    with open(alt_def_path, "w") as fh:
        fh.write(example_content)

    # Create the catalog DB for the new definition
    create_result = _run_manager(env, ["--create-db", "--log-stdout"])
    assert create_result.returncode == 0, (
        f"manager --create-db failed:\n{create_result.stderr}"
    )

    # Inject METRICS_DB_PATH into [MISC] section
    with open(env.config_file) as fh:
        config_text = fh.read()
    injected = config_text.replace(
        "[MISC]",
        f"[MISC]\nMETRICS_DB_PATH = {metrics_db}",
        1,
    )
    with open(env.config_file, "w") as fh:
        fh.write(injected)

    result = _run_dar_backup(env, ["--full-backup", "-d", alt_def])
    assert result.returncode == 0, (
        f"Full backup failed (returncode={result.returncode}):\n{result.stdout}\n{result.stderr}"
    )

    assert os.path.exists(metrics_db), (
        f"Metrics DB was not created at: {metrics_db}"
    )

    with contextlib.closing(sqlite3.connect(metrics_db)) as conn:
        rows = conn.execute(
            "SELECT backup_type, status FROM backup_runs WHERE backup_type = 'FULL'"
        ).fetchall()

    assert len(rows) == 1, (
        f"Expected exactly 1 FULL row in metrics DB, found {len(rows)}: {rows}"
    )
    backup_type, status = rows[0]
    assert backup_type == "FULL", f"backup_type mismatch: {backup_type}"
    assert status == "SUCCESS", (
        f"Expected status='SUCCESS' in metrics DB row, got: {status}"
    )
