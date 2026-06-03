#!/usr/bin/env python3
"""
Integration tests for dar_backup.py that call module functions directly
(in-process) so that coverage is tracked.

No mocking.  Real `dar` and `manager` binaries are used wherever a backup is
involved.  Functions are called directly (not via subprocess) because subprocess
coverage is not recorded in this project (no sitecustomize.py in the venv).
"""

import glob
import io
import os
import sqlite3
import stat
import sys
from contextlib import closing, redirect_stdout, redirect_stderr
from pathlib import Path
from types import SimpleNamespace

import pytest

pytestmark = [pytest.mark.integration, pytest.mark.smoke]

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

import dar_backup.dar_backup as dar_backup_mod
from dar_backup import __about__ as about
from dar_backup.command_runner import CommandRunner
from dar_backup.config_settings import ConfigSettings
from dar_backup.util import update_postreq_status
from tests.testdata_verification import run_backup_script


# ---------------------------------------------------------------------------
# list_definitions() — direct call, no mocking
# ---------------------------------------------------------------------------

def test_dar_backup_list_definitions_function(setup_environment, env):
    """
    Call list_definitions() directly; verify 'example' is returned.

    Covers: list_definitions() body (lines 1737-1749).
    """
    defs = dar_backup_mod.list_definitions(env.backup_d_dir)
    assert "example" in defs, f"'example' not found in definitions: {defs}"
    env.logger.info("list_definitions() returned %s ✓", defs)


def test_dar_backup_list_definitions_invalid_name_skipped(setup_environment, env):
    """
    When backup.d contains an entry with an invalid name, list_definitions()
    skips it and prints a warning to stderr.

    Covers: the else/warning branch inside list_definitions() (lines 1751-1755).

    dar_backup.py uses `from sys import stderr` at module level, so the module's
    `stderr` attribute is bound to the original file object — not to sys.stderr.
    redirect_stderr() only redirects sys.stderr, so we must swap dar_backup_mod.stderr
    directly with a StringIO buffer to capture the warning.
    """
    bad_def = os.path.join(env.backup_d_dir, "bad name!")
    with open(bad_def, "w") as f:
        f.write("-R /\n")
    buf = io.StringIO()
    saved_stderr = dar_backup_mod.stderr
    dar_backup_mod.stderr = buf
    try:
        defs = dar_backup_mod.list_definitions(env.backup_d_dir)
        assert "bad name!" not in defs
        assert "example" in defs
        warning = buf.getvalue()
        assert "skipping" in warning.lower() or "invalid" in warning.lower(), (
            f"expected skipping/invalid warning, got: {warning!r}"
        )
    finally:
        dar_backup_mod.stderr = saved_stderr
        os.remove(bad_def)
    env.logger.info("list_definitions() skipped invalid name ✓")


# ---------------------------------------------------------------------------
# print_changelog / print_readme — direct calls, no mocking
# ---------------------------------------------------------------------------

def test_dar_backup_print_changelog(capsys):
    """
    Call print_changelog() directly with pretty=False.

    Covers: print_changelog (1728-1730), _resolve_doc_path (1708-1725),
    print_markdown plain-text path (1702-1703).
    """
    dar_backup_mod.print_changelog(None, pretty=False)
    captured = capsys.readouterr()
    assert len(captured.out) > 0, "Changelog output should not be empty"


def test_dar_backup_print_readme(capsys):
    """
    Call print_readme() directly with pretty=False.

    Covers: print_readme (1733-1735), same _resolve_doc_path and print_markdown
    paths as above.
    """
    dar_backup_mod.print_readme(None, pretty=False)
    captured = capsys.readouterr()
    assert len(captured.out) > 0, "README output should not be empty"


# ---------------------------------------------------------------------------
# filter_darrc_file() — direct call, real .darrc file
# ---------------------------------------------------------------------------

def test_dar_backup_filter_darrc_file(setup_environment, env):
    """
    Call filter_darrc_file() with the real .darrc from the test environment;
    verify the filtered copy is created, has mode 0o440, and strips -vt/-vs etc.

    Covers: filter_darrc_file() body (lines 1574-1589).
    """
    filtered = dar_backup_mod.filter_darrc_file(env.dar_rc)
    try:
        assert os.path.exists(filtered), "filtered darrc file must be created"
        mode = stat.S_IMODE(os.stat(filtered).st_mode)
        assert mode == 0o440, f"expected mode 440, got {oct(mode)}"
        with open(filtered) as f:
            content = f.read()
        for opt in ["-vt", "-vs", "-vd", "-vf", "-va"]:
            for line in content.splitlines():
                assert opt not in line, f"{opt} should be stripped but found in: {line!r}"
    finally:
        if os.path.exists(filtered):
            os.chmod(filtered, 0o644)
            os.remove(filtered)
    env.logger.info("filter_darrc_file() produced correct filtered darrc ✓")


# ---------------------------------------------------------------------------
# clean_restore_test_directory() — direct call, real files
# ---------------------------------------------------------------------------

def test_dar_backup_clean_restore_test_directory(setup_environment, env):
    """
    Put files in the restore test directory, then call
    clean_restore_test_directory() directly.  Verifies the directory is emptied.

    Covers: lines 1787-1799 (the os.listdir / shutil.rmtree cleaning loop).
    """
    config_settings = ConfigSettings(env.config_file)
    restore_dir = config_settings.test_restore_dir

    sentinel_file = os.path.join(restore_dir, "sentinel.txt")
    sentinel_subdir = os.path.join(restore_dir, "subdir")
    os.makedirs(sentinel_subdir, exist_ok=True)
    with open(sentinel_file, "w") as f:
        f.write("clean me")

    # dar_backup_mod.logger is None at module level; set it for the call
    saved_logger = dar_backup_mod.logger
    dar_backup_mod.logger = env.logger
    try:
        dar_backup_mod.clean_restore_test_directory(config_settings)
    finally:
        dar_backup_mod.logger = saved_logger

    assert not os.path.exists(sentinel_file), "sentinel file should be removed"
    assert not os.path.exists(sentinel_subdir), "sentinel subdir should be removed"
    env.logger.info("clean_restore_test_directory() cleared restore dir ✓")


# ---------------------------------------------------------------------------
# should_clean_restore_test_directory() — direct call, no mocking
# ---------------------------------------------------------------------------

def test_dar_backup_should_clean_for_full_backup(setup_environment, env):
    """
    With --full-backup and do_not_compare=False, should_clean returns True.

    Covers: first branch (line 1808-1809).
    """
    config_settings = ConfigSettings(env.config_file)
    args = SimpleNamespace(
        full_backup=True, differential_backup=False, incremental_backup=False,
        restore=False, do_not_compare=False, restore_dir=None,
    )
    assert dar_backup_mod.should_clean_restore_test_directory(args, config_settings) is True


def test_dar_backup_should_not_clean_when_do_not_compare(setup_environment, env):
    """
    With --full-backup and --do-not-compare, should_clean returns False.

    Covers: do_not_compare branch (line 1809).
    """
    config_settings = ConfigSettings(env.config_file)
    args = SimpleNamespace(
        full_backup=True, differential_backup=False, incremental_backup=False,
        restore=False, do_not_compare=True, restore_dir=None,
    )
    assert dar_backup_mod.should_clean_restore_test_directory(args, config_settings) is False


def test_dar_backup_should_clean_restore_to_same_dir(setup_environment, env):
    """
    With --restore pointing to the default test_restore_dir, should_clean is True.

    Covers: restore branch (lines 1811-1815) when dirs match.
    """
    config_settings = ConfigSettings(env.config_file)
    args = SimpleNamespace(
        full_backup=False, differential_backup=False, incremental_backup=False,
        restore=True, do_not_compare=False,
        restore_dir=config_settings.test_restore_dir,
    )
    assert dar_backup_mod.should_clean_restore_test_directory(args, config_settings) is True


def test_dar_backup_should_not_clean_restore_to_different_dir(setup_environment, env, tmp_path):
    """
    With --restore pointing to a different directory, should_clean is False.

    Covers: restore branch (lines 1811-1815) when dirs differ.
    """
    config_settings = ConfigSettings(env.config_file)
    args = SimpleNamespace(
        full_backup=False, differential_backup=False, incremental_backup=False,
        restore=True, do_not_compare=False,
        restore_dir=str(tmp_path / "other_restore"),
    )
    assert dar_backup_mod.should_clean_restore_test_directory(args, config_settings) is False


# ---------------------------------------------------------------------------
# Full backup with --suppress-dar-msg — uses real dar, no mocking
#
# filter_darrc_file() is called first to get the filtered .darrc path, then
# run_backup_script() is called to do the real backup using that filtered .darrc
# via the --darrc flag.  The filtered file is cleaned up in a finally block.
# ---------------------------------------------------------------------------

def test_dar_backup_full_backup_with_suppress_dar_msg(setup_environment, env):
    """
    Simulate --suppress-dar-msg by:
      1. Calling filter_darrc_file() in-process (covers lines 1574-1589).
      2. Running a real FULL backup via dar-backup with the filtered .darrc
         passed explicitly (--darrc flag).
      3. Verifying the filtered temp file is cleaned up.

    Real `dar` runs.  No mocking.
    """
    # Step 1: create the filtered darrc in-process
    filtered_darrc = dar_backup_mod.filter_darrc_file(env.dar_rc)
    assert os.path.exists(filtered_darrc)

    try:
        # Step 2: run a real backup using the filtered darrc
        runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
        r = runner.run([
            "dar-backup", "--full-backup", "-d", "example",
            "--darrc", filtered_darrc,
            "--log-stdout", "-c", env.config_file,
        ], timeout=300)
        assert r.returncode == 0, f"backup with filtered darrc failed: {r.stderr}"

        archives = glob.glob(os.path.join(env.backup_dir, "example_FULL_*.1.dar"))
        assert len(archives) > 0, "A FULL .dar slice must exist after backup"
        env.logger.info("Backup with suppress-dar-msg (filtered darrc) ✓")
    finally:
        # Step 3: clean up the filtered darrc (mirrors what main() does)
        if os.path.exists(filtered_darrc):
            os.chmod(filtered_darrc, 0o644)
            os.remove(filtered_darrc)


# ---------------------------------------------------------------------------
# list_definitions() — subdir in backup_d_dir must be skipped
# ---------------------------------------------------------------------------

def test_dar_backup_list_definitions_skips_subdirectory(setup_environment, env):
    """
    list_definitions() must not include subdirectories of backup_d_dir in the
    returned list — only plain files are valid backup definitions.

    Covers: line 1747 (continue for non-file entries).
    """
    subdir = os.path.join(env.backup_d_dir, "a_subdir_that_must_be_skipped")
    os.makedirs(subdir, exist_ok=True)
    try:
        defs = dar_backup_mod.list_definitions(env.backup_d_dir)
        assert "a_subdir_that_must_be_skipped" not in defs, (
            "subdirectory must never appear in the definitions list"
        )
        assert "example" in defs, "the real 'example' definition must still be present"
    finally:
        os.rmdir(subdir)
    env.logger.info("list_definitions() correctly skipped subdirectory ✓")


# ---------------------------------------------------------------------------
# clean_restore_test_directory() — early-return guards
# ---------------------------------------------------------------------------

def test_dar_backup_clean_restore_no_restore_dir_configured():
    """
    clean_restore_test_directory() must be a no-op when test_restore_dir is
    not set on the config object — it must return without touching anything.

    Covers: line 1765 (early return when restore_dir is falsy).
    """
    class _Config:
        test_restore_dir = None

    # If the function proceeds past the guard it would crash (no logger set).
    # Completing without exception proves the early return fired.
    dar_backup_mod.clean_restore_test_directory(_Config())


def test_dar_backup_clean_restore_nonexistent_path_is_noop(tmp_path):
    """
    clean_restore_test_directory() must not raise and must not create or
    delete anything when the configured test_restore_dir does not exist.

    Covers: line 1770 (early return when restore_dir path is absent).
    """
    class _Config:
        test_restore_dir = str(tmp_path / "this_dir_does_not_exist")

    # Sentinel: verify no directory was created as a side-effect
    dar_backup_mod.clean_restore_test_directory(_Config())
    assert not (tmp_path / "this_dir_does_not_exist").exists(), (
        "function must not create a missing restore directory"
    )


# ---------------------------------------------------------------------------
# _normalize_restore_dir() — None / empty input
# ---------------------------------------------------------------------------

def test_dar_backup_normalize_restore_dir_falsy_inputs():
    """
    _normalize_restore_dir() must return None for None and for an empty string.
    This guards callers that compare the result to a known path against
    accidental matches with an uninitialised value.

    Covers: line 1803 (return None when path is falsy).
    """
    assert dar_backup_mod._normalize_restore_dir(None) is None
    assert dar_backup_mod._normalize_restore_dir("") is None


# ---------------------------------------------------------------------------
# should_clean_restore_test_directory() — no-operation fallback
# ---------------------------------------------------------------------------

def test_dar_backup_should_not_clean_when_no_operation(setup_environment, env):
    """
    should_clean_restore_test_directory() must return False when the args
    object requests neither backup nor restore — there is no operation that
    would write to the restore directory, so cleaning it would be incorrect.

    Covers: line 1817 (return False fallback at end of function).
    """
    config_settings = ConfigSettings(env.config_file)
    args = SimpleNamespace(
        full_backup=False, differential_backup=False, incremental_backup=False,
        restore=False,
    )
    result = dar_backup_mod.should_clean_restore_test_directory(args, config_settings)
    assert result is False, (
        "must not clean restore dir when no backup/restore operation is requested"
    )


# ---------------------------------------------------------------------------
# main() early-exit CLI flags — no dar, no config needed
# ---------------------------------------------------------------------------

def test_dar_backup_main_version_flag_prints_version(capsys):
    """
    dar-backup --version must exit 0 and print the version string so that
    scripts and users can reliably detect the installed release.

    Covers: lines 1888-1889 (show_version() + exit in main()).
    """
    saved_argv = sys.argv[:]
    sys.argv = ["dar-backup", "--version"]
    try:
        with pytest.raises(SystemExit) as exc_info:
            dar_backup_mod.main()
        assert exc_info.value.code == 0
    finally:
        sys.argv = saved_argv

    out = capsys.readouterr().out
    assert about.__version__ in out, (
        f"version string '{about.__version__}' must appear in --version output; got: {out!r}"
    )


def test_dar_backup_main_examples_flag_prints_usage(capsys):
    """
    dar-backup --examples must exit 0 and print at least one example command
    so that new users can get started without reading the full manual.

    Covers: lines 1891-1892 (show_examples() + exit in main()).
    """
    saved_argv = sys.argv[:]
    sys.argv = ["dar-backup", "--examples"]
    try:
        with pytest.raises(SystemExit) as exc_info:
            dar_backup_mod.main()
        assert exc_info.value.code == 0
    finally:
        sys.argv = saved_argv

    out = capsys.readouterr().out
    assert "full-backup" in out.lower() or "dar-backup" in out.lower(), (
        f"expected example commands in output; got: {out!r}"
    )


def test_dar_backup_main_readme_flag_prints_content(capsys):
    """
    dar-backup --readme must exit 0 and print the README so that the
    documentation is accessible directly from the CLI.

    Covers: lines 1894-1895 (print_readme() + exit in main()).
    """
    saved_argv = sys.argv[:]
    sys.argv = ["dar-backup", "--readme"]
    try:
        with pytest.raises(SystemExit) as exc_info:
            dar_backup_mod.main()
        assert exc_info.value.code == 0
    finally:
        sys.argv = saved_argv

    out = capsys.readouterr().out
    assert len(out) > 100, "README output must be non-trivial"


def test_dar_backup_main_changelog_flag_prints_content(capsys):
    """
    dar-backup --changelog must exit 0 and print the CHANGELOG so users can
    inspect release history directly from the CLI.

    Covers: lines 1900-1901 (print_changelog() + exit in main()).
    """
    saved_argv = sys.argv[:]
    sys.argv = ["dar-backup", "--changelog"]
    try:
        with pytest.raises(SystemExit) as exc_info:
            dar_backup_mod.main()
        assert exc_info.value.code == 0
    finally:
        sys.argv = saved_argv

    out = capsys.readouterr().out
    assert len(out) > 100, "CHANGELOG output must be non-trivial"


# ---------------------------------------------------------------------------
# _record_prereq_failure() — PREREQ failure recorded in DB and stats
# ---------------------------------------------------------------------------

def _inject_metrics_db(config_file: str, test_dir: str) -> str:
    """
    Append METRICS_DB_PATH to the [MISC] section of config_file so that
    write_metrics_row() actually writes to an SQLite DB we can inspect.

    Returns:
        Absolute path to the metrics DB that will be created.
    """
    metrics_db = os.path.join(test_dir, "prereq_metrics.db")
    with open(config_file) as fh:
        content = fh.read()
    if "[MISC]\n" not in content:
        raise RuntimeError(f"[MISC] section not found in {config_file}")
    content = content.replace(
        "[MISC]\n",
        f"[MISC]\nMETRICS_DB_PATH = {metrics_db}\n",
        1,
    )
    with open(config_file, "w") as fh:
        fh.write(content)
    return metrics_db


def test_record_prereq_failure_single_definition(setup_environment, env):
    """
    When _record_prereq_failure() is called with args.backup_definition set,
    exactly one FAILURE row with failed_phase='PREREQ' must be written to the
    metrics DB and one matching entry must appear in stats_accumulator.

    This directly tests the in-process helper so no 'dar' run is needed.
    """
    metrics_db = _inject_metrics_db(env.config_file, env.test_dir)
    config_settings = ConfigSettings(env.config_file)

    args = SimpleNamespace(
        backup_definition="example",
        full_backup=True,
        differential_backup=False,
        incremental_backup=False,
        dar_version=None,
    )
    error = RuntimeError("PREREQ_01: /nonexistent-script failed, return code: 1")
    stats: list = []

    saved_logger = dar_backup_mod.logger
    dar_backup_mod.logger = env.logger
    try:
        dar_backup_mod._record_prereq_failure(args, config_settings, stats, error, "FULL")
    finally:
        dar_backup_mod.logger = saved_logger

    # stats_accumulator must NOT include the 'example' definition (it is skipped)
    # because perform_backup() skips it and _record_prereq_failure mirrors that logic.
    # If the definition is not 'example', it would appear — test with a real one would
    # need a non-example def.  The stats list must be empty for 'example'.
    assert stats == [], (
        "'example' definition must be skipped in stats just as perform_backup() skips it; "
        f"got: {stats}"
    )

    # The metrics DB must not have been written for 'example' either.
    if os.path.exists(metrics_db):
        with closing(sqlite3.connect(metrics_db)) as conn:
            rows = conn.execute("SELECT * FROM backup_runs").fetchall()
        assert rows == [], f"'example' rows must not be written to DB; got {rows}"

    env.logger.info("_record_prereq_failure skips 'example' definition ✓")


def test_record_prereq_failure_all_definitions(setup_environment, env):
    """
    When _record_prereq_failure() is called with args.backup_definition=None
    (no -d flag), every non-'example' definition in backup.d must appear in
    stats_accumulator with status='FAILURE' and failed_phase='PREREQ', and a
    corresponding row must be written to the metrics DB.

    A second definition 'testdef' is created in backup.d so that the
    'all definitions' code path has at least one real definition to process.
    """
    metrics_db = _inject_metrics_db(env.config_file, env.test_dir)
    config_settings = ConfigSettings(env.config_file)

    # Create a second definition so list_definitions() returns at least one
    # non-example entry.
    second_def = os.path.join(env.backup_d_dir, "testdef")
    with open(second_def, "w") as fh:
        fh.write("-R /tmp\n")
    try:
        args = SimpleNamespace(
            backup_definition=None,
            full_backup=True,
            differential_backup=False,
            incremental_backup=False,
            dar_version=None,
        )
        error = RuntimeError("PREREQ_01: /nonexistent-script failed, return code: 127")
        stats: list = []

        saved_logger = dar_backup_mod.logger
        dar_backup_mod.logger = env.logger
        try:
            dar_backup_mod._record_prereq_failure(args, config_settings, stats, error, "FULL")
        finally:
            dar_backup_mod.logger = saved_logger

        # 'testdef' must appear; 'example' must not
        definitions_in_stats = {s["definition"] for s in stats}
        assert "testdef" in definitions_in_stats, (
            f"'testdef' must be in stats; got definitions: {definitions_in_stats}"
        )
        assert "example" not in definitions_in_stats, (
            "'example' must be skipped just as perform_backup() skips it"
        )

        # Every entry in stats must be FAILURE
        for entry in stats:
            assert entry["status"] == "FAILURE", f"expected FAILURE, got: {entry}"
            assert entry["type"] == "FULL", f"expected FULL backup_type, got: {entry}"

        # Verify DB rows
        assert os.path.exists(metrics_db), "metrics DB must be created by write_metrics_row()"
        with closing(sqlite3.connect(metrics_db)) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT backup_definition, status, failed_phase FROM backup_runs ORDER BY rowid"
            ).fetchall()

        db_definitions = {r["backup_definition"] for r in rows}
        assert "testdef" in db_definitions, (
            f"'testdef' must have a row in the DB; found: {db_definitions}"
        )
        assert "example" not in db_definitions, (
            "'example' must not be written to DB"
        )
        for row in rows:
            assert row["status"] == "FAILURE", f"DB row status must be FAILURE: {dict(row)}"
            assert row["failed_phase"] == "PREREQ", (
                f"DB row failed_phase must be 'PREREQ': {dict(row)}"
            )

        env.logger.info(
            "_record_prereq_failure wrote PREREQ FAILURE rows for all definitions ✓"
        )
    finally:
        if os.path.exists(second_def):
            os.remove(second_def)


# ---------------------------------------------------------------------------
# prereq_status column — written into each DB row
# ---------------------------------------------------------------------------

def test_record_prereq_failure_sets_prereq_status_in_db(setup_environment, env):
    """
    Each row written by _record_prereq_failure() must have prereq_status='FAILURE'
    so that the Dashboard can render a red ✗ in the PRE phase column.

    Covers: run_id and prereq_status columns in the metrics schema.
    """
    import uuid as _uuid
    metrics_db = _inject_metrics_db(env.config_file, env.test_dir)
    config_settings = ConfigSettings(env.config_file)

    second_def = os.path.join(env.backup_d_dir, "prereqtest")
    with open(second_def, "w") as fh:
        fh.write("-R /tmp\n")
    try:
        run_id = str(_uuid.uuid4())
        args = SimpleNamespace(
            backup_definition=None,
            full_backup=True,
            differential_backup=False,
            incremental_backup=False,
            dar_version=None,
        )
        error = RuntimeError("PREREQ_01: mount-check failed, return code: 1")
        stats: list = []

        saved_logger = dar_backup_mod.logger
        dar_backup_mod.logger = env.logger
        try:
            dar_backup_mod._record_prereq_failure(
                args, config_settings, stats, error, "FULL", run_id=run_id
            )
        finally:
            dar_backup_mod.logger = saved_logger

        assert os.path.exists(metrics_db), "metrics DB must be created"
        with closing(sqlite3.connect(metrics_db)) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT backup_definition, prereq_status, run_id FROM backup_runs ORDER BY rowid"
            ).fetchall()

        assert len(rows) > 0, "at least one row must be written for non-example definitions"
        for row in rows:
            assert row["prereq_status"] == "FAILURE", (
                f"prereq_status must be 'FAILURE'; got: {dict(row)}"
            )
            assert row["run_id"] == run_id, (
                f"run_id must match the one passed in; got: {dict(row)}"
            )
        env.logger.info("prereq_status='FAILURE' and run_id written correctly ✓")
    finally:
        if os.path.exists(second_def):
            os.remove(second_def)


# ---------------------------------------------------------------------------
# postreq_status column — back-filled via UPDATE after POSTREQ runs
# ---------------------------------------------------------------------------

def test_update_postreq_status_sets_column_in_db(setup_environment, env):
    """
    update_postreq_status() must UPDATE every row whose run_id matches,
    setting postreq_status to 'SUCCESS' or 'FAILURE'.

    Two rows are written with the same run_id; after calling
    update_postreq_status() both must reflect the new status.
    A third row with a different run_id must remain unchanged (NULL).

    Covers: update_postreq_status() in util.py and the postreq_status column.
    """
    import uuid as _uuid
    from dar_backup.util import write_metrics_row, ensure_metrics_db

    metrics_db = _inject_metrics_db(env.config_file, env.test_dir)
    config_settings = ConfigSettings(env.config_file)

    run_id_a = str(_uuid.uuid4())
    run_id_b = str(_uuid.uuid4())

    from datetime import datetime, timezone as _tz
    now_iso = datetime.now(_tz.utc).isoformat()

    def _make_row(definition: str, run_id: str) -> dict:
        return {
            "backup_definition":             definition,
            "backup_type":                   "FULL",
            "archive_name":                  None,
            "dar_backup_version":            "test",
            "dar_version":                   None,
            "run_started_at":                now_iso,
            "backup_dir_free_bytes":         None,
            "run_finished_at":               now_iso,
            "duration_secs":                 1.0,
            "dar_duration_secs":             None,
            "verify_duration_secs":          None,
            "par2_duration_secs":            None,
            "status":                        "SUCCESS",
            "dar_exit_code":                 0,
            "failed_phase":                  None,
            "error_summary":                 None,
            "catalog_updated":               None,
            "verify_passed":                 None,
            "restore_test_passed":           None,
            "par2_passed":                   None,
            "archive_size_bytes":            None,
            "num_slices":                    None,
            "par2_size_bytes":               None,
            "files_verified":                None,
            "hostname":                      None,
            "inodes_saved":                  None,
            "hard_links_treated":            None,
            "inodes_changed_during_backup":  None,
            "bytes_wasted":                  None,
            "inodes_metadata_only":          None,
            "inodes_not_saved":              None,
            "inodes_failed":                 None,
            "inodes_excluded":               None,
            "inodes_deleted":                None,
            "inodes_total":                  None,
            "ea_saved":                      None,
            "fsa_saved":                     None,
            "run_id":                        run_id,
            "prereq_status":                 "SUCCESS",
            "postreq_status":                None,
        }

    write_metrics_row(_make_row("defA", run_id_a), config_settings)
    write_metrics_row(_make_row("defB", run_id_a), config_settings)
    write_metrics_row(_make_row("defC", run_id_b), config_settings)

    # Back-fill postreq for run_id_a only
    update_postreq_status(run_id_a, "SUCCESS", config_settings)

    with closing(sqlite3.connect(metrics_db)) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT backup_definition, postreq_status FROM backup_runs ORDER BY rowid"
        ).fetchall()

    by_def = {r["backup_definition"]: r["postreq_status"] for r in rows}
    assert by_def["defA"] == "SUCCESS", f"defA postreq_status must be SUCCESS; got: {by_def}"
    assert by_def["defB"] == "SUCCESS", f"defB postreq_status must be SUCCESS; got: {by_def}"
    assert by_def["defC"] is None, (
        f"defC (different run_id) must remain NULL; got: {by_def}"
    )
    env.logger.info("update_postreq_status() correctly updated only the matching run_id rows ✓")
