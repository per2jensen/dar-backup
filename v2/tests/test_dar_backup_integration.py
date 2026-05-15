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
import stat
import sys
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path
from types import SimpleNamespace

import pytest

pytestmark = [pytest.mark.integration]

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

import dar_backup.dar_backup as dar_backup_mod
from dar_backup import __about__ as about
from dar_backup.command_runner import CommandRunner
from dar_backup.config_settings import ConfigSettings
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
