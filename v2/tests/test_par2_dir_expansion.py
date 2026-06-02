# SPDX-License-Identifier: GPL-3.0-or-later
"""
Integration tests: PAR2_DIR path expansion (tilde and environment variables).

Finding #10 — test_tilde_in_config_file and test_env_vars_in_config_file cover
BACKUP_DIR and LOGFILE_LOCATION but not PAR2_DIR.  The global PAR2_DIR is
expanded by the ConfigSettings field-expansion loop; the per-definition PAR2_DIR
is expanded inside generate_par2_files() (via os.path.expanduser/expandvars at
runtime).  Neither path is exercised by an integration test that verifies par2
files actually land in the expanded directory.

These tests verify:

  A. Global PAR2_DIR with tilde (~) — par2 files land in the expanded path.
  B. Global PAR2_DIR with an environment variable ($VAR/par2) — par2 files
     land in the expanded path.
  C. Per-definition PAR2_DIR with tilde — definition-specific par2 files
     land in the per-def expanded directory.
  D. Undefined environment variable in PAR2_DIR — backup exits non-zero or
     writes par2 files to the backup_dir fallback; it must not crash with
     an unhandled exception.

All tests run a real dar-backup --full-backup and inspect the filesystem.

Marks: integration, slow
"""

import os
import sys
from configparser import ConfigParser
from pathlib import Path

import pytest

pytestmark = [pytest.mark.integration, pytest.mark.slow]

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from dar_backup.command_runner import CommandRunner
from tests.envdata import EnvData


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_BACKUP_DEF = "par2dir-expand"


def _write_backup_def(env: EnvData) -> None:
    def_path = os.path.join(env.backup_d_dir, _BACKUP_DEF)
    Path(def_path).write_text(
        "-R /\n-s 10G\n-z6\n-am\n--cache-directory-tagging\n"
        f"-g {env.data_dir.lstrip('/')}\n"
    )
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
    result = runner.run(
        ["manager", "--create-db", "--config-file", env.config_file, "--log-stdout"],
        timeout=30,
    )
    if result.returncode != 0:
        raise RuntimeError(f"manager --create-db failed: {result.stderr}")


def _set_global_par2_dir(env: EnvData, par2_dir_value: str) -> None:
    """Set PAR2_DIR in the [PAR2] section (unexpanded — value as written in config)."""
    config = ConfigParser()
    config.read(env.config_file)
    if "PAR2" not in config:
        config["PAR2"] = {}
    config["PAR2"]["ENABLED"] = "True"
    config["PAR2"]["ERROR_CORRECTION_PERCENT"] = "5"
    config["PAR2"]["PAR2_DIR"] = par2_dir_value
    with open(env.config_file, "w") as fh:
        config.write(fh)


def _set_per_def_par2_dir(env: EnvData, definition: str, par2_dir_value: str) -> None:
    """Set PAR2_DIR in a per-definition section."""
    config = ConfigParser()
    config.read(env.config_file)
    if "PAR2" not in config:
        config["PAR2"] = {}
    config["PAR2"]["ENABLED"] = "True"
    config["PAR2"]["ERROR_CORRECTION_PERCENT"] = "5"
    if definition not in config:
        config[definition] = {}
    config[definition]["PAR2_DIR"] = par2_dir_value
    with open(env.config_file, "w") as fh:
        config.write(fh)


def _run_full_backup(env: EnvData, definition: str = _BACKUP_DEF) -> tuple:
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
    result = runner.run(
        [
            "dar-backup", "--full-backup",
            "-d", definition,
            "--log-stdout", "--log-level", "debug",
            "--config-file", env.config_file,
        ],
        timeout=300,
    )
    return result.returncode, (result.stdout or "") + (result.stderr or "")


def _par2_files_in(directory: str, definition: str) -> list:
    """Return all .par2 files in directory that match the definition name."""
    if not os.path.isdir(directory):
        return []
    return [
        f for f in os.listdir(directory)
        if f.startswith(definition) and f.endswith(".par2")
    ]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_global_par2_dir_tilde_expansion(
    setup_environment, env: EnvData
) -> None:
    """
    PAR2_DIR = ~/par2-tilde-test must expand to a real path under $HOME
    and par2 files must be written there, not in BACKUP_DIR.
    """
    # Use a subdirectory of the test temp tree so we don't litter $HOME
    # We fake HOME to point at our test_dir so ~ expands safely.
    fake_home = env.test_dir
    par2_subdir = os.path.join(fake_home, "par2-tilde-test")

    _write_backup_def(env)
    _set_global_par2_dir(env, "~/par2-tilde-test")

    # Temporarily override HOME so ~ expands to our test_dir
    original_home = os.environ.get("HOME")
    os.environ["HOME"] = fake_home
    try:
        rc, output = _run_full_backup(env)
    finally:
        if original_home is None:
            os.environ.pop("HOME", None)
        else:
            os.environ["HOME"] = original_home

    assert rc == 0, f"dar-backup failed (rc={rc}):\n{output}"

    par2_files = _par2_files_in(par2_subdir, _BACKUP_DEF)
    env.logger.info("par2 files in %s: %s", par2_subdir, par2_files)
    assert par2_files, (
        f"No par2 files found in expanded tilde directory {par2_subdir!r}. "
        f"Contents of backup_dir: {os.listdir(env.backup_dir)}"
    )


def test_global_par2_dir_env_var_expansion(
    setup_environment, env: EnvData
) -> None:
    """
    PAR2_DIR = $DAR_TEST_PAR2_DIR must expand at runtime and par2 files
    must be written to the directory named by that variable.
    """
    par2_target = os.path.join(env.test_dir, "par2-envvar-target")
    os.makedirs(par2_target, exist_ok=True)

    _write_backup_def(env)
    _set_global_par2_dir(env, "$DAR_TEST_PAR2_DIR")

    os.environ["DAR_TEST_PAR2_DIR"] = par2_target
    try:
        rc, output = _run_full_backup(env)
    finally:
        os.environ.pop("DAR_TEST_PAR2_DIR", None)

    assert rc == 0, f"dar-backup failed (rc={rc}):\n{output}"

    par2_files = _par2_files_in(par2_target, _BACKUP_DEF)
    env.logger.info("par2 files in %s: %s", par2_target, par2_files)
    assert par2_files, (
        f"No par2 files found in env-var-expanded directory {par2_target!r}. "
        f"Contents of backup_dir: {os.listdir(env.backup_dir)}"
    )


def test_per_definition_par2_dir_tilde_expansion(
    setup_environment, env: EnvData
) -> None:
    """
    A per-definition PAR2_DIR containing ~ must also be expanded and par2
    files must land in that directory.
    """
    fake_home = env.test_dir
    par2_subdir = os.path.join(fake_home, "par2-perdef-tilde")

    _write_backup_def(env)
    _set_per_def_par2_dir(env, _BACKUP_DEF, "~/par2-perdef-tilde")

    original_home = os.environ.get("HOME")
    os.environ["HOME"] = fake_home
    try:
        rc, output = _run_full_backup(env)
    finally:
        if original_home is None:
            os.environ.pop("HOME", None)
        else:
            os.environ["HOME"] = original_home

    assert rc == 0, f"dar-backup failed (rc={rc}):\n{output}"

    par2_files = _par2_files_in(par2_subdir, _BACKUP_DEF)
    env.logger.info("per-def par2 files in %s: %s", par2_subdir, par2_files)
    assert par2_files, (
        f"No par2 files found in per-definition tilde-expanded dir {par2_subdir!r}. "
        f"Contents of backup_dir: {os.listdir(env.backup_dir)}"
    )


def test_undefined_env_var_in_par2_dir_does_not_raise_unhandled_exception(
    setup_environment, env: EnvData
) -> None:
    """
    Setting PAR2_DIR to a path containing an undefined environment variable
    (e.g. $DEFINITELY_UNSET_VAR_XYZ/par2) must not produce an unhandled Python
    exception (no 'Traceback' in output).

    Acceptable outcomes:
      - dar-backup exits 0 and writes par2 files somewhere (backup_dir
        fallback or the literal unexpanded path if the OS allows it).
      - dar-backup exits non-zero with a clear error message.

    In both cases a Python traceback is a bug.
    """
    _write_backup_def(env)
    _set_global_par2_dir(env, "$DEFINITELY_UNSET_VAR_XYZ_DAR_BACKUP/par2")

    # Guarantee the variable is not set
    os.environ.pop("DEFINITELY_UNSET_VAR_XYZ_DAR_BACKUP", None)

    rc, output = _run_full_backup(env)

    env.logger.info("rc=%d for undefined env-var PAR2_DIR", rc)

    assert "Traceback" not in output, (
        "Unhandled Python exception when PAR2_DIR contains undefined env var:\n"
        + output[:3000]
    )
    # rc may be 0 (fallback) or non-zero (graceful error) — both are acceptable
    env.logger.info(
        "Undefined env-var in PAR2_DIR handled gracefully (rc=%d, no traceback)", rc
    )
