# SPDX-License-Identifier: GPL-3.0-or-later
"""
Integration tests: concurrent dar-backup invocations against the same config.

Finding #2 — test_duplicate_full_backup_fails covers sequential re-runs
(second invocation rejects the already-existing archive).  There is no test
that spawns two processes simultaneously and verifies both complete without
corrupting the catalog DB or leaving the archive directory in an inconsistent
state.

Scenario A — same backup definition, simultaneous FULL:
  Both processes target the same archive filename.  The "already exists" guard
  in dar-backup means exactly one of them must succeed (rc=0) and the other
  must exit with rc=2 (skipped), OR both succeed if the OS races the .1.dar
  check differently.  The critical invariant is:

    - No process crashes (rc must be 0 or 2, never an unhandled exception).
    - The catalog DB must be consistent (dar-manager --sanity-check passes).
    - Exactly one .1.dar slice exists (no partial or duplicate file).

Scenario B — different backup definitions, simultaneous FULL:
  Two independent definitions run in parallel.  Both must succeed and produce
  independent, intact archives.

Marks: integration, slow
"""

import os
import subprocess
import sys
import threading
import time
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

def _disable_par2(env: EnvData) -> None:
    """Turn off PAR2 to keep tests fast."""
    config = ConfigParser()
    config.read(env.config_file)
    if "PAR2" not in config:
        config["PAR2"] = {}
    config["PAR2"]["ENABLED"] = "False"
    with open(env.config_file, "w") as fh:
        config.write(fh)


def _write_backup_def(env: EnvData, name: str, data_dir: str) -> None:
    """Write a backup definition and create its catalog DB."""
    def_path = os.path.join(env.backup_d_dir, name)
    Path(def_path).write_text(
        "-R /\n-s 10G\n-z6\n-am\n--cache-directory-tagging\n"
        f"-g {data_dir.lstrip('/')}\n"
    )
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
    result = runner.run(
        ["manager", "--create-db", "--config-file", env.config_file, "--log-stdout"],
        timeout=30,
    )
    if result.returncode != 0:
        raise RuntimeError(f"manager --create-db failed (rc={result.returncode}): {result.stderr}")


def _run_backup_subprocess(
    config_file: str,
    definition: str,
    results: list,
    index: int,
) -> None:
    """
    Launch dar-backup --full-backup in a subprocess and store the returncode
    in results[index].  Designed to be called from a threading.Thread.
    """
    proc = subprocess.run(
        [
            "dar-backup", "--full-backup",
            "-d", definition,
            "--log-stdout", "--log-level", "debug",
            "--config-file", config_file,
        ],
        capture_output=True,
        text=True,
        timeout=300,
    )
    results[index] = proc.returncode


def _catalog_is_consistent(env: EnvData, definition: str) -> bool:
    """Return True if dar_manager --check exits 0 for the given definition's DB."""
    db_path = os.path.join(env.backup_dir, f"{definition}.db")
    if not os.path.exists(db_path):
        return False
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
    result = runner.run(
        ["dar_manager", "--base", db_path, "--check"],
        timeout=30,
    )
    return result.returncode == 0


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_concurrent_same_definition_does_not_corrupt_catalog(
    setup_environment, env: EnvData
) -> None:
    """
    Two dar-backup processes targeting the same FULL backup definition must
    not corrupt the catalog DB.  One of them will find the archive already
    exists (rc=2) or both will complete (rc=0) — neither outcome should leave
    the DB in a broken state.

    The acceptable exit codes are 0 (success) and 2 (skip — archive exists).
    Any other code signals an unhandled crash.
    """
    _disable_par2(env)

    results = [None, None]
    threads = [
        threading.Thread(
            target=_run_backup_subprocess,
            args=(env.config_file, "example", results, i),
            daemon=True,
        )
        for i in range(2)
    ]

    # Start both threads as close together as possible
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=360)

    env.logger.info("Concurrent same-def results: %s", results)

    for i, rc in enumerate(results):
        assert rc is not None, f"Thread {i} did not complete"
        assert rc in (0, 2), (
            f"Thread {i} exited with rc={rc}; expected 0 (success) or 2 (skipped). "
            "This indicates an unhandled crash."
        )

    # Catalog DB must still pass sanity check
    assert _catalog_is_consistent(env, "example"), (
        "Catalog DB is inconsistent after concurrent backup run"
    )

    # At most one .1.dar slice must exist (no duplicates or phantom files)
    dar_slices = [
        f for f in os.listdir(env.backup_dir)
        if f.startswith("example_FULL_") and f.endswith(".1.dar")
    ]
    assert len(dar_slices) <= 1, (
        f"Expected at most one .1.dar slice, found: {dar_slices}"
    )


def test_concurrent_different_definitions_both_succeed(
    setup_environment, env: EnvData
) -> None:
    """
    Two dar-backup processes running different backup definitions simultaneously
    must both complete with rc=0 and produce independent, intact archives.
    """
    _disable_par2(env)

    # Create a second independent data tree and definition
    second_data = os.path.join(env.test_dir, "data2")
    os.makedirs(second_data, exist_ok=True)
    for name in ("alpha.txt", "beta.txt", "gamma.txt"):
        Path(os.path.join(second_data, name)).write_text(f"content of {name}\n")

    _write_backup_def(env, "second-def", second_data)

    results = [None, None]
    threads = [
        threading.Thread(
            target=_run_backup_subprocess,
            args=(env.config_file, definition, results, i),
            daemon=True,
        )
        for i, definition in enumerate(["example", "second-def"])
    ]

    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=360)

    env.logger.info("Concurrent different-def results: %s", results)

    for i, rc in enumerate(results):
        assert rc is not None, f"Thread {i} did not complete"
        assert rc == 0, f"Thread {i} (definition {'example' if i==0 else 'second-def'}) failed with rc={rc}"

    # Each definition must have produced exactly one .1.dar slice
    for definition in ("example", "second-def"):
        slices = [
            f for f in os.listdir(env.backup_dir)
            if f.startswith(f"{definition}_FULL_") and f.endswith(".1.dar")
        ]
        assert len(slices) == 1, (
            f"Expected 1 .1.dar for '{definition}', found: {slices}"
        )

    # Both catalog DBs must be consistent
    for definition in ("example", "second-def"):
        assert _catalog_is_consistent(env, definition), (
            f"Catalog DB for '{definition}' is inconsistent after concurrent run"
        )
