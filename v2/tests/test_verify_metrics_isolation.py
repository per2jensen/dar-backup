#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""
Tests proving that metrics code inside verify() cannot break a backup.

One test per guarded site in verify():

  1. size_lookup dict comprehension
  2. sample dict initialisation (_parse_size_bytes)
  3. samples.append(sample)
  4. write_restore_test_samples() call site

Each test injects a failure at the target site and asserts that:
  - verify() returns passed=True (backup result unaffected)
  - files_verified >= 1 where a real backup is run (tests 2-4)
"""

import os
import sys
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import dar_backup.dar_backup as db
from dar_backup.dar_backup import verify
from dar_backup.command_runner import CommandRunner
from envdata import EnvData

pytestmark = [pytest.mark.integration, pytest.mark.slow]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_config(env: EnvData, no_files: int = 1) -> SimpleNamespace:
    """Return a minimal config_settings-like object for verify()."""
    return SimpleNamespace(
        test_restore_dir=env.restore_dir,
        logfile_location=env.log_file,
        command_timeout_secs=86400,
        backup_dir=env.backup_dir,
        min_size_verification_mb=0,
        max_size_verification_mb=20,
        no_files_verification=no_files,
        metrics_db_path=None,
    )


def _wire_module(env: EnvData, monkeypatch) -> None:
    """Wire the module-level runner and logger to real test objects."""
    monkeypatch.setattr(db, "runner", CommandRunner(
        logger=env.logger, command_logger=env.command_logger
    ))
    monkeypatch.setattr(db, "logger", env.logger)


# ---------------------------------------------------------------------------
# Guard 1 – size_lookup dict comprehension
# ---------------------------------------------------------------------------

def test_verify_size_lookup_failure_does_not_break_backup(
    setup_environment, env: EnvData
) -> None:
    """size_lookup guard: a hash failure during dict-comprehension must not propagate.

    Monkeypatching required: iterating a plain Python list in a dict comprehension
    cannot fail in CPython; _ExplodingHashStr simulates a hypothetical key-hashing
    failure (e.g. a future bug in a custom __hash__).
    The runner is stubbed to returncode=0 so dar -t passes without a real archive.
    select_restoretest_samples is stubbed to [] so verify() returns via the
    early-exit path — sufficient to confirm the guard fires without aborting.
    """
    class _ExplodingHashStr(str):
        def __hash__(self):
            raise RuntimeError("Simulated hash failure in size_lookup")

    mock_runner = MagicMock()
    mock_runner.run.return_value.returncode = 0

    args = SimpleNamespace(verbose=False, do_not_compare=False, darrc=env.dar_rc)

    with patch("dar_backup.dar_backup.runner", mock_runner), \
         patch("dar_backup.dar_backup.get_backed_up_files",
               return_value=[(_ExplodingHashStr("some/file.txt"), "1 kio")]), \
         patch("dar_backup.dar_backup.select_restoretest_samples", return_value=[]), \
         patch("dar_backup.dar_backup.logger"):
        result = verify(args, "mock-archive", "mock-definition", _make_config(env))

    assert result.passed is True, (
        "backup result must be unaffected by a size_lookup dict-comprehension failure"
    )


# ---------------------------------------------------------------------------
# Guard 2 – sample dict initialisation (_parse_size_bytes)
# ---------------------------------------------------------------------------

def test_verify_parse_size_bytes_failure_does_not_break_backup(
    setup_environment, env: EnvData, monkeypatch
) -> None:
    """sample-init guard: _parse_size_bytes raising must not abort verify().

    Monkeypatching required: _parse_size_bytes handles all valid and invalid
    inputs gracefully and never raises; raising unconditionally here simulates
    a hypothetical internal failure that cannot be triggered by normal input.
    A real backup and dar restore confirm files_verified > 0 despite the error.
    """
    from testdata_verification import run_backup_script

    run_backup_script("--full-backup", env)
    archive = f"example_FULL_{env.datestamp}"
    backup_file = os.path.join(env.backup_dir, archive)
    backup_definition = os.path.join(env.backup_d_dir, "example")

    def _always_raise(*a, **kw):
        raise RuntimeError("Simulated _parse_size_bytes failure")

    monkeypatch.setattr(db, "_parse_size_bytes", _always_raise)
    _wire_module(env, monkeypatch)

    args = SimpleNamespace(verbose=False, do_not_compare=False, darrc=env.dar_rc)

    result = verify(args, backup_file, backup_definition, _make_config(env))

    assert result.passed is True, (
        "backup result must be unaffected by a _parse_size_bytes failure"
    )
    assert result.files_verified >= 1, (
        "verification must still run despite the metrics sample-init failure"
    )


# ---------------------------------------------------------------------------
# Guard 3 – samples.append(sample)
# ---------------------------------------------------------------------------

def test_verify_samples_append_guard_does_not_drop_samples(
    setup_environment, env: EnvData, monkeypatch
) -> None:
    """samples.append guard: the try/except must not silently discard samples.

    list.append cannot raise in CPython — this test proves the guard is inert
    on the normal path: the number of samples passed to write_restore_test_samples
    must equal files_verified, confirming no sample is lost.
    write_restore_test_samples is replaced with a real capture function (not a
    Mock) so the assertion is on the actual samples list produced by verify().
    """
    from testdata_verification import run_backup_script

    run_backup_script("--full-backup", env)
    archive = f"example_FULL_{env.datestamp}"
    backup_file = os.path.join(env.backup_dir, archive)
    backup_definition = os.path.join(env.backup_d_dir, "example")

    captured: dict = {}

    def _capture(run_id, backup_definition, archive_name, samples, config_settings):
        captured["samples"] = samples

    monkeypatch.setattr(db, "write_restore_test_samples", _capture)
    _wire_module(env, monkeypatch)

    args = SimpleNamespace(verbose=False, do_not_compare=False, darrc=env.dar_rc)

    result = verify(
        args, backup_file, backup_definition, _make_config(env), run_id="test-guard3"
    )

    assert result.passed is True
    assert result.files_verified >= 1
    assert "samples" in captured, "write_restore_test_samples was not called"
    assert len(captured["samples"]) == result.files_verified, (
        "guard 3 must not drop any samples: "
        f"captured {len(captured['samples'])} but files_verified={result.files_verified}"
    )


# ---------------------------------------------------------------------------
# Guard 4 – write_restore_test_samples() call site
# ---------------------------------------------------------------------------

def test_verify_write_restore_test_samples_failure_does_not_break_backup(
    setup_environment, env: EnvData, monkeypatch
) -> None:
    """write_restore_test_samples call-site guard: a DB write failure must not abort verify().

    write_restore_test_samples already catches its own exceptions internally;
    monkeypatching it to raise unconditionally exercises the outer call-site
    guard in verify() itself — the belt-and-suspenders layer.
    A real backup confirms files_verified > 0 so the full verify() path is taken.
    """
    from testdata_verification import run_backup_script

    run_backup_script("--full-backup", env)
    archive = f"example_FULL_{env.datestamp}"
    backup_file = os.path.join(env.backup_dir, archive)
    backup_definition = os.path.join(env.backup_d_dir, "example")

    def _always_raise(*a, **kw):
        raise RuntimeError("Simulated write_restore_test_samples failure")

    monkeypatch.setattr(db, "write_restore_test_samples", _always_raise)
    _wire_module(env, monkeypatch)

    args = SimpleNamespace(verbose=False, do_not_compare=False, darrc=env.dar_rc)

    result = verify(
        args, backup_file, backup_definition, _make_config(env), run_id="test-guard4"
    )

    assert result.passed is True, (
        "backup result must be unaffected by a write_restore_test_samples failure"
    )
    assert result.files_verified >= 1, (
        "verification must still complete despite the DB write failure"
    )
