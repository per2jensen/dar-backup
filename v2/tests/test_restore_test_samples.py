#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""
Unit tests for restore_test_samples metrics DB support.

Covers:
- ensure_metrics_db creates both new tables and seeds fail_reasons
- write_restore_test_samples writes PASS / FAIL / SKIP rows correctly
- write_restore_test_samples is a no-op when metrics_db_path is absent or samples is empty
- _parse_size_bytes parses dar size strings to bytes
"""

import os
import sqlite3
import sys
from contextlib import closing
from types import SimpleNamespace

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from dar_backup.util import (
    ensure_metrics_db,
    write_restore_test_samples,
    RESTORE_FAIL_CONTENT_MISMATCH,
    RESTORE_FAIL_METADATA_MISMATCH,
    RESTORE_FAIL_SOURCE_MISSING,
    RESTORE_FAIL_RESTORED_MISSING,
    RESTORE_FAIL_PERMISSION_ERROR,
    RESTORE_FAIL_UNKNOWN_ERROR,
)
from dar_backup.dar_backup import _parse_size_bytes, _size_in_verification_range

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _db(tmp_path) -> str:
    """Return a fresh metrics DB path under tmp_path."""
    path = str(tmp_path / "metrics.db")
    ensure_metrics_db(path)
    return path


def _config(db_path: str):
    return SimpleNamespace(metrics_db_path=db_path)


def _sample(result: str = "PASS", fail_reason_id=None, fail_detail=None) -> dict:
    return {
        "file_path":       "/some/file.txt",
        "file_size_bytes": 1024,
        "result":          result,
        "fail_reason_id":  fail_reason_id,
        "fail_detail":     fail_detail,
        "tested_at":       "2026-05-26T12:00:00+00:00",
    }


# ---------------------------------------------------------------------------
# Schema tests
# ---------------------------------------------------------------------------

def test_ensure_metrics_db_creates_restore_test_tables(tmp_path):
    """Both new tables must exist after ensure_metrics_db."""
    db_path = _db(tmp_path)
    with closing(sqlite3.connect(db_path)) as conn:
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert "restore_test_fail_reasons" in tables
    assert "restore_test_samples" in tables


def test_ensure_metrics_db_seeds_all_fail_reasons(tmp_path):
    """All six fail reason rows must be present with correct codes."""
    db_path = _db(tmp_path)
    with closing(sqlite3.connect(db_path)) as conn:
        rows = {r[0]: r[1] for r in conn.execute("SELECT id, code FROM restore_test_fail_reasons")}
    assert rows[RESTORE_FAIL_CONTENT_MISMATCH] == "CONTENT_MISMATCH"
    assert rows[RESTORE_FAIL_METADATA_MISMATCH] == "METADATA_MISMATCH"
    assert rows[RESTORE_FAIL_SOURCE_MISSING]    == "SOURCE_MISSING"
    assert rows[RESTORE_FAIL_RESTORED_MISSING]  == "RESTORED_MISSING"
    assert rows[RESTORE_FAIL_PERMISSION_ERROR]  == "PERMISSION_ERROR"
    assert rows[RESTORE_FAIL_UNKNOWN_ERROR]     == "UNKNOWN_ERROR"
    assert len(rows) == 6


def test_ensure_metrics_db_seeds_are_idempotent(tmp_path):
    """Calling ensure_metrics_db twice must not duplicate seed rows."""
    db_path = _db(tmp_path)
    ensure_metrics_db(db_path)  # second call
    with closing(sqlite3.connect(db_path)) as conn:
        count = conn.execute("SELECT COUNT(*) FROM restore_test_fail_reasons").fetchone()[0]
    assert count == 6


# ---------------------------------------------------------------------------
# write_restore_test_samples tests
# ---------------------------------------------------------------------------

def test_write_restore_test_samples_pass_row(tmp_path):
    """A PASS sample is written with null fail_reason_id and fail_detail."""
    db_path = _db(tmp_path)
    write_restore_test_samples("run-1", "mydef", "mydef_FULL_2026-05-26", [_sample()], _config(db_path))

    with closing(sqlite3.connect(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT * FROM restore_test_samples").fetchall()

    assert len(rows) == 1
    row = dict(rows[0])
    assert row["run_id"]           == "run-1"
    assert row["backup_definition"] == "mydef"
    assert row["archive_name"]     == "mydef_FULL_2026-05-26"
    assert row["file_path"]        == "/some/file.txt"
    assert row["file_size_bytes"]  == 1024
    assert row["result"]           == "PASS"
    assert row["fail_reason_id"]   is None
    assert row["fail_detail"]      is None


def test_write_restore_test_samples_fail_content_mismatch(tmp_path):
    """A FAIL/CONTENT_MISMATCH sample is written with the correct reason id."""
    db_path = _db(tmp_path)
    s = _sample("FAIL", RESTORE_FAIL_CONTENT_MISMATCH)
    write_restore_test_samples("run-2", "mydef", "mydef_FULL_2026-05-26", [s], _config(db_path))

    with closing(sqlite3.connect(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        row = dict(conn.execute("SELECT * FROM restore_test_samples").fetchone())

    assert row["result"]          == "FAIL"
    assert row["fail_reason_id"]  == RESTORE_FAIL_CONTENT_MISMATCH
    assert row["fail_detail"]     is None


def test_write_restore_test_samples_fail_metadata_mismatch_with_detail(tmp_path):
    """A FAIL/METADATA_MISMATCH sample preserves the fail_detail string."""
    db_path = _db(tmp_path)
    detail = "permission mismatch: source=0o100644 restored=0o100600"
    s = _sample("FAIL", RESTORE_FAIL_METADATA_MISMATCH, detail)
    write_restore_test_samples("run-3", "mydef", "mydef_FULL_2026-05-26", [s], _config(db_path))

    with closing(sqlite3.connect(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        row = dict(conn.execute("SELECT * FROM restore_test_samples").fetchone())

    assert row["result"]         == "FAIL"
    assert row["fail_reason_id"] == RESTORE_FAIL_METADATA_MISMATCH
    assert row["fail_detail"]    == detail


def test_write_restore_test_samples_skip_source_missing(tmp_path):
    """A SKIP/SOURCE_MISSING sample is written correctly."""
    db_path = _db(tmp_path)
    s = _sample("SKIP", RESTORE_FAIL_SOURCE_MISSING)
    write_restore_test_samples("run-4", "mydef", "mydef_FULL_2026-05-26", [s], _config(db_path))

    with closing(sqlite3.connect(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        row = dict(conn.execute("SELECT * FROM restore_test_samples").fetchone())

    assert row["result"]         == "SKIP"
    assert row["fail_reason_id"] == RESTORE_FAIL_SOURCE_MISSING


def test_write_restore_test_samples_multiple_rows_one_commit(tmp_path):
    """Multiple samples are written in one call and all appear in the DB."""
    db_path = _db(tmp_path)
    samples = [
        {**_sample("PASS"),  "file_path": "/a.txt"},
        {**_sample("FAIL", RESTORE_FAIL_CONTENT_MISMATCH), "file_path": "/b.txt"},
        {**_sample("SKIP", RESTORE_FAIL_RESTORED_MISSING), "file_path": "/c.txt"},
    ]
    write_restore_test_samples("run-5", "mydef", "mydef_FULL_2026-05-26", samples, _config(db_path))

    with closing(sqlite3.connect(db_path)) as conn:
        rows = conn.execute(
            "SELECT file_path, result FROM restore_test_samples ORDER BY file_path"
        ).fetchall()

    assert rows == [("/a.txt", "PASS"), ("/b.txt", "FAIL"), ("/c.txt", "SKIP")]


def test_write_restore_test_samples_noop_when_no_db_path(tmp_path):
    """No DB file is created when metrics_db_path is absent from config."""
    db_path = str(tmp_path / "should_not_exist.db")
    write_restore_test_samples("run-x", "d", "d_FULL_2026-05-26", [_sample()], SimpleNamespace())
    assert not os.path.exists(db_path)


def test_write_restore_test_samples_noop_when_samples_empty(tmp_path):
    """No rows are inserted and no error is raised when samples list is empty."""
    db_path = _db(tmp_path)
    write_restore_test_samples("run-x", "d", "d_FULL_2026-05-26", [], _config(db_path))

    with closing(sqlite3.connect(db_path)) as conn:
        count = conn.execute("SELECT COUNT(*) FROM restore_test_samples").fetchone()[0]
    assert count == 0


# ---------------------------------------------------------------------------
# _parse_size_bytes tests
# ---------------------------------------------------------------------------

def test_parse_size_bytes_mio(tmp_path):
    assert _parse_size_bytes("10 Mio") == 10 * 1024 * 1024


def test_parse_size_bytes_kio(tmp_path):
    assert _parse_size_bytes("512 kio") == 512 * 1024


def test_parse_size_bytes_gio(tmp_path):
    assert _parse_size_bytes("2 Gio") == 2 * 1024 * 1024 * 1024


def test_parse_size_bytes_o(tmp_path):
    assert _parse_size_bytes("42 o") == 42


def test_parse_size_bytes_unknown_unit_returns_none(tmp_path):
    assert _parse_size_bytes("10 Foo") is None


def test_parse_size_bytes_empty_returns_none(tmp_path):
    assert _parse_size_bytes("") is None


def test_parse_size_bytes_none_returns_none(tmp_path):
    assert _parse_size_bytes(None) is None


# ---------------------------------------------------------------------------
# _size_in_verification_range tests
# ---------------------------------------------------------------------------

def _make_range_config(min_mb: int, max_mb: int) -> SimpleNamespace:
    return SimpleNamespace(
        min_size_verification_mb=min_mb,
        max_size_verification_mb=max_mb,
    )


def test_size_in_verification_range_within_window():
    cfg = _make_range_config(1, 100)
    assert _size_in_verification_range("10 Mio", cfg) is True


def test_size_in_verification_range_below_minimum():
    cfg = _make_range_config(10, 100)
    assert _size_in_verification_range("1 Mio", cfg) is False


def test_size_in_verification_range_above_maximum():
    cfg = _make_range_config(0, 1)
    assert _size_in_verification_range("10 Mio", cfg) is False


def test_size_in_verification_range_unparseable_returns_false():
    cfg = _make_range_config(0, 100)
    assert _size_in_verification_range("not-a-size", cfg) is False


def test_size_in_verification_range_delegates_unknown_unit_to_parse_size_bytes():
    """_size_in_verification_range() must return False for an unknown unit by
    delegating to _parse_size_bytes(), which returns None for unknown units.
    This guards against the two functions diverging when new units are added
    to _DAR_SIZE_UNITS: adding a unit there automatically covers this function
    without a second update.
    """
    cfg = _make_range_config(0, 9999)
    # "Pio" is not in _DAR_SIZE_UNITS — both functions must reject it
    assert _size_in_verification_range("1 Pio", cfg) is False
    assert _parse_size_bytes("1 Pio") is None
