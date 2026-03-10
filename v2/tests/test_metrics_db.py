# SPDX-License-Identifier: GPL-3.0-or-later
"""
Isolated unit tests for the metrics DB infrastructure.

Covers:
  - ensure_metrics_db() — schema creation and idempotency
  - write_metrics_row() — happy path, disabled path, error resilience
  - ConfigSettings — METRICS_DB_PATH parsed / absent
"""

import sqlite3
from configparser import ConfigParser
from types import SimpleNamespace

import pytest

from dar_backup.util import ensure_metrics_db, write_metrics_row
from dar_backup.config_settings import ConfigSettings

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_FULL_METRICS = {
    "backup_definition":  "test-def",
    "backup_type":        "FULL",
    "archive_name":       "test-def_FULL_2026-03-10",
    "dar_backup_version": "1.0.0",
    "dar_version":        "2.7.5",
    "run_started_at":     "2026-03-10T10:00:00Z",
    "run_finished_at":    "2026-03-10T10:05:00Z",
    "duration_secs":      300.0,
    "dar_duration_secs":  250.0,
    "verify_duration_secs": 40.0,
    "par2_duration_secs": 10.0,
    "status":             "SUCCESS",
    "dar_exit_code":      0,
    "failed_phase":       None,
    "error_summary":      None,
    "catalog_updated":    1,
    "verify_passed":      1,
    "restore_test_passed": 1,
    "par2_passed":        1,
    "archive_size_bytes": 1048576,
    "num_slices":         1,
    "par2_size_bytes":    104857,
    "files_verified":     5,
    "backup_dir_free_bytes": 10737418240,
}

_SPARSE_METRICS = {
    "backup_definition":  "sparse-def",
    "backup_type":        "INCR",
    "archive_name":       None,
    "dar_backup_version": None,
    "dar_version":        None,
    "run_started_at":     "2026-03-10T12:00:00Z",
    "run_finished_at":    None,
    "duration_secs":      None,
    "dar_duration_secs":  None,
    "verify_duration_secs": None,
    "par2_duration_secs": None,
    "status":             "FAILURE",
    "dar_exit_code":      None,
    "failed_phase":       None,
    "error_summary":      "pre-flight failed",
    "catalog_updated":    None,
    "verify_passed":      None,
    "restore_test_passed": None,
    "par2_passed":        None,
    "archive_size_bytes": None,
    "num_slices":         None,
    "par2_size_bytes":    None,
    "files_verified":     None,
    "backup_dir_free_bytes": None,
}


def _cfg(db_path):
    """Minimal stand-in for ConfigSettings with only metrics_db_path set."""
    return SimpleNamespace(metrics_db_path=db_path)


def _write_config(path, base_dir, *, misc_overrides=None):
    config = ConfigParser()
    config["MISC"] = {
        "LOGFILE_LOCATION": str(base_dir / "dar-backup.log"),
        "MAX_SIZE_VERIFICATION_MB": "20",
        "MIN_SIZE_VERIFICATION_MB": "0",
        "NO_FILES_VERIFICATION": "5",
        "COMMAND_TIMEOUT_SECS": "30",
    }
    config["DIRECTORIES"] = {
        "BACKUP_DIR":      str(base_dir / "backups"),
        "BACKUP.D_DIR":    str(base_dir / "backup.d"),
        "TEST_RESTORE_DIR": str(base_dir / "restore"),
    }
    config["AGE"]  = {"DIFF_AGE": "30", "INCR_AGE": "15"}
    config["PAR2"] = {"ERROR_CORRECTION_PERCENT": "5", "ENABLED": "true"}
    if misc_overrides:
        config["MISC"].update(misc_overrides)
    with open(path, "w") as fh:
        config.write(fh)
    return path


# ---------------------------------------------------------------------------
# ensure_metrics_db
# ---------------------------------------------------------------------------

def test_ensure_metrics_db_creates_schema(tmp_path):
    db = str(tmp_path / "metrics.db")
    ensure_metrics_db(db)
    with sqlite3.connect(db) as conn:
        tables = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )}
    assert "backup_runs" in tables


def test_ensure_metrics_db_creates_indexes(tmp_path):
    db = str(tmp_path / "metrics.db")
    ensure_metrics_db(db)
    with sqlite3.connect(db) as conn:
        indexes = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='index'"
        )}
    assert "idx_runs_definition"    in indexes
    assert "idx_runs_status"        in indexes
    assert "idx_runs_dar_exit_code" in indexes


def test_ensure_metrics_db_is_idempotent(tmp_path):
    """Calling ensure_metrics_db twice must not raise and must leave the table empty."""
    db = str(tmp_path / "metrics.db")
    ensure_metrics_db(db)
    ensure_metrics_db(db)   # second call — must not raise
    with sqlite3.connect(db) as conn:
        count = conn.execute("SELECT count(*) FROM backup_runs").fetchone()[0]
    assert count == 0


# ---------------------------------------------------------------------------
# write_metrics_row — disabled / no-op paths
# ---------------------------------------------------------------------------

def test_write_metrics_row_noop_when_path_is_none():
    """metrics_db_path=None must silently do nothing."""
    write_metrics_row(_FULL_METRICS, _cfg(None))   # must not raise


def test_write_metrics_row_noop_when_path_is_empty_string():
    """metrics_db_path='' (falsy) must also be a silent no-op."""
    write_metrics_row(_FULL_METRICS, _cfg(""))     # must not raise


# ---------------------------------------------------------------------------
# write_metrics_row — happy path
# ---------------------------------------------------------------------------

def test_write_metrics_row_creates_db_file_if_missing(tmp_path):
    db_path = tmp_path / "metrics.db"
    assert not db_path.exists()
    write_metrics_row(_FULL_METRICS, _cfg(str(db_path)))
    assert db_path.exists()


def test_write_metrics_row_inserts_one_row(tmp_path):
    db = str(tmp_path / "metrics.db")
    write_metrics_row(_FULL_METRICS, _cfg(db))
    with sqlite3.connect(db) as conn:
        rows = conn.execute("SELECT * FROM backup_runs").fetchall()
    assert len(rows) == 1


def test_write_metrics_row_values_round_trip(tmp_path):
    db = str(tmp_path / "metrics.db")
    write_metrics_row(_FULL_METRICS, _cfg(db))
    with sqlite3.connect(db) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT * FROM backup_runs").fetchone()
    assert row["backup_definition"]  == "test-def"
    assert row["backup_type"]        == "FULL"
    assert row["status"]             == "SUCCESS"
    assert row["dar_exit_code"]      == 0
    assert row["archive_size_bytes"] == 1048576
    assert row["num_slices"]         == 1
    assert row["files_verified"]     == 5


def test_write_metrics_row_multiple_rows_accumulate(tmp_path):
    db = str(tmp_path / "metrics.db")
    cfg = _cfg(db)
    write_metrics_row(_FULL_METRICS, cfg)
    write_metrics_row({**_FULL_METRICS, "backup_type": "DIFF"}, cfg)
    write_metrics_row({**_FULL_METRICS, "backup_type": "INCR"}, cfg)
    with sqlite3.connect(db) as conn:
        count = conn.execute("SELECT count(*) FROM backup_runs").fetchone()[0]
    assert count == 3


def test_write_metrics_row_null_optional_fields(tmp_path):
    """All optional fields set to None must still insert cleanly."""
    db = str(tmp_path / "metrics.db")
    write_metrics_row(_SPARSE_METRICS, _cfg(db))
    with sqlite3.connect(db) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT * FROM backup_runs").fetchone()
    assert row["status"]        == "FAILURE"
    assert row["error_summary"] == "pre-flight failed"
    assert row["dar_exit_code"] is None
    assert row["num_slices"]    is None


# ---------------------------------------------------------------------------
# write_metrics_row — error resilience
# ---------------------------------------------------------------------------

def test_write_metrics_row_swallows_error_on_bad_path():
    """An unwritable DB path must not raise — the error is only logged."""
    write_metrics_row(_FULL_METRICS, _cfg("/no/such/directory/metrics.db"))
    # reaching here means no exception was propagated


def test_write_metrics_row_does_not_raise_on_missing_key(tmp_path):
    """A metrics dict missing optional keys must not crash the function."""
    db = str(tmp_path / "metrics.db")
    minimal = {
        "backup_definition": "x",
        "backup_type":       "FULL",
        "run_started_at":    "2026-03-10T08:00:00Z",
        "status":            "SUCCESS",
        # all other keys absent — SQLite will bind them as NULL via named params
    }
    # This will raise a KeyError inside execute() because named params are missing;
    # write_metrics_row must swallow it.
    write_metrics_row(minimal, _cfg(db))   # must not raise


# ---------------------------------------------------------------------------
# ConfigSettings — METRICS_DB_PATH integration
# ---------------------------------------------------------------------------

def test_config_settings_metrics_db_path_parsed(tmp_path):
    db_path = str(tmp_path / "metrics.db")
    conf = _write_config(
        tmp_path / "dar-backup.conf",
        tmp_path,
        misc_overrides={"METRICS_DB_PATH": db_path},
    )
    settings = ConfigSettings(str(conf))
    assert settings.metrics_db_path == db_path


def test_config_settings_metrics_db_path_absent_is_none(tmp_path):
    """When METRICS_DB_PATH is not in the config, the attribute is None."""
    conf = _write_config(tmp_path / "dar-backup.conf", tmp_path)
    settings = ConfigSettings(str(conf))
    assert settings.metrics_db_path is None
