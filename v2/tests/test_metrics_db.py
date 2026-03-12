# SPDX-License-Identifier: GPL-3.0-or-later
"""
Isolated unit tests for the metrics DB infrastructure.

Covers:
  - ensure_metrics_db() — schema creation and idempotency
  - write_metrics_row() — happy path, disabled path, error resilience
  - ConfigSettings — METRICS_DB_PATH parsed / absent
"""

import os
import sqlite3
from configparser import ConfigParser
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from dar_backup.util import ensure_metrics_db, write_metrics_row, _METRICS_MIGRATIONS
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
    "hostname":                      "testhost",
    "inodes_saved":                  6581,
    "hard_links_treated":            0,
    "inodes_changed_during_backup":  0,
    "bytes_wasted":                  0,
    "inodes_metadata_only":          0,
    "inodes_not_saved":              24695,
    "inodes_failed":                 13,
    "inodes_excluded":               9,
    "inodes_deleted":                0,
    "inodes_total":                  31298,
    "ea_saved":                      0,
    "fsa_saved":                     0,
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
# Helpers — old-schema DB (simulates a DB created before the migration columns)
# ---------------------------------------------------------------------------

_OLD_SCHEMA_DDL = """
CREATE TABLE IF NOT EXISTS backup_runs (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    backup_definition     TEXT    NOT NULL,
    backup_type           TEXT    NOT NULL CHECK (backup_type IN ('FULL', 'DIFF', 'INCR')),
    archive_name          TEXT,
    dar_backup_version    TEXT,
    dar_version           TEXT,
    run_started_at        TEXT    NOT NULL,
    run_finished_at       TEXT,
    duration_secs         REAL,
    dar_duration_secs     REAL,
    verify_duration_secs  REAL,
    par2_duration_secs    REAL,
    status                TEXT    NOT NULL CHECK (status IN ('SUCCESS', 'WARNING', 'FAILURE')),
    dar_exit_code         INTEGER,
    failed_phase          TEXT,
    error_summary         TEXT,
    catalog_updated       INTEGER,
    verify_passed         INTEGER,
    restore_test_passed   INTEGER,
    par2_passed           INTEGER,
    archive_size_bytes    INTEGER,
    num_slices            INTEGER,
    par2_size_bytes       INTEGER,
    files_verified        INTEGER,
    backup_dir_free_bytes INTEGER
);
"""


def _make_old_db(db_path: str) -> None:
    """Create a DB with the pre-migration schema and one existing data row."""
    with sqlite3.connect(db_path) as conn:
        conn.executescript(_OLD_SCHEMA_DDL)
        conn.execute(
            """
            INSERT INTO backup_runs (
                backup_definition, backup_type, run_started_at, status
            ) VALUES ('legacy-def', 'FULL', '2025-01-01T00:00:00Z', 'SUCCESS')
            """
        )


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
# ensure_metrics_db — migration of existing (old-schema) databases
# ---------------------------------------------------------------------------

def test_ensure_metrics_db_migrates_old_db_adds_new_columns(tmp_path):
    """Running ensure_metrics_db on a pre-migration DB must add all new columns."""
    db = str(tmp_path / "metrics.db")
    _make_old_db(db)
    ensure_metrics_db(db)   # must migrate, not raise
    with sqlite3.connect(db) as conn:
        cols = {row[1] for row in conn.execute("PRAGMA table_info(backup_runs)")}
    for col_name, _ in _METRICS_MIGRATIONS:
        assert col_name in cols, f"Migration column missing: {col_name}"


def test_ensure_metrics_db_migration_preserves_existing_rows(tmp_path):
    """Migration must not touch existing data rows."""
    db = str(tmp_path / "metrics.db")
    _make_old_db(db)
    ensure_metrics_db(db)
    with sqlite3.connect(db) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT * FROM backup_runs").fetchone()
    assert row["backup_definition"] == "legacy-def"
    assert row["status"]            == "SUCCESS"


def test_ensure_metrics_db_migration_new_columns_are_null_for_old_rows(tmp_path):
    """New columns on pre-existing rows must be NULL (no default supplied)."""
    db = str(tmp_path / "metrics.db")
    _make_old_db(db)
    ensure_metrics_db(db)
    with sqlite3.connect(db) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT * FROM backup_runs").fetchone()
    for col_name, _ in _METRICS_MIGRATIONS:
        assert row[col_name] is None, f"{col_name} should be NULL on legacy row"


def test_ensure_metrics_db_migration_is_idempotent(tmp_path):
    """Running ensure_metrics_db twice on a migrated DB must not raise."""
    db = str(tmp_path / "metrics.db")
    _make_old_db(db)
    ensure_metrics_db(db)
    ensure_metrics_db(db)   # second call — IF NOT EXISTS makes this safe


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


# ---------------------------------------------------------------------------
# Gap 1 — CHECK constraint violations are swallowed and logged as warnings
# ---------------------------------------------------------------------------

def _row_count(db: str) -> int:
    """Return number of rows in backup_runs for the given DB file."""
    with sqlite3.connect(db) as conn:
        return conn.execute("SELECT count(*) FROM backup_runs").fetchone()[0]


def _mock_logger():
    """Return a patched get_logger that yields a MagicMock logger."""
    return patch("dar_backup.util.get_logger", return_value=MagicMock())


def test_write_metrics_row_invalid_backup_type_swallowed_and_logged(tmp_path):
    """backup_type not in ('FULL','DIFF','INCR') must be swallowed, logged, and insert 0 rows."""
    db = str(tmp_path / "metrics.db")
    bad = {**_FULL_METRICS, "backup_type": "INVALID"}
    with _mock_logger() as mock_get:
        write_metrics_row(bad, _cfg(db))
        mock_get.return_value.warning.assert_called_once()
    assert _row_count(db) == 0


def test_write_metrics_row_invalid_status_swallowed_and_logged(tmp_path):
    """status not in ('SUCCESS','WARNING','FAILURE') must be swallowed, logged, and insert 0 rows."""
    db = str(tmp_path / "metrics.db")
    bad = {**_FULL_METRICS, "status": "UNKNOWN"}
    with _mock_logger() as mock_get:
        write_metrics_row(bad, _cfg(db))
        mock_get.return_value.warning.assert_called_once()
    assert _row_count(db) == 0


def test_write_metrics_row_invalid_failed_phase_swallowed_and_logged(tmp_path):
    """failed_phase not in ('DAR','VERIFY','PAR2',NULL) must be swallowed, logged, and insert 0 rows."""
    db = str(tmp_path / "metrics.db")
    bad = {**_FULL_METRICS, "failed_phase": "CATALOG"}
    with _mock_logger() as mock_get:
        write_metrics_row(bad, _cfg(db))
        mock_get.return_value.warning.assert_called_once()
    assert _row_count(db) == 0


# ---------------------------------------------------------------------------
# Gap 2 — 'WARNING' status round-trip
# ---------------------------------------------------------------------------

def test_write_metrics_row_warning_status_round_trip(tmp_path):
    """status='WARNING' must insert and read back correctly."""
    db = str(tmp_path / "metrics.db")
    write_metrics_row({**_FULL_METRICS, "status": "WARNING"}, _cfg(db))
    with sqlite3.connect(db) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT status FROM backup_runs").fetchone()
    assert row["status"] == "WARNING"


# ---------------------------------------------------------------------------
# Gap 3 — valid non-NULL failed_phase values round-trip
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("phase", ["DAR", "VERIFY", "PAR2"])
def test_write_metrics_row_failed_phase_round_trip(tmp_path, phase):
    """Each valid failed_phase value must insert and read back correctly."""
    db = str(tmp_path / "metrics.db")
    row_data = {**_FULL_METRICS, "status": "FAILURE", "failed_phase": phase}
    write_metrics_row(row_data, _cfg(db))
    with sqlite3.connect(db) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT failed_phase FROM backup_runs").fetchone()
    assert row["failed_phase"] == phase


# ---------------------------------------------------------------------------
# Gap 4 — config_settings object has no metrics_db_path attribute at all
# ---------------------------------------------------------------------------

def test_write_metrics_row_noop_when_config_missing_attribute():
    """config_settings with no metrics_db_path attribute must be a silent no-op."""
    write_metrics_row(_FULL_METRICS, SimpleNamespace())   # must not raise


# ---------------------------------------------------------------------------
# Gap 5 — tilde / env-var expansion in db_path
# ---------------------------------------------------------------------------

def test_write_metrics_row_expands_tilde_in_path(tmp_path, monkeypatch):
    """A db_path starting with ~ must expand to the real home directory."""
    monkeypatch.setenv("HOME", str(tmp_path))
    tilde_path = "~/metrics.db"
    write_metrics_row(_FULL_METRICS, _cfg(tilde_path))
    expected = tmp_path / "metrics.db"
    assert expected.exists()
    assert _row_count(str(expected)) == 1


def test_write_metrics_row_expands_env_var_in_path(tmp_path, monkeypatch):
    """A db_path containing $VAR must expand the environment variable."""
    monkeypatch.setenv("METRICS_DIR", str(tmp_path))
    var_path = "$METRICS_DIR/metrics.db"
    write_metrics_row(_FULL_METRICS, _cfg(var_path))
    expected = tmp_path / "metrics.db"
    assert expected.exists()
    assert _row_count(str(expected)) == 1


def test_write_metrics_row_undefined_env_var_swallowed_and_logged(monkeypatch):
    """An undefined $VAR leaves the literal string as path; sqlite fails to create it,
    the error is swallowed, and a warning is logged — no exception propagates."""
    # Ensure the variable is definitely not set in this process
    monkeypatch.delenv("METRICS_UNDEFINED_VAR_XYZ", raising=False)
    bad_path = "$METRICS_UNDEFINED_VAR_XYZ/metrics.db"
    with _mock_logger() as mock_get:
        write_metrics_row(_FULL_METRICS, _cfg(bad_path))
        mock_get.return_value.warning.assert_called_once()
    # The literal path must not have been created on the filesystem
    assert not os.path.exists(bad_path)


# ---------------------------------------------------------------------------
# Gap 6 — column schema regression: verify all expected columns are present
# ---------------------------------------------------------------------------

_EXPECTED_COLUMNS = {
    "id", "backup_definition", "backup_type", "archive_name",
    "dar_backup_version", "dar_version",
    "run_started_at", "run_finished_at", "duration_secs",
    "dar_duration_secs", "verify_duration_secs", "par2_duration_secs",
    "status", "dar_exit_code", "failed_phase", "error_summary",
    "catalog_updated", "verify_passed", "restore_test_passed", "par2_passed",
    "archive_size_bytes", "num_slices", "par2_size_bytes",
    "files_verified", "backup_dir_free_bytes",
    "hostname",
    "inodes_saved", "hard_links_treated", "inodes_changed_during_backup",
    "bytes_wasted", "inodes_metadata_only", "inodes_not_saved",
    "inodes_failed", "inodes_excluded", "inodes_deleted",
    "inodes_total", "ea_saved", "fsa_saved",
}


def test_ensure_metrics_db_all_columns_present(tmp_path):
    """Schema must contain every expected column — catches renames or removals."""
    from dar_backup.util import ensure_metrics_db
    db = str(tmp_path / "metrics.db")
    ensure_metrics_db(db)
    with sqlite3.connect(db) as conn:
        cols = {row[1] for row in conn.execute("PRAGMA table_info(backup_runs)")}
    assert _EXPECTED_COLUMNS == cols


def test_ensure_metrics_db_not_null_constraints(tmp_path):
    """backup_definition, backup_type, run_started_at and status must be NOT NULL."""
    from dar_backup.util import ensure_metrics_db
    db = str(tmp_path / "metrics.db")
    ensure_metrics_db(db)
    with sqlite3.connect(db) as conn:
        not_null_cols = {
            row[1]
            for row in conn.execute("PRAGMA table_info(backup_runs)")
            if row[3] == 1   # notnull flag
        }
    assert {"backup_definition", "backup_type", "run_started_at", "status"} <= not_null_cols
