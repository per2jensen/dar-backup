# SPDX-License-Identifier: GPL-3.0-or-later
"""
Tests for v2/scripts/import-archive-metrics.py

The script is a standalone file (not a package), so it is loaded via
importlib.util.spec_from_file_location.  All internal functions are accessed
through the module object ``_mod``.
"""

import importlib.util
import logging
import sqlite3
import subprocess
import sys
from pathlib import Path
from typing import Optional
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Load the script as a module
# ---------------------------------------------------------------------------
_SCRIPT = Path(__file__).parent.parent / "scripts" / "import-archive-metrics.py"

_spec = importlib.util.spec_from_file_location("import_archive_metrics", _SCRIPT)
_mod  = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)  # type: ignore[union-attr]

_scan_archives    = _mod._scan_archives
_slice_sizes      = _mod._slice_sizes
_parse_dar_stats  = _mod._parse_dar_stats
_run_dar_list     = _mod._run_dar_list
_already_imported = _mod._already_imported
_insert_row       = _mod._insert_row
_ensure_db        = _mod._ensure_db
_fmt_bytes        = _mod._fmt_bytes
main              = _mod.main

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _make_dar_file(directory: Path, name: str, size: int = 1024) -> None:
    """Create a fake .dar slice file of a given byte size."""
    (directory / name).write_bytes(b"x" * size)


def _open_minimal_db(db_path: str) -> sqlite3.Connection:
    """
    Create a backup_runs table with the minimal schema used by the script's
    fallback DDL and return an open connection.
    """
    conn = sqlite3.connect(db_path)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS backup_runs (
            id                            INTEGER PRIMARY KEY AUTOINCREMENT,
            backup_definition             TEXT    NOT NULL,
            backup_type                   TEXT    NOT NULL,
            archive_name                  TEXT,
            run_started_at                TEXT    NOT NULL,
            status                        TEXT    NOT NULL,
            archive_size_bytes            INTEGER,
            num_slices                    INTEGER,
            inodes_saved                  INTEGER,
            hard_links_treated            INTEGER,
            inodes_changed_during_backup  INTEGER,
            bytes_wasted                  INTEGER,
            inodes_metadata_only          INTEGER,
            inodes_not_saved              INTEGER,
            inodes_failed                 INTEGER,
            inodes_excluded               INTEGER,
            inodes_deleted                INTEGER,
            inodes_total                  INTEGER,
            ea_saved                      INTEGER,
            fsa_saved                     INTEGER
        )
    """)
    conn.commit()
    return conn


def _null_stats() -> dict[str, Optional[int]]:
    """Return a dict of all-NULL inode stats (as returned when dar -l fails)."""
    return {k: None for k, _ in _mod._STAT_PATTERNS}


def _full_row(archive_name: str = "homedir_FULL_2025-01-15") -> dict:
    """Return a minimal valid row dict suitable for _insert_row."""
    return {
        "backup_definition":             "homedir",
        "backup_type":                   "FULL",
        "archive_name":                  archive_name,
        "run_started_at":                "2025-01-15T00:00:00",
        "status":                        "SUCCESS",
        "archive_size_bytes":            1_000_000,
        "num_slices":                    1,
        "inodes_saved":                  42,
        "hard_links_treated":            0,
        "inodes_changed_during_backup":  0,
        "bytes_wasted":                  0,
        "inodes_metadata_only":          0,
        "inodes_not_saved":              0,
        "inodes_failed":                 0,
        "inodes_excluded":               0,
        "inodes_deleted":                0,
        "inodes_total":                  42,
        "ea_saved":                      0,
        "fsa_saved":                     0,
    }


# ---------------------------------------------------------------------------
# _scan_archives
# ---------------------------------------------------------------------------

class TestScanArchives:
    """Tests for _scan_archives(archive_dir, backup_definition=None)."""

    def test_empty_directory_returns_empty_list(self, tmp_path: Path) -> None:
        """No files → empty result."""
        assert _scan_archives(str(tmp_path)) == []

    def test_current_format_archive_found(self, tmp_path: Path) -> None:
        """Archive with _HHMMSS_NN suffix is matched and groups are correct."""
        _make_dar_file(tmp_path, "homedir_FULL_2025-01-15_120000_01.1.dar")
        result = _scan_archives(str(tmp_path))
        assert len(result) == 1
        fname, m = result[0]
        assert fname == "homedir_FULL_2025-01-15_120000_01.1.dar"
        assert m.group("definition") == "homedir"
        assert m.group("type")       == "FULL"
        assert m.group("date")       == "2025-01-15"
        assert m.group("time")       == "120000"
        assert m.group("seq")        == "01"

    def test_legacy_format_archive_found(self, tmp_path: Path) -> None:
        """Archive without _HHMMSS_NN suffix (legacy) is matched; optional groups are None."""
        _make_dar_file(tmp_path, "media-files_DIFF_2025-12-20.1.dar")
        result = _scan_archives(str(tmp_path))
        assert len(result) == 1
        _, m = result[0]
        assert m.group("definition") == "media-files"
        assert m.group("type")       == "DIFF"
        assert m.group("date")       == "2025-12-20"
        assert m.group("time")       is None
        assert m.group("seq")        is None

    def test_incr_type_matched(self, tmp_path: Path) -> None:
        """INCR backup type is accepted."""
        _make_dar_file(tmp_path, "homedir_INCR_2025-06-15_090000_01.1.dar")
        result = _scan_archives(str(tmp_path))
        assert len(result) == 1
        assert result[0][1].group("type") == "INCR"

    def test_non_first_slices_are_ignored(self, tmp_path: Path) -> None:
        """Only .1.dar files are entry points; .2.dar and .3.dar slices are ignored."""
        _make_dar_file(tmp_path, "homedir_FULL_2025-01-15.1.dar")
        _make_dar_file(tmp_path, "homedir_FULL_2025-01-15.2.dar")
        _make_dar_file(tmp_path, "homedir_FULL_2025-01-15.3.dar")
        result = _scan_archives(str(tmp_path))
        assert len(result) == 1

    def test_unrelated_files_are_ignored(self, tmp_path: Path) -> None:
        """Non-archive files do not appear in results."""
        (tmp_path / "README.txt").write_text("hello")
        (tmp_path / "homedir_FULL_2025-01-15.1.dar.part").write_bytes(b"x")
        assert _scan_archives(str(tmp_path)) == []

    def test_backup_definition_filter_exact_match(self, tmp_path: Path) -> None:
        """Only archives whose definition matches exactly are returned."""
        _make_dar_file(tmp_path, "homedir_FULL_2025-01-15.1.dar")
        _make_dar_file(tmp_path, "media-files_FULL_2025-01-15.1.dar")
        result = _scan_archives(str(tmp_path), backup_definition="homedir")
        assert len(result) == 1
        assert result[0][1].group("definition") == "homedir"

    def test_backup_definition_filter_no_match_returns_empty(self, tmp_path: Path) -> None:
        """Definition filter that matches nothing returns an empty list."""
        _make_dar_file(tmp_path, "homedir_FULL_2025-01-15.1.dar")
        assert _scan_archives(str(tmp_path), backup_definition="other") == []

    def test_results_sorted_chronologically_by_date(self, tmp_path: Path) -> None:
        """Results are ordered oldest-first by date."""
        _make_dar_file(tmp_path, "homedir_DIFF_2025-03-01.1.dar")
        _make_dar_file(tmp_path, "homedir_FULL_2025-01-01.1.dar")
        _make_dar_file(tmp_path, "homedir_INCR_2025-02-01.1.dar")
        result = _scan_archives(str(tmp_path))
        dates = [r[1].group("date") for r in result]
        assert dates == ["2025-01-01", "2025-02-01", "2025-03-01"]

    def test_same_date_sorted_by_time(self, tmp_path: Path) -> None:
        """Archives on the same date are sorted by embedded time."""
        _make_dar_file(tmp_path, "homedir_DIFF_2025-01-01_180000_01.1.dar")
        _make_dar_file(tmp_path, "homedir_FULL_2025-01-01_060000_01.1.dar")
        result = _scan_archives(str(tmp_path))
        assert result[0][1].group("time") == "060000"
        assert result[1][1].group("time") == "180000"

    def test_mixed_legacy_and_current_format_sorted(self, tmp_path: Path) -> None:
        """Legacy archives (no time) sort before same-date current archives."""
        _make_dar_file(tmp_path, "homedir_FULL_2025-01-01_120000_01.1.dar")
        _make_dar_file(tmp_path, "homedir_DIFF_2025-01-01.1.dar")  # legacy → time='000000'
        result = _scan_archives(str(tmp_path))
        # Legacy archive gets time='000000' in sort key, so comes first
        assert result[0][1].group("time") is None
        assert result[1][1].group("time") == "120000"


# ---------------------------------------------------------------------------
# _slice_sizes
# ---------------------------------------------------------------------------

class TestSliceSizes:
    """Tests for _slice_sizes(archive_dir, archive_name)."""

    def test_single_slice_returns_correct_size_and_count(self, tmp_path: Path) -> None:
        _make_dar_file(tmp_path, "homedir_FULL_2025-01-15.1.dar", size=5000)
        total, count = _slice_sizes(str(tmp_path), "homedir_FULL_2025-01-15")
        assert total == 5000
        assert count == 1

    def test_multiple_slices_summed(self, tmp_path: Path) -> None:
        _make_dar_file(tmp_path, "homedir_FULL_2025-01-15.1.dar", size=1000)
        _make_dar_file(tmp_path, "homedir_FULL_2025-01-15.2.dar", size=2000)
        _make_dar_file(tmp_path, "homedir_FULL_2025-01-15.3.dar", size=3000)
        total, count = _slice_sizes(str(tmp_path), "homedir_FULL_2025-01-15")
        assert total == 6000
        assert count == 3

    def test_no_slices_returns_zeros(self, tmp_path: Path) -> None:
        total, count = _slice_sizes(str(tmp_path), "homedir_FULL_2025-01-15")
        assert total == 0
        assert count == 0

    def test_other_archive_slices_not_counted(self, tmp_path: Path) -> None:
        """Slices belonging to a different archive name are not included."""
        _make_dar_file(tmp_path, "homedir_FULL_2025-01-15.1.dar", size=1000)
        _make_dar_file(tmp_path, "media-files_FULL_2025-01-15.1.dar", size=9999)
        total, count = _slice_sizes(str(tmp_path), "homedir_FULL_2025-01-15")
        assert total == 1000
        assert count == 1


# ---------------------------------------------------------------------------
# _parse_dar_stats
# ---------------------------------------------------------------------------

class TestParseDarStats:
    """Tests for _parse_dar_stats(output)."""

    _SAMPLE = (
        "  42 inode(s) saved\n"
        "  including 3 hard link(s) treated\n"
        "  0 inode(s) changed at the moment of the backup\n"
        "  512 byte(s) have been wasted\n"
        "  1 inode(s) with only metadata changed\n"
        "  100 inode(s) not saved (no inode/file change)\n"
        "  0 inode(s) failed to be saved\n"
        "  5 inode(s) ignored (excluded by filters)\n"
        "  2 inode(s) recorded as deleted\n"
        "  Total number of inode(s) considered: 150\n"
        "  EA saved for 10 inode(s)\n"
        "  FSA saved for 7 inode(s)\n"
    )

    def test_all_stats_parsed_from_full_output(self) -> None:
        stats = _parse_dar_stats(self._SAMPLE)
        assert stats["inodes_saved"]                 == 42
        assert stats["hard_links_treated"]           == 3
        assert stats["inodes_changed_during_backup"] == 0
        assert stats["bytes_wasted"]                 == 512
        assert stats["inodes_metadata_only"]         == 1
        assert stats["inodes_not_saved"]             == 100
        assert stats["inodes_failed"]                == 0
        assert stats["inodes_excluded"]              == 5
        assert stats["inodes_deleted"]               == 2
        assert stats["inodes_total"]                 == 150
        assert stats["ea_saved"]                     == 10
        assert stats["fsa_saved"]                    == 7

    def test_empty_output_returns_all_none(self) -> None:
        stats = _parse_dar_stats("")
        assert all(v is None for v in stats.values())

    def test_partial_output_leaves_missing_as_none(self) -> None:
        stats = _parse_dar_stats("42 inode(s) saved\n")
        assert stats["inodes_saved"] == 42
        assert stats["inodes_total"] is None

    def test_returns_dict_with_all_expected_keys(self) -> None:
        stats = _parse_dar_stats("")
        expected_keys = {k for k, _ in _mod._STAT_PATTERNS}
        assert set(stats.keys()) == expected_keys


# ---------------------------------------------------------------------------
# _run_dar_list
# ---------------------------------------------------------------------------

class TestRunDarList:
    """Tests for _run_dar_list(dar_bin, archive_dir, archive_name, logger)."""

    def _logger(self) -> logging.Logger:
        return logging.getLogger("test.run_dar_list")

    def test_dar_binary_not_found_returns_null_stats(self, tmp_path: Path) -> None:
        stats = _run_dar_list("/nonexistent/dar", str(tmp_path), "homedir_FULL_2025-01-15", self._logger())
        assert all(v is None for v in stats.values())

    def test_dar_timeout_returns_null_stats(self, tmp_path: Path) -> None:
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="dar", timeout=300)):
            stats = _run_dar_list("dar", str(tmp_path), "homedir_FULL_2025-01-15", self._logger())
        assert all(v is None for v in stats.values())

    def test_oserror_returns_null_stats(self, tmp_path: Path) -> None:
        with patch("subprocess.run", side_effect=OSError("permission denied")):
            stats = _run_dar_list("dar", str(tmp_path), "homedir_FULL_2025-01-15", self._logger())
        assert all(v is None for v in stats.values())

    def test_non_utf8_output_does_not_raise(self, tmp_path: Path) -> None:
        """Non-UTF-8 bytes in filenames listed by dar must not crash the script."""
        non_utf8_bytes = b"\xe5\xff\xfe invalid bytes mixed in"
        mock_result = MagicMock()
        mock_result.stdout   = non_utf8_bytes
        mock_result.stderr   = b"42 inode(s) saved\n"
        mock_result.returncode = 0
        with patch("subprocess.run", return_value=mock_result):
            stats = _run_dar_list("dar", str(tmp_path), "homedir_FULL_2025-01-15", self._logger())
        # The summary line in stderr must still be parsed despite bad bytes in stdout
        assert stats["inodes_saved"] == 42

    def test_successful_output_parsed(self, tmp_path: Path) -> None:
        mock_result = MagicMock()
        mock_result.stdout     = b"10 inode(s) saved\n"
        mock_result.stderr     = b"Total number of inode(s) considered: 15\n"
        mock_result.returncode = 0
        with patch("subprocess.run", return_value=mock_result):
            stats = _run_dar_list("dar", str(tmp_path), "homedir_FULL_2025-01-15", self._logger())
        assert stats["inodes_saved"] == 10
        assert stats["inodes_total"] == 15

    def test_null_stats_dict_has_all_keys(self, tmp_path: Path) -> None:
        """The returned dict always contains every stat key even when all are None."""
        stats = _run_dar_list("/nonexistent/dar", str(tmp_path), "x", self._logger())
        expected_keys = {k for k, _ in _mod._STAT_PATTERNS}
        assert set(stats.keys()) == expected_keys


# ---------------------------------------------------------------------------
# _already_imported
# ---------------------------------------------------------------------------

class TestAlreadyImported:
    """Tests for _already_imported(conn, archive_name)."""

    def test_returns_false_when_archive_not_in_db(self, tmp_path: Path) -> None:
        conn = _open_minimal_db(str(tmp_path / "test.db"))
        assert _already_imported(conn, "homedir_FULL_2025-01-15") is False
        conn.close()

    def test_returns_true_when_archive_in_db(self, tmp_path: Path) -> None:
        conn = _open_minimal_db(str(tmp_path / "test.db"))
        conn.execute(
            "INSERT INTO backup_runs "
            "(backup_definition, backup_type, archive_name, run_started_at, status) "
            "VALUES (?, ?, ?, ?, ?)",
            ("homedir", "FULL", "homedir_FULL_2025-01-15", "2025-01-15T00:00:00", "SUCCESS"),
        )
        conn.commit()
        assert _already_imported(conn, "homedir_FULL_2025-01-15") is True
        conn.close()

    def test_different_archive_name_returns_false(self, tmp_path: Path) -> None:
        conn = _open_minimal_db(str(tmp_path / "test.db"))
        conn.execute(
            "INSERT INTO backup_runs "
            "(backup_definition, backup_type, archive_name, run_started_at, status) "
            "VALUES (?, ?, ?, ?, ?)",
            ("homedir", "FULL", "homedir_FULL_2025-01-15", "2025-01-15T00:00:00", "SUCCESS"),
        )
        conn.commit()
        assert _already_imported(conn, "homedir_FULL_2025-02-01") is False
        conn.close()


# ---------------------------------------------------------------------------
# _insert_row
# ---------------------------------------------------------------------------

class TestInsertRow:
    """Tests for _insert_row(conn, row)."""

    def test_row_inserted_successfully(self, tmp_path: Path) -> None:
        conn = _open_minimal_db(str(tmp_path / "test.db"))
        _insert_row(conn, _full_row())
        conn.commit()
        row = conn.execute(
            "SELECT backup_definition, backup_type, status FROM backup_runs"
        ).fetchone()
        assert row == ("homedir", "FULL", "SUCCESS")
        conn.close()

    def test_null_inode_stats_accepted(self, tmp_path: Path) -> None:
        """Rows where dar -l produced no stats (all NULLs) insert without error."""
        conn = _open_minimal_db(str(tmp_path / "test.db"))
        row = _full_row()
        for key in ["inodes_saved", "inodes_total", "ea_saved", "fsa_saved"]:
            row[key] = None
        _insert_row(conn, row)
        conn.commit()
        count = conn.execute("SELECT COUNT(*) FROM backup_runs").fetchone()[0]
        assert count == 1
        conn.close()

    def test_archive_size_bytes_stored_correctly(self, tmp_path: Path) -> None:
        conn = _open_minimal_db(str(tmp_path / "test.db"))
        row = _full_row()
        row["archive_size_bytes"] = 987_654_321
        _insert_row(conn, row)
        conn.commit()
        stored = conn.execute("SELECT archive_size_bytes FROM backup_runs").fetchone()[0]
        assert stored == 987_654_321
        conn.close()

    def test_run_started_at_stored_correctly(self, tmp_path: Path) -> None:
        conn = _open_minimal_db(str(tmp_path / "test.db"))
        _insert_row(conn, _full_row())
        conn.commit()
        stored = conn.execute("SELECT run_started_at FROM backup_runs").fetchone()[0]
        assert stored == "2025-01-15T00:00:00"
        conn.close()


# ---------------------------------------------------------------------------
# _fmt_bytes
# ---------------------------------------------------------------------------

class TestFmtBytes:
    """Tests for _fmt_bytes(b)."""

    def test_gigabytes_formatted(self) -> None:
        assert _fmt_bytes(2_500_000_000) == "2.5 GB"

    def test_exactly_one_gigabyte(self) -> None:
        assert _fmt_bytes(1_000_000_000) == "1.0 GB"

    def test_megabytes_formatted(self) -> None:
        assert _fmt_bytes(512_000_000) == "512.0 MB"

    def test_kilobytes_formatted(self) -> None:
        assert _fmt_bytes(4_000) == "4 KB"

    def test_bytes_formatted(self) -> None:
        assert _fmt_bytes(999) == "999 B"

    def test_zero_bytes(self) -> None:
        assert _fmt_bytes(0) == "0 B"


# ---------------------------------------------------------------------------
# _ensure_db
# ---------------------------------------------------------------------------

class TestEnsureDb:
    """Tests for _ensure_db(db_path) using the fallback DDL path."""

    def test_creates_backup_runs_table(self, tmp_path: Path) -> None:
        db_path = str(tmp_path / "new.db")
        with patch.dict(sys.modules, {"dar_backup.util": None}):
            # Force ImportError so the fallback DDL is used
            with patch("builtins.__import__", side_effect=_raise_on_dar_backup_util):
                _ensure_db(db_path)
        conn = sqlite3.connect(db_path)
        tables = [r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()]
        conn.close()
        assert "backup_runs" in tables

    def test_idempotent_when_table_already_exists(self, tmp_path: Path) -> None:
        """Calling _ensure_db twice on the same file must not raise."""
        db_path = str(tmp_path / "existing.db")
        with patch("builtins.__import__", side_effect=_raise_on_dar_backup_util):
            _ensure_db(db_path)
            _ensure_db(db_path)  # second call must be a no-op


def _raise_on_dar_backup_util(name, *args, **kwargs):
    """Helper: raise ImportError for dar_backup.util, pass everything else through."""
    if name == "dar_backup.util":
        raise ImportError("mocked absence of dar_backup.util")
    return original_import(name, *args, **kwargs)


original_import = __builtins__.__import__ if hasattr(__builtins__, "__import__") else __import__


# ---------------------------------------------------------------------------
# main() — end-to-end with a real temp filesystem and in-process DB
# ---------------------------------------------------------------------------

class TestMain:
    """
    End-to-end tests for main().

    sys.argv is monkeypatched so _parse_args() sees the desired arguments.
    _run_dar_list is patched to avoid needing a real dar binary.
    """

    def _run(self, monkeypatch: pytest.MonkeyPatch, argv: list[str]) -> int:
        monkeypatch.setattr(sys, "argv", ["import-archive-metrics.py"] + argv)
        return main()

    def _null_dar(self):
        """Patch _run_dar_list on the module to return all-NULL stats."""
        return patch.object(_mod, "_run_dar_list", return_value=_null_stats())

    # --- happy path ---------------------------------------------------------

    def test_imports_single_archive_returns_0(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _make_dar_file(tmp_path, "homedir_FULL_2025-01-15.1.dar", size=1024)
        db_path = str(tmp_path / "metrics.db")
        with self._null_dar():
            rc = self._run(monkeypatch, [
                "--archive-dir", str(tmp_path),
                "--metrics-db", db_path,
            ])
        assert rc == 0
        conn = sqlite3.connect(db_path)
        row = conn.execute(
            "SELECT backup_definition, backup_type, status FROM backup_runs"
        ).fetchone()
        conn.close()
        assert row == ("homedir", "FULL", "SUCCESS")

    def test_imports_legacy_filename_correctly(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Archives without _HHMMSS_NN suffix get timestamp T00:00:00."""
        _make_dar_file(tmp_path, "media-files_DIFF_2025-12-20.1.dar", size=512)
        db_path = str(tmp_path / "metrics.db")
        with self._null_dar():
            rc = self._run(monkeypatch, [
                "--archive-dir", str(tmp_path),
                "--metrics-db", db_path,
            ])
        assert rc == 0
        conn = sqlite3.connect(db_path)
        row = conn.execute("SELECT run_started_at, backup_type FROM backup_runs").fetchone()
        conn.close()
        assert row[0] == "2025-12-20T00:00:00"
        assert row[1] == "DIFF"

    def test_imports_current_filename_with_timestamp(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Archives with _HHMMSS_NN suffix use that time in the stored timestamp."""
        _make_dar_file(tmp_path, "homedir_FULL_2025-01-15_143000_01.1.dar", size=512)
        db_path = str(tmp_path / "metrics.db")
        with self._null_dar():
            rc = self._run(monkeypatch, [
                "--archive-dir", str(tmp_path),
                "--metrics-db", db_path,
            ])
        assert rc == 0
        conn = sqlite3.connect(db_path)
        ts = conn.execute("SELECT run_started_at FROM backup_runs").fetchone()[0]
        conn.close()
        assert ts == "2025-01-15T14:30:00"

    def test_status_always_success(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _make_dar_file(tmp_path, "homedir_FULL_2025-01-15.1.dar")
        db_path = str(tmp_path / "metrics.db")
        with self._null_dar():
            self._run(monkeypatch, [
                "--archive-dir", str(tmp_path), "--metrics-db", db_path,
            ])
        conn = sqlite3.connect(db_path)
        status = conn.execute("SELECT status FROM backup_runs").fetchone()[0]
        conn.close()
        assert status == "SUCCESS"

    # --- idempotency --------------------------------------------------------

    def test_second_run_skips_already_imported(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _make_dar_file(tmp_path, "homedir_FULL_2025-01-15.1.dar")
        db_path = str(tmp_path / "metrics.db")
        argv = ["--archive-dir", str(tmp_path), "--metrics-db", db_path]
        with self._null_dar():
            self._run(monkeypatch, argv)
            rc = self._run(monkeypatch, argv)
        assert rc == 0
        conn = sqlite3.connect(db_path)
        count = conn.execute("SELECT COUNT(*) FROM backup_runs").fetchone()[0]
        conn.close()
        assert count == 1  # only one row, not two

    # --- filtering ----------------------------------------------------------

    def test_backup_definition_filter_imports_only_matching(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _make_dar_file(tmp_path, "homedir_FULL_2025-01-15.1.dar")
        _make_dar_file(tmp_path, "media-files_FULL_2025-01-15.1.dar")
        db_path = str(tmp_path / "metrics.db")
        with self._null_dar():
            rc = self._run(monkeypatch, [
                "--archive-dir", str(tmp_path),
                "--metrics-db", db_path,
                "--backup-definition", "homedir",
            ])
        assert rc == 0
        conn = sqlite3.connect(db_path)
        defs = [r[0] for r in conn.execute(
            "SELECT backup_definition FROM backup_runs"
        ).fetchall()]
        conn.close()
        assert defs == ["homedir"]

    # --- dry-run ------------------------------------------------------------

    def test_dry_run_returns_0_without_writing_db(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _make_dar_file(tmp_path, "homedir_FULL_2025-01-15.1.dar")
        db_path = str(tmp_path / "metrics.db")
        rc = self._run(monkeypatch, [
            "--archive-dir", str(tmp_path),
            "--metrics-db", db_path,
            "--dry-run",
        ])
        assert rc == 0
        assert not Path(db_path).exists()

    # --- edge cases ---------------------------------------------------------

    def test_no_matching_archives_returns_0(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        (tmp_path / "unrelated.txt").write_text("x")
        db_path = str(tmp_path / "metrics.db")
        rc = self._run(monkeypatch, [
            "--archive-dir", str(tmp_path),
            "--metrics-db", db_path,
        ])
        assert rc == 0

    def test_archive_with_no_slices_on_disk_counts_as_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """_slice_sizes returning (0, 0) means the slices are gone — counts as error."""
        db_path = str(tmp_path / "metrics.db")
        fake_match = _mod._ARCHIVE_RE.match("homedir_FULL_2025-01-15.1.dar")
        with (
            patch.object(_mod, "_scan_archives",
                         return_value=[("homedir_FULL_2025-01-15.1.dar", fake_match)]),
            patch.object(_mod, "_slice_sizes", return_value=(0, 0)),
        ):
            rc = self._run(monkeypatch, [
                "--archive-dir", str(tmp_path),
                "--metrics-db", db_path,
            ])
        assert rc == 1

    def test_multiple_archives_all_imported(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _make_dar_file(tmp_path, "homedir_FULL_2025-01-01.1.dar")
        _make_dar_file(tmp_path, "homedir_DIFF_2025-02-01.1.dar")
        _make_dar_file(tmp_path, "homedir_INCR_2025-03-01.1.dar")
        db_path = str(tmp_path / "metrics.db")
        with self._null_dar():
            rc = self._run(monkeypatch, [
                "--archive-dir", str(tmp_path),
                "--metrics-db", db_path,
            ])
        assert rc == 0
        conn = sqlite3.connect(db_path)
        count = conn.execute("SELECT COUNT(*) FROM backup_runs").fetchone()[0]
        conn.close()
        assert count == 3

    def test_archive_size_bytes_stored_as_sum_of_slices(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _make_dar_file(tmp_path, "homedir_FULL_2025-01-15.1.dar", size=1000)
        _make_dar_file(tmp_path, "homedir_FULL_2025-01-15.2.dar", size=2000)
        db_path = str(tmp_path / "metrics.db")
        with self._null_dar():
            self._run(monkeypatch, [
                "--archive-dir", str(tmp_path),
                "--metrics-db", db_path,
            ])
        conn = sqlite3.connect(db_path)
        stored = conn.execute("SELECT archive_size_bytes FROM backup_runs").fetchone()[0]
        conn.close()
        assert stored == 3000
