#!/usr/bin/env python3
"""
import-archive-metrics.py

Populate the dar-backup metrics SQLite database from existing .dar archives
without re-running backups.  Useful for seeding historical data into the
metrics DB so that trend charts in the dashboard cover archives that predate
the metrics feature.

What is extracted per archive
------------------------------
  Recoverable from the archive on disk:
    backup_definition   — parsed from the archive filename
    backup_type         — FULL / DIFF / INCR, parsed from filename
    archive_name        — the base name (without .1.dar)
    run_started_at      — date/time embedded in the filename
    archive_size_bytes  — sum of all .N.dar slice sizes
    num_slices          — number of .N.dar slices found
    status              — always SUCCESS (archive exists → backup completed)

  Attempted via `dar -l` (left NULL if dar cannot parse them):
    inodes_saved, inodes_not_saved, inodes_failed, inodes_excluded,
    inodes_deleted, hard_links_treated, inodes_changed_during_backup,
    bytes_wasted, inodes_metadata_only, inodes_total, ea_saved, fsa_saved

  Always NULL for historical imports (not recorded by dar):
    duration_secs, dar_duration_secs, verify_duration_secs, par2_duration_secs,
    verify_passed, restore_test_passed, par2_passed, par2_size_bytes,
    failed_phase, error_summary, dar_exit_code, dar_backup_version, dar_version

Idempotency
-----------
Archives already present in the DB (matched by archive_name) are silently
skipped.  Safe to run repeatedly as new archives accumulate.

Usage
-----
    python import-archive-metrics.py \\
        --archive-dir /path/to/archives \\
        --metrics-db  /path/to/dar-backup-metrics.db \\
        [--backup-definition homedir] \\
        [--dar /usr/bin/dar] \\
        [--dry-run]

Requirements
------------
  - dar must be on PATH or supplied via --dar
  - Run inside the dar-backup virtualenv so that dar_backup.util is importable
"""

import argparse
import logging
import os
import re
import sqlite3
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Archive filename pattern
#
# Supported formats (time and sequence are optional — older archives omit them):
#   <definition>_<TYPE>_<YYYY-MM-DD>_<HHMMSS>_<NN>.1.dar   (current)
#   <definition>_<TYPE>_<YYYY-MM-DD>.1.dar                  (legacy)
#
# The definition name may contain letters, digits, spaces, and hyphens.
# ---------------------------------------------------------------------------
_ARCHIVE_RE = re.compile(
    r'^(?P<definition>.+)_(?P<type>FULL|DIFF|INCR)_'
    r'(?P<date>\d{4}-\d{2}-\d{2})'
    r'(?:_(?P<time>\d{6})_(?P<seq>\d{2}))?'   # optional: _HHMMSS_NN
    r'\.1\.dar$'
)

# ---------------------------------------------------------------------------
# Inode stat patterns copied from dar_backup.util so the script can work even
# when called without the package on sys.path (graceful fallback).
# ---------------------------------------------------------------------------
_STAT_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("inodes_saved",                 re.compile(r'(\d+)\s+inode\(s\)\s+saved')),
    ("hard_links_treated",           re.compile(r'including\s+(\d+)\s+hard\s+link\(s\)\s+treated')),
    ("inodes_changed_during_backup", re.compile(r'(\d+)\s+inode\(s\)\s+changed\s+at\s+the\s+moment\s+of\s+the\s+backup')),
    ("bytes_wasted",                 re.compile(r'(\d+)\s+byte\(s\)\s+have\s+been\s+wasted')),
    ("inodes_metadata_only",         re.compile(r'(\d+)\s+inode\(s\)\s+with\s+only\s+metadata\s+changed')),
    ("inodes_not_saved",             re.compile(r'(\d+)\s+inode\(s\)\s+not\s+saved\s+\(no\s+inode/file\s+change\)')),
    ("inodes_failed",                re.compile(r'(\d+)\s+inode\(s\)\s+failed\s+to\s+be\s+saved')),
    ("inodes_excluded",              re.compile(r'(\d+)\s+inode\(s\)\s+ignored\s+\(excluded\s+by\s+filters\)')),
    ("inodes_deleted",               re.compile(r'(\d+)\s+inode\(s\)\s+recorded\s+as\s+deleted')),
    ("inodes_total",                 re.compile(r'Total\s+number\s+of\s+inode\(s\)\s+considered:\s*(\d+)')),
    ("ea_saved",                     re.compile(r'EA\s+saved\s+for\s+(\d+)\s+inode\(s\)')),
    ("fsa_saved",                    re.compile(r'FSA\s+saved\s+for\s+(\d+)\s+inode\(s\)')),
]


def _setup_logging(verbose: bool) -> logging.Logger:
    """
    Configure and return the root logger for this script.

    Args:
        verbose: If True, set level to DEBUG; otherwise INFO.

    Returns:
        Configured Logger instance.
    """
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        format='%(asctime)s %(levelname)-8s %(message)s',
        datefmt='%Y-%m-%dT%H:%M:%S',
        level=level,
        stream=sys.stderr,
    )
    return logging.getLogger(__name__)


def _parse_args() -> argparse.Namespace:
    """
    Parse and validate command-line arguments.

    Returns:
        Parsed argument namespace.

    Raises:
        SystemExit: If required arguments are missing or paths are invalid.
    """
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        '--archive-dir', required=True,
        help='Directory containing .dar archive slices.',
    )
    parser.add_argument(
        '--metrics-db', required=True,
        help='Path to the dar-backup-metrics SQLite database file.',
    )
    parser.add_argument(
        '--backup-definition',
        help='Only import archives whose definition name matches this value exactly. '
             'Use this when multiple users share the same archive directory.',
    )
    parser.add_argument(
        '--dar', default='dar',
        help='Path to the dar binary (default: dar from PATH).',
    )
    parser.add_argument(
        '--dry-run', action='store_true',
        help='Show what would be imported without writing to the DB.',
    )
    parser.add_argument(
        '--verbose', action='store_true',
        help='Enable DEBUG logging.',
    )
    args = parser.parse_args()

    args.archive_dir = os.path.expanduser(os.path.expandvars(args.archive_dir))
    args.metrics_db  = os.path.expanduser(os.path.expandvars(args.metrics_db))

    if not os.path.isdir(args.archive_dir):
        parser.error(f"--archive-dir does not exist or is not a directory: {args.archive_dir}")

    return args


def _ensure_db(db_path: str) -> None:
    """
    Create the backup_runs table if it does not already exist.

    Delegates to dar_backup.util.ensure_metrics_db when available so that the
    full schema (including all migration columns) is guaranteed.  Falls back to
    a minimal CREATE TABLE that covers the columns this script writes.

    Args:
        db_path: Absolute path to the SQLite database file.

    Raises:
        sqlite3.Error: On unrecoverable database errors.
    """
    try:
        from dar_backup.util import ensure_metrics_db  # type: ignore
        ensure_metrics_db(db_path)
        return
    except ImportError:
        pass

    # Minimal fallback schema — only the columns this script populates.
    minimal_ddl = """
    CREATE TABLE IF NOT EXISTS backup_runs (
        id                            INTEGER PRIMARY KEY AUTOINCREMENT,
        backup_definition             TEXT    NOT NULL,
        backup_type                   TEXT    NOT NULL CHECK (backup_type IN ('FULL', 'DIFF', 'INCR')),
        archive_name                  TEXT,
        run_started_at                TEXT    NOT NULL,
        status                        TEXT    NOT NULL CHECK (status IN ('SUCCESS', 'WARNING', 'FAILURE')),
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
    );
    """
    with sqlite3.connect(db_path) as conn:
        conn.executescript(minimal_ddl)


def _already_imported(conn: sqlite3.Connection, archive_name: str) -> bool:
    """
    Return True if a row for this archive_name already exists in backup_runs.

    Args:
        conn:         Open SQLite connection.
        archive_name: The archive base name (without .1.dar extension).

    Returns:
        True if the archive is already recorded; False otherwise.
    """
    row = conn.execute(
        "SELECT 1 FROM backup_runs WHERE archive_name = ? LIMIT 1",
        (archive_name,),
    ).fetchone()
    return row is not None


def _scan_archives(archive_dir: str,
                   backup_definition: Optional[str] = None) -> list[tuple[str, re.Match]]:
    """
    Scan archive_dir for first-slice (.1.dar) files matching the naming convention.

    Files are returned sorted by (date, time, sequence) so that imports are
    chronologically ordered.

    Args:
        archive_dir:       Path to the directory containing .dar files.
        backup_definition: If given, only archives whose parsed definition name
                           matches exactly are returned.

    Returns:
        List of (filename, match) tuples, sorted chronologically.

    Raises:
        OSError: If the directory cannot be listed.
    """
    results: list[tuple[str, re.Match]] = []
    for entry in os.scandir(archive_dir):
        if not entry.is_file():
            continue
        m = _ARCHIVE_RE.match(entry.name)
        if not m:
            continue
        if backup_definition and m.group('definition') != backup_definition:
            continue
        results.append((entry.name, m))

    # Sort chronologically: date, then time (may be None for legacy archives)
    results.sort(key=lambda t: (
        t[1].group('date'),
        t[1].group('time') or '000000',
        t[1].group('seq')  or '00',
    ))
    return results


def _slice_sizes(archive_dir: str, archive_name: str) -> tuple[int, int]:
    """
    Sum the sizes of all .dar slices for the given archive and count them.

    Args:
        archive_dir:  Directory containing the slices.
        archive_name: Base name of the archive (without .N.dar suffix).

    Returns:
        (total_bytes, num_slices) tuple.
    """
    total = 0
    count = 0
    # Slices are named <archive_name>.1.dar, <archive_name>.2.dar, …
    prefix = archive_name + '.'
    for entry in os.scandir(archive_dir):
        if not entry.is_file():
            continue
        name = entry.name
        if name.startswith(prefix) and name.endswith('.dar'):
            try:
                total += entry.stat().st_size
                count += 1
            except OSError:
                pass  # slice disappeared between scan and stat — harmless
    return total, count


def _parse_dar_stats(output: str) -> dict[str, Optional[int]]:
    """
    Extract inode statistics from dar's text output using the shared patterns.

    Args:
        output: Combined stdout + stderr text from a dar invocation.

    Returns:
        Dict mapping stat key to int value or None if the pattern did not match.
    """
    result: dict[str, Optional[int]] = {}
    for key, pattern in _STAT_PATTERNS:
        m = pattern.search(output)
        if m:
            try:
                result[key] = int(m.group(1))
            except (ValueError, IndexError):
                result[key] = None
        else:
            result[key] = None
    return result


def _run_dar_list(dar_bin: str, archive_dir: str, archive_name: str,
                  logger: logging.Logger) -> dict[str, Optional[int]]:
    """
    Run `dar -l` on the archive and attempt to extract inode statistics.

    dar -l lists archive contents and prints a summary block that may include
    inode counts depending on dar version.  If dar is not available, if the
    command fails, or if the patterns do not match, all values are NULL — this
    never prevents the import of the row.

    Args:
        dar_bin:      Path to the dar binary.
        archive_dir:  Directory containing archive slices.
        archive_name: Base archive name (no .N.dar).
        logger:       Logger for diagnostic messages.

    Returns:
        Dict of inode stat keys mapped to int or None.
    """
    null_stats: dict[str, Optional[int]] = {k: None for k, _ in _STAT_PATTERNS}
    archive_path = os.path.join(archive_dir, archive_name)
    cmd = [dar_bin, '-l', archive_path, '-Q']
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            timeout=300,
        )
        # Decode with errors='replace' — dar -l output may contain non-UTF-8
        # filenames; the summary block we parse is always ASCII.
        combined = (
            result.stdout.decode('utf-8', errors='replace') +
            result.stderr.decode('utf-8', errors='replace')
        )
        stats = _parse_dar_stats(combined)
        found = sum(1 for v in stats.values() if v is not None)
        logger.debug("dar -l on %s: %d stat(s) parsed (exit %d)",
                     archive_name, found, result.returncode)
        return stats
    except FileNotFoundError:
        logger.warning("dar binary not found at '%s' — inode stats will be NULL", dar_bin)
        return null_stats
    except subprocess.TimeoutExpired:
        logger.warning("dar -l timed out for %s — inode stats will be NULL", archive_name)
        return null_stats
    except OSError as exc:
        logger.warning("dar -l failed for %s: %s — inode stats will be NULL", archive_name, exc)
        return null_stats


def _insert_row(conn: sqlite3.Connection, row: dict) -> None:
    """
    Insert one metrics row into backup_runs.

    Uses INSERT OR IGNORE so that a race condition between the existence check
    and the insert cannot create a duplicate.

    Args:
        conn: Open SQLite connection.
        row:  Dict of column-name → value.

    Raises:
        sqlite3.Error: On unexpected database errors.
    """
    conn.execute(
        """
        INSERT OR IGNORE INTO backup_runs (
            backup_definition, backup_type, archive_name,
            run_started_at, status,
            archive_size_bytes, num_slices,
            inodes_saved, hard_links_treated, inodes_changed_during_backup,
            bytes_wasted, inodes_metadata_only, inodes_not_saved,
            inodes_failed, inodes_excluded, inodes_deleted,
            inodes_total, ea_saved, fsa_saved
        ) VALUES (
            :backup_definition, :backup_type, :archive_name,
            :run_started_at, :status,
            :archive_size_bytes, :num_slices,
            :inodes_saved, :hard_links_treated, :inodes_changed_during_backup,
            :bytes_wasted, :inodes_metadata_only, :inodes_not_saved,
            :inodes_failed, :inodes_excluded, :inodes_deleted,
            :inodes_total, :ea_saved, :fsa_saved
        )
        """,
        row,
    )


def main() -> int:
    """
    Entry point: scan archives, check DB, import missing rows.

    Returns:
        0 on success, 1 if any archive failed to import.
    """
    args = _parse_args()
    logger = _setup_logging(args.verbose)

    logger.info("Archive directory : %s", args.archive_dir)
    logger.info("Metrics database  : %s", args.metrics_db)
    logger.info("dar binary        : %s", args.dar)
    if args.dry_run:
        logger.info("DRY RUN — no changes will be written")

    # Scan for .1.dar files matching the naming convention
    try:
        archives = _scan_archives(args.archive_dir, args.backup_definition)
    except OSError as exc:
        logger.error("Failed to scan archive directory: %s", exc)
        return 1

    if not archives:
        logger.info("No archives matching the naming convention found in %s", args.archive_dir)
        return 0

    logger.info("Found %d candidate archive(s)", len(archives))
    if args.backup_definition:
        logger.info("Filtering to definition : %s", args.backup_definition)

    if args.dry_run:
        for fname, m in archives:
            archive_name = fname[:-len('.1.dar')]
            ts = m.group('date') + (' ' + m.group('time') if m.group('time') else '')
            logger.info("  [dry-run] would import: %-52s  %s  %s  %s",
                        archive_name, m.group('definition'), m.group('type'), ts)
        return 0

    # Set up the database
    try:
        _ensure_db(args.metrics_db)
    except sqlite3.Error as exc:
        logger.error("Failed to initialise metrics database: %s", exc)
        return 1

    imported = 0
    skipped  = 0
    errors   = 0

    with sqlite3.connect(args.metrics_db) as conn:
        for fname, m in archives:
            archive_name = fname[:-len('.1.dar')]
            definition   = m.group('definition')
            backup_type  = m.group('type')
            date_str     = m.group('date')
            time_str     = m.group('time')   # None for legacy archives

            # Build ISO timestamp from filename (time is absent in legacy archives)
            try:
                if time_str:
                    run_started_at = datetime.strptime(
                        f"{date_str}_{time_str}", "%Y-%m-%d_%H%M%S"
                    ).isoformat(sep='T')
                else:
                    run_started_at = datetime.strptime(date_str, "%Y-%m-%d").isoformat(sep='T')
            except ValueError as exc:
                logger.warning("Cannot parse timestamp from '%s': %s — skipping", fname, exc)
                errors += 1
                continue

            # Idempotency check
            if _already_imported(conn, archive_name):
                logger.debug("Already imported: %s — skipping", archive_name)
                skipped += 1
                continue

            # Archive size and slice count
            total_bytes, num_slices = _slice_sizes(args.archive_dir, archive_name)
            if num_slices == 0:
                logger.warning("No slices found for %s — skipping", archive_name)
                errors += 1
                continue

            # Inode stats via dar -l
            inode_stats = _run_dar_list(args.dar, args.archive_dir, archive_name, logger)

            row: dict = {
                "backup_definition":             definition,
                "backup_type":                   backup_type,
                "archive_name":                  archive_name,
                "run_started_at":                run_started_at,
                "status":                        "SUCCESS",
                "archive_size_bytes":            total_bytes if total_bytes > 0 else None,
                "num_slices":                    num_slices,
                **inode_stats,
            }

            try:
                _insert_row(conn, row)
                conn.commit()
                imported += 1
                logger.info(
                    "Imported %-10s %-4s  %s  %s  slices=%d",
                    backup_type, definition, run_started_at,
                    _fmt_bytes(total_bytes), num_slices,
                )
            except sqlite3.Error as exc:
                logger.error("DB insert failed for %s: %s", archive_name, exc)
                errors += 1

    logger.info(
        "Done — imported: %d  skipped (already present): %d  errors: %d",
        imported, skipped, errors,
    )
    return 0 if errors == 0 else 1


def _fmt_bytes(b: int) -> str:
    """
    Format a byte count as a human-readable string.

    Args:
        b: Number of bytes.

    Returns:
        Formatted string such as '4.2 GB' or '512 MB'.
    """
    if b >= 1_000_000_000:
        return f"{b / 1_000_000_000:.1f} GB"
    if b >= 1_000_000:
        return f"{b / 1_000_000:.1f} MB"
    if b >= 1_000:
        return f"{b / 1_000:.0f} KB"
    return f"{b} B"


if __name__ == '__main__':
    sys.exit(main())
