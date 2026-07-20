#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later

"""
   Copyright (C) 2024  Per Jensen

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <https://www.gnu.org/licenses/>.


   This script creates and maintains `dar` databases with catalogs.
"""

import argcomplete
import argparse
import fcntl
import logging
import os
import re
import signal
import sys
import threading
import shlex
import dateparser

from inputimeout import inputimeout, TimeoutOccurred


from . import __about__ as about
from dar_backup.config_settings import ConfigSettings
from dar_backup.util import init_logging
from dar_backup.util import get_config_file
from dar_backup.util import send_discord_message
from dar_backup.util import get_logger
from dar_backup.util import ArchiveName
from dar_backup.util import get_binary_info
from dar_backup.util import show_version
from dar_backup.util import get_invocation_command_line
from dar_backup.util import print_aligned_settings
from dar_backup.util import show_scriptname
from dar_backup.util import validate_directory
from dar_backup.util import archive_exists
from dar_backup.util import inspect_archive_slices
from dar_backup.util import resolve_ownership_flag
from dar_backup.util import get_backup_definition_root

from dar_backup.command_runner import CommandRunner
from dar_backup.command_runner import CommandResult
from dar_backup.util import backup_definition_completer, archive_content_completer, add_specific_archive_completer

from dataclasses import dataclass
from datetime import datetime, tzinfo
from sys import stderr
from time import time
from typing import BinaryIO, Dict, List, Tuple, Optional, cast

# Constants
SCRIPTNAME = os.path.basename(__file__)
SCRIPTPATH = os.path.realpath(__file__)
SCRIPTDIRPATH = os.path.dirname(SCRIPTPATH)
DB_SUFFIX = ".db"

# Module-level by design: tests inject real logger/runner objects via save/restore
# (see logger_runner_globals_accepted memory) — not a bug.
logger = get_logger()
runner: Optional[CommandRunner] = None


def _runner() -> CommandRunner:
    """Return the module-level CommandRunner initialized by main().

    Returns:
        The active CommandRunner instance.

    Raises:
        AssertionError: If called before main() has initialized the runner.
    """
    assert runner is not None, "CommandRunner not initialized; call main() first"  # noqa: S101 — internal invariant, not user input — module must be initialized by main()
    return runner


def _open_command_log(command: List[str]) -> Tuple[Optional[BinaryIO], Optional[threading.Lock]]:
    """Open the command_logger's log file directly and write a command header.

    Locates the file backing the current command_output_logger handler, opens it
    for appending in binary mode, and writes a timestamped "COMMAND: ..." header
    line naming the command about to run.

    Args:
        command: Command and arguments to record in the header line.

    Returns:
        A (log_file, lock) tuple, or (None, None) if the command_output_logger
        has no file-backed handler to write into.
    """
    command_logger = get_logger(command_output_logger=True)
    log_path = None
    for handler in getattr(command_logger, "handlers", []):
        if hasattr(handler, "baseFilename"):
            log_path = handler.baseFilename
            break
    if not log_path:
        return None, None
    log_file = open(log_path, "ab")
    header = (
        f"{datetime.now().astimezone().strftime('%Y-%m-%d %H:%M:%S')} - COMMAND: "
        f"{' '.join(map(shlex.quote, command))}\n"
    ).encode("utf-8", errors="replace")
    log_file.write(header)
    log_file.flush()
    return log_file, threading.Lock()


def get_db_dir(config_settings: ConfigSettings) -> str:
    """
    Return the correct directory for storing catalog databases.
    Uses manager_db_dir if set, otherwise falls back to backup_dir.
    """
    return config_settings.manager_db_dir or config_settings.backup_dir


def show_more_help() -> None:
    """Print the extended --more-help text (currently just the NAME section) to stdout."""
    help_text = f"""
NAME
    {SCRIPTNAME} - creates/maintains `dar` databases with catalogs for backup definitions
"""
    print(help_text)


def create_db(backup_def: str, config_settings: ConfigSettings, logger: logging.Logger, runner: CommandRunner) -> int:
    """Create the catalog database for a backup definition if one doesn't already exist.

    If a database file already exists: an empty (placeholder) file is treated as
    already-created and skipped; a non-empty file is checked with
    `dar_manager --check` and skipped if healthy, or renamed aside (with a
    ".corrupted.<timestamp>" suffix) and recreated if the check fails.

    Args:
        backup_def: Backup definition name (used as the database's base filename).
        config_settings: Loaded configuration providing the database directory.
        logger: Logger for status/error messages.
        runner: CommandRunner used to invoke dar_manager.

    Returns:
        0 on success (created, or already present and healthy/empty); the
        dar_manager process's non-zero return code on failure; 1 if the
        database directory itself is invalid.
    """
    db_dir = get_db_dir(config_settings)

    error = validate_directory(db_dir, "DB dir")
    if error:
        logger.error(error)
        return 1

    database = f"{backup_def}{DB_SUFFIX}"
    database_path = os.path.join(db_dir, database)

    logger.debug(f"DB directory: {db_dir}")

    if os.path.exists(database_path):
        db_size = os.path.getsize(database_path)
        if db_size == 0:
            # Empty file — freshly created placeholder, skip without checking
            logger.info(f'"{database_path}" already exists (empty), skipping creation')
            return 0
        # Non-empty db — verify integrity before deciding to skip
        check_command = ['dar_manager', '--base', database_path, '--check']
        check_process = runner.run(check_command)
        if check_process.returncode == 0:
            logger.info(f'"{database_path}" already exists and is healthy, skipping creation')
            return 0
        else:
            logger.warning(f'"{database_path}" exists but is corrupted (size={db_size}, returncode={check_process.returncode}), recreating')
            backup_path = f"{database_path}.corrupted.{int(time())}"
            os.rename(database_path, backup_path)
            logger.info(f'Corrupted database backed up to: "{backup_path}"')
            # fall through to create a fresh db below

    logger.info(f'Create catalog database: "{database_path}"')
    command = ['dar_manager', '--create', database_path]
    process = runner.run(command)
    logger.debug(f"return code from 'db created': {process.returncode}")
    if process.returncode == 0:
        logger.info(f'Database created: "{database_path}"')
    else:
        _log_command_failure(process, f'Something went wrong creating the database: "{database_path}"')

    return process.returncode


def list_catalogs(backup_def: str, config_settings: ConfigSettings, suppress_output: bool = False) -> CommandResult:
    """List catalogs from the database for the given backup definition.

    Archive names are sorted by definition then date. Unless suppress_output is
    True, each archive name is also printed to stdout.

    Args:
        backup_def: Backup definition name (identifies the catalog database).
        config_settings: Loaded configuration providing the database directory
            and command timeout.
        suppress_output: When True, do not print archive names to stdout —
            only return the CommandResult.

    Returns:
        A CommandResult containing the raw stdout/stderr and return code.
    """
    database = f"{backup_def}{DB_SUFFIX}"
    database_path = os.path.join(get_db_dir(config_settings), database)

    if not os.path.exists(database_path):
        error_msg = f'Database not found: "{database_path}"'
        logger.error(error_msg)
        return CommandResult(1, '', error_msg)

    command = ['dar_manager', '--base', database_path, '--list']
    timeout = _coerce_timeout(config_settings.command_timeout_secs)

    archive_names: List[str] = []
    archive_lines: List[str] = []

    def on_line(line: str) -> None:
        line = line.strip()
        if not line or "archive #" in line or "dar path" in line or "compression" in line:
            return
        parts = line.split("\t")
        if len(parts) >= 3:
            archive_names.append(parts[2].strip())
            archive_lines.append(line)

    result = _runner().stream_command(command, on_line, timeout=timeout)

    if result.returncode != 0:
        _log_command_failure(result, f'Error listing catalogs for: "{database_path}"')
        return result

    # Sort by definition then date; fall back gracefully for non-standard names
    def sort_key(name):
        parsed = ArchiveName.parse(name)
        if parsed:
            return (parsed.definition, parsed.as_datetime() or datetime.min)
        return (name, datetime.min)

    archive_names = sorted(archive_names, key=sort_key)

    if not suppress_output:
        for name in archive_names:
            print(name)

    return CommandResult(0, "\n".join(archive_lines), "")


def cat_no_for_name(archive: str, config_settings: ConfigSettings) -> int:
    """Find the catalog number for the given archive name.

    Args:
        archive: Archive base name to look up (e.g. "example_FULL_2026-01-01").
        config_settings: Loaded configuration providing the database directory.

    Returns:
      - the found number, if the archive catalog is present in the database
      - "-1" if the archive is not found
    """

    parsed = ArchiveName.parse(archive)
    if parsed is None:
        logger.error(f"Cannot parse archive name: '{archive}'")
        return -1
    process = list_catalogs(parsed.definition, config_settings, suppress_output=True)
    if process.returncode != 0:
        logger.error(f"Error listing catalogs for backup def: '{parsed.definition}'")
        return -1
    for line in cast(str, process.stdout).splitlines():
        # archive_lines from list_catalogs are tab-separated; parts[2] is the
        # archive base name.  An exact string comparison avoids two bugs in the
        # previous regex approach: (a) unescaped special chars in archive names
        # (e.g. '-' in dates) and (b) an un-anchored pattern that let
        # "media_FULL_…" match a line for "media2_FULL_…".
        parts = line.split("\t")
        if len(parts) >= 3 and parts[2].strip() == archive:
            num_match = re.search(r"\d+", parts[0])
            if num_match:
                logger.info(f"Found archive: '{archive}', catalog #: '{num_match.group(0)}'")
                return int(num_match.group(0))
    return -1


def list_archive_contents(archive: str, config_settings: ConfigSettings) -> int:
    """List the contents of a specific archive, given the archive name.

    Prints only actual file entries (lines beginning with '[ Saved ]').
    If none are found, a notice is printed instead.

    Args:
        archive: Archive base name whose contents should be listed.
        config_settings: Loaded configuration providing the database directory
            and command timeout.

    Returns:
        0 on success, 1 if the archive cannot be parsed/found, or the
        underlying dar_manager process's non-zero return code on failure.
    """
    parsed = ArchiveName.parse(archive)
    if parsed is None:
        logger.error(f"Cannot parse archive name: '{archive}'")
        return 1
    database = f"{parsed.definition}{DB_SUFFIX}"
    database_path = os.path.join(get_db_dir(config_settings), database)

    if not os.path.exists(database_path):
        logger.error(f'Database not found: "{database_path}"')
        return 1

    cat_no = cat_no_for_name(archive, config_settings)
    if cat_no < 0:
        logger.error(f"archive: '{archive}' not found in database: '{database_path}'")
        return 1


    command = ['dar_manager', '--base', database_path, '-u', f"{cat_no}"]
    # Respect the configured timeout, including -1 (disabled) which _coerce_timeout
    # maps to None.  A previous `or 10` here silently forced a 10s timeout even when
    # the user disabled timeouts, killing --list-archive-contents on large catalogs.
    timeout = _coerce_timeout(config_settings.command_timeout_secs)

    found = False

    def on_line(line: str) -> None:
        nonlocal found
        if line.strip().startswith("[ Saved ]"):
            print(line)
            found = True

    result = _runner().stream_command(command, on_line, timeout=timeout)

    if result.returncode != 0:
        _log_command_failure(result, f'Error listing contents of archive: "{database_path}"')
        return result.returncode

    if not found:
        print(f"[info] Archive '{archive}' is empty.")

    return result.returncode



def list_catalog_contents(catalog_number: int, backup_def: str, config_settings: ConfigSettings)  -> int:
    """List the contents of a specific catalog number in a backup definition's database.

    Args:
        catalog_number: Catalog entry number within the database (dar_manager's
            `-u` argument).
        backup_def: Backup definition name (identifies the catalog database).
        config_settings: Loaded configuration providing the database directory.

    Returns:
        0 on success, 1 if the database does not exist, or the underlying
        dar_manager process's non-zero return code on failure.
    """
    logger = get_logger()
    database = f"{backup_def}{DB_SUFFIX}"
    database_path = os.path.join(get_db_dir(config_settings), database)
    if not os.path.exists(database_path):
        logger.error(f'Catalog database not found: "{database_path}"')
        return 1
    command = ['dar_manager', '--base', database_path, '-u', f"{catalog_number}"]
    process = _runner().run(command, capture_output_limit_bytes=-1)
    if process.returncode != 0:
        _log_command_failure(process, f'Error listing catalogs for: "{database_path}"')
    else:
        print(process.stdout)
    return process.returncode


def find_file(file: str, backup_def: str, config_settings: ConfigSettings) -> int:
    """Find and print the catalog entries for a specific file across all archives.

    Args:
        file: Relative path (as stored in the catalog) to search for.
        backup_def: Backup definition name (identifies the catalog database).
        config_settings: Loaded configuration providing the database directory.

    Returns:
        0 on success, 1 if the database does not exist, or the underlying
        dar_manager process's non-zero return code on failure.
    """
    database = f"{backup_def}{DB_SUFFIX}"
    database_path = os.path.join(get_db_dir(config_settings), database)
    if not os.path.exists(database_path):
        logger.error(f'Database not found: "{database_path}"')
        return 1
    command = ['dar_manager', '--base', database_path, '-f', f"{file}"]
    process = _runner().run(command, capture_output_limit_bytes=-1)
    if process.returncode != 0:
        _log_command_failure(process, f'Error finding file: {file} in: "{database_path}"')
    else:
        print(process.stdout)
    return process.returncode


def restore_at(backup_def: str, paths: List[str], when: str, target: str, config_settings: ConfigSettings,
               verbose: bool = False, ignore_ownership: bool = True, no_deleted: bool = False) -> int:
    """
    Perform a Point-in-Time Recovery (PITR) by selecting the correct archive
    chain from the dar_manager catalog and restoring directly with dar.

    dar_manager's native ``-w DATE`` option filters by *file mtime*, not by
    *archive creation date*.  Because a POSIX rename does not update the
    renamed entry's mtime, ``dar_manager -w`` would include post-rename names
    even when restoring to a point before the rename occurred.
    ``_restore_with_dar`` instead filters by archive creation date, which
    correctly reflects the state of the backup at the requested point in time.
    See ``v2/doc/pitr-archive-date-vs-file-mtime.md`` for the full analysis.

    Args:
        backup_def: Backup definition name (prefix for the catalog DB, e.g. "example").
        paths: One or more file or directory paths as stored in the DAR catalog
            (must be relative, e.g. "tmp/unit-test/.../file.txt"; absolute paths
            or any ``..`` component are rejected — see _restore_paths_invalid_reason).
        when: Date/time string to restore "as of". Parsed via dateparser and
            converted to a datetime for archive selection. If None/empty,
            the latest version is restored.
        target: Destination directory for restore output. Required to avoid
            restoring into an unintended working directory.
        config_settings: Loaded ConfigSettings used to locate backup dirs/DB and
            timeouts.
        verbose: Unused; kept for API compatibility.
        ignore_ownership: When True, passes --comparison-field=ignore-owner to dar so
            uid/gid are not restored.  Defaults to True (safe for non-root).
        no_deleted: When True, passes --deleted=ignore to dar so deletion records in
            DIFF/INCR archives do not cause errors when restoring to an empty directory.

    Returns:
        Process return code (0 on success, non-zero on failure).
    """
    database = f"{backup_def}{DB_SUFFIX}"
    database_path = os.path.join(get_db_dir(config_settings), database)
    logger.debug(
        "PITR restore requested: backup_def=%s paths=%d when=%s target=%s db=%s",
        backup_def,
        len(paths),
        when,
        target,
        database_path,
    )

    if not os.path.exists(database_path):
        logger.error(f'Database not found: "{database_path}"')
        return 1

    if not target:
        logger.error("Restore target directory is required (--target).")
        return 1
    unsafe_reason = _restore_target_unsafe_reason(target)
    if unsafe_reason:
        logger.error(unsafe_reason)
        return 1

    invalid_paths_reason = _restore_paths_invalid_reason(paths)
    if invalid_paths_reason:
        logger.error(invalid_paths_reason)
        return 1

    # Parse date (or default to "now" for latest restore)
    date_arg = None
    parsed_date = None
    if when:
        parsed_date = _parse_when(when)
        if parsed_date:
            date_arg = parsed_date.strftime("%Y/%m/%d-%H:%M:%S")
            logger.info("Restoring files as of: %s (from input '%s')", date_arg, when)
            logger.debug("Parsed PITR timestamp: %s -> %s", when, date_arg)
        else:
            logger.error(f"Could not parse date: '{when}'")
            return 1
    else:
        # Must stay naive: compared below (and in _resolve_directory_chain /
        # PITR version selection) against naive datetimes from _parse_when()
        # and catalog-listing strptime parsing.
        parsed_date = datetime.now()  # noqa: DTZ005
        logger.info(
            "Restoring files as of: %s (no --when provided; using current time)",
            parsed_date.strftime("%Y/%m/%d-%H:%M:%S"),
        )

    # Target directory handling: pass -R and -n via dar_manager's -e option so dar
    # rebases paths and fails fast instead of prompting to overwrite.
    #
    # An exclusive flock on the target directory is held from just after makedirs
    # through to the end of _restore_with_dar().  This prevents two concurrent
    # dar-backup PITR processes from both passing the pre-existence check and then
    # interleaving dar writes into the same target — an event that would produce
    # silently corrupted output with no error logged.  The lock is cooperative:
    # it stops concurrent dar-backup processes but cannot block unrelated processes
    # that happen to write into the directory without acquiring the lock.
    lock_fd: Optional[int] = None
    try:
        if target:
            logger.debug("PITR target directory: %s (cwd=%s)", target, os.getcwd())
            if not os.path.exists(target):
                try:
                    os.makedirs(target, exist_ok=True)
                except Exception:
                    logger.exception(f"Could not create target directory '{target}'")
                    return 1
                logger.debug("Created target directory: %s", target)

            try:
                lock_fd = os.open(target, os.O_RDONLY)
            except OSError:
                logger.exception("Could not open restore target '%s' for locking", target)
                return 1
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                logger.exception(
                    "Restore target '%s' is locked by a concurrent PITR restore — "
                    "aborting to prevent silent data corruption",
                    target,
                )
                os.close(lock_fd)
                lock_fd = None
                return 1
            except OSError:
                logger.exception("Could not lock restore target '%s'", target)
                os.close(lock_fd)
                lock_fd = None
                return 1

            # Fail fast if any requested paths already exist under target.
            normalized_paths = [os.path.normpath(path.lstrip(os.sep)) for path in paths]
            if normalized_paths:
                logger.debug("Normalized restore paths count=%d sample=%s", len(normalized_paths), normalized_paths[:3])
            existing = []
            for rel_path in normalized_paths:
                if not rel_path or rel_path == ".":
                    continue
                # Checked ahead of the exists() test below: a symlink planted
                # inside the target (mid-path, or a dangling leaf that
                # os.path.exists() would report as absent) must not silently
                # redirect dar's writes outside the target.
                symlink_reason = _symlink_component_reason(target, rel_path)
                if symlink_reason:
                    logger.error(symlink_reason)
                    return 1
                candidate = os.path.join(target, rel_path)
                if os.path.exists(candidate):
                    existing.append(rel_path)
            if existing:
                sample = ", ".join(existing[:3])
                extra = f" (+{len(existing) - 3} more)" if len(existing) > 3 else ""
                logger.error(
                    "Restore target '%s' already contains path(s) to restore: %s%s. For safety, PITR restores abort "
                    "without overwriting existing files. Use a clean/empty target.",
                    target,
                    sample,
                    extra,
                )
                return 1

        # PITR restore: select archives by creation date and restore with dar directly.
        # dar_manager -w is intentionally NOT used here; see docstring for the full rationale.
        try:
            return _restore_with_dar(backup_def, paths, parsed_date, target, config_settings,
                                     ignore_ownership=ignore_ownership, no_deleted=no_deleted)
        except KeyboardInterrupt:
            msg = (
                f"PITR restore interrupted (Ctrl-C or SIGTERM) for '{backup_def}' "
                f"paths={paths} target='{target}'. "
                f"The target directory may be incomplete and must NOT be used."
            )
            logger.exception(msg)
            raise
    finally:
        if lock_fd is not None:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
                os.close(lock_fd)
            except OSError:
                pass


def _restore_paths_invalid_reason(paths: List[str]) -> Optional[str]:
    """Validate --restore-path values before they reach dar.

    Catalog paths are always relative and never contain ``..`` — anything else
    is either operator error or an attempt to make ``dar -g``/the target
    pre-checks operate outside the intended tree.

    Args:
        paths: The --restore-path values as given on the command line.

    Returns:
        None if every path is acceptable; otherwise a human-readable reason
        naming the first offending path, suitable for logging directly.
    """
    if not paths:
        return "No restore path given (--restore-path requires at least one path)."
    for path in paths:
        if not path or not path.strip():
            return "Empty restore path given (--restore-path requires relative catalog paths)."
        if os.path.isabs(path):
            return (
                f"Restore path '{path}' is absolute. Paths must be relative, exactly as stored "
                f"in the catalog (no leading '{os.sep}')."
            )
        if ".." in path.split(os.sep):
            return (
                f"Restore path '{path}' contains a '..' component. Catalog paths never do — "
                f"refusing to restore outside the target."
            )
    return None


def _symlink_component_reason(target: str, rel_path: str) -> Optional[str]:
    """Check for symlinks on rel_path's component chain inside target.

    A symlink planted inside the restore target (e.g. ``target/data -> /etc``)
    would redirect dar's writes outside the target; a dangling symlink at the
    leaf would also slip past an ``os.path.exists`` pre-check. Both are
    refused.

    Args:
        target: The restore target directory (assumed lock-checked by caller).
        rel_path: Normalized relative path about to be restored.

    Returns:
        None if no component of rel_path inside target is a symlink; otherwise
        a human-readable reason naming the offending component.
    """
    current = target
    for part in rel_path.split(os.sep):
        if not part or part == ".":
            continue
        current = os.path.join(current, part)
        if os.path.islink(current):
            return (
                f"'{current}' inside the restore target is a symlink — restoring through it "
                f"could write outside the target. Remove it or use a clean/empty target."
            )
    return None


def _restore_target_unsafe_reason(target: str) -> Optional[str]:
    """Check a PITR restore target against an allow/protect list of directory prefixes.

    Args:
        target: Restore target directory to check (need not exist yet).

    Returns:
        None if target is safe to restore into; otherwise a human-readable
        reason string suitable for logging directly.
    """
    # realpath() resolves symlinks to their canonical path so that a symlink
    # under /home pointing to /etc cannot bypass the protected-prefix check.
    # abspath() would NOT follow symlinks and would leave the check bypassable.
    # realpath() also normalises the path, so normpath() is not needed.
    target_norm = os.path.realpath(target)

    # "/tmp"/"/var/tmp" here are allow-list entries being checked against,
    # not temp file writes — S108 false positive.
    allow_prefixes = (
        "/tmp",  # noqa: S108
        "/var/tmp",  # noqa: S108
        "/home",
    )
    if target_norm in allow_prefixes or any(target_norm.startswith(prefix + os.sep) for prefix in allow_prefixes):
        return None

    protected_prefixes = (
        "/bin",
        "/sbin",
        "/usr",
        "/etc",
        "/lib",
        "/lib64",
        "/boot",
        "/proc",
        "/sys",
        "/dev",
        "/var",
        "/root",
    )
    if target_norm == "/" or target_norm in protected_prefixes:
        return f"Restore target '{target_norm}' is a protected system directory. Choose a safer location."
    if any(target_norm.startswith(prefix + os.sep) for prefix in protected_prefixes):
        return f"Restore target '{target_norm}' is under a protected system directory. Choose a safer location."

    return None


def _local_tzinfo() -> tzinfo:
    """Return the system's current local timezone (via datetime.astimezone())."""
    return cast(tzinfo, datetime.now().astimezone().tzinfo)


def _normalize_when_dt(dt: datetime) -> datetime:
    """Convert a possibly-timezone-aware datetime to naive local time.

    Args:
        dt: Datetime to normalize; may be naive or timezone-aware.

    Returns:
        dt unchanged if it is already naive; otherwise dt converted to the
        local timezone with tzinfo stripped, so it can be compared directly
        with the naive datetimes parsed from archive names.
    """
    if dt.tzinfo is None or dt.tzinfo.utcoffset(dt) is None:
        return dt
    local_tz = _local_tzinfo()
    return dt.astimezone(local_tz).replace(tzinfo=None)


def _parse_when(when: str) -> Optional[datetime]:
    """Parse a natural-language or ISO date/time string for PITR selection.

    Args:
        when: Date/time expression, e.g. "now", "2 weeks ago", "2026-01-29 15:00".

    Returns:
        A naive local datetime (see _normalize_when_dt), or None if when
        could not be parsed.
    """
    parsed = dateparser.parse(when)
    if not parsed:
        return None
    normalized = _normalize_when_dt(parsed)
    if normalized is not parsed:
        logger.debug("Normalized PITR timestamp with timezone: %s -> %s", parsed, normalized)
    return normalized


def _coerce_timeout(value: Optional[int]) -> Optional[int]:
    """Normalize a config/CLI timeout value to a valid CommandRunner timeout.

    Args:
        value: Raw timeout value from ConfigSettings.command_timeout_secs
            (may be int, str, bool, or None depending on the source).

    Returns:
        The positive integer timeout in seconds, or None to disable the
        timeout (for None, non-positive, unparseable, or bool input).
    """
    if value is None:
        return None
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return None if value <= 0 else value
    if isinstance(value, str):
        try:
            value_int = int(value)
        except ValueError:
            return None
        return None if value_int <= 0 else value_int
    return None


def _log_command_failure(result: CommandResult, context: str) -> None:
    """Log a failed command at ERROR level with context, stderr, and stdout.

    Args:
        result: CommandResult returned by runner.run() or runner.stream_command().
        context: Human-readable description of what operation failed (may include
            returncode when the caller needs it in the message).
    """
    logger.error("%s", context)
    if result.stderr:
        logger.error("stderr: %s", result.stderr)
    if result.stdout:
        logger.error("stdout: %s", result.stdout)


def _parse_archive_map(list_output: str) -> Dict[int, str]:
    """Parse `dar_manager --list` output into a catalog-number-to-path mapping.

    Args:
        list_output: Raw stdout from `dar_manager --base <db> --list`.

    Returns:
        A dict mapping each catalog entry number to its full archive base path
        (directory + basename, without the ".N.dar" slice suffix). Header and
        separator lines are skipped.
    """
    archives: Dict[int, str] = {}
    for line in list_output.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("archive #") or stripped.startswith("-"):
            continue
        # dar_manager --list is TAB-separated (num, path, basename) — the same
        # format list_catalogs() and cat_no_for_name() parse.  Split on tab, not
        # whitespace, so archive basenames or paths that contain spaces stay
        # intact: backup definition names may contain spaces (e.g. "my backup"),
        # and a plain .split() would tear "my backup_FULL_2026-01-01" into two
        # fields, yielding a wrong path whose slice then appears "missing".
        parts = [p.strip() for p in stripped.split("\t")]
        if len(parts) < 3 or not parts[0].isdigit():
            continue
        num = int(parts[0])
        basename = parts[-1]
        path = " ".join(parts[1:-1])
        archives[num] = os.path.join(path, basename)
    return archives


def _replace_path_prefix(path: str, old_prefix: str, new_prefix: str) -> Optional[str]:
    """Rewrite path's leading directory prefix, if it matches old_prefix.

    Args:
        path: Normalized directory path to check (e.g. an archive's directory).
        old_prefix: Prefix to look for at the start of path.
        new_prefix: Replacement for old_prefix.

    Returns:
        The rewritten path if path equals old_prefix or is nested under it;
        otherwise None (no match, path is left alone by the caller).
    """
    old_norm = os.path.normpath(old_prefix)
    new_norm = os.path.normpath(new_prefix)
    if path == old_norm:
        return new_norm
    if path.startswith(old_norm + os.sep):
        suffix = path[len(old_norm):]
        return os.path.normpath(new_norm + suffix)
    return None


def relocate_archive_paths(
    backup_def: str,
    old_prefix: str,
    new_prefix: str,
    config_settings: ConfigSettings,
    dry_run: bool = False,
) -> int:
    """Rewrite an archive path prefix in place across a backup definition's catalog DB.

    Used when archives have moved (or a mountpoint changed) after the catalog
    was built, so the DB's absolute archive paths no longer match reality.
    Lists all catalog entries, finds those whose directory starts with
    old_prefix, and rewrites each matching entry via `dar_manager -p`.

    Args:
        backup_def: Backup definition name (identifies the catalog database).
        old_prefix: Directory path prefix to replace.
        new_prefix: Replacement directory path prefix.
        config_settings: Loaded configuration providing the database directory
            and command timeout.
        dry_run: If True, log what would change without calling dar_manager.

    Returns:
        0 on success (including "nothing matched"); 1 if the database is
        missing, the catalog could not be listed, or any individual path
        update failed.
    """
    database = f"{backup_def}{DB_SUFFIX}"
    database_path = os.path.join(get_db_dir(config_settings), database)
    if not os.path.exists(database_path):
        logger.error(f'Database not found: "{database_path}"')
        return 1

    timeout = _coerce_timeout(config_settings.command_timeout_secs)
    list_result = _runner().run(["dar_manager", "--base", database_path, "--list"], timeout=timeout)
    if list_result.returncode != 0:
        _log_command_failure(list_result, f'Error listing catalogs for: "{database_path}"')
        return list_result.returncode

    archive_map = _parse_archive_map(cast(str, list_result.stdout) or "")
    if not archive_map:
        logger.error("Could not determine archive list from dar_manager output.")
        return 1

    updates: List[Tuple[int, str, str, str]] = []
    for catalog_no, full_path in archive_map.items():
        current_dir = os.path.dirname(full_path)
        new_dir = _replace_path_prefix(current_dir, old_prefix, new_prefix)
        if new_dir and new_dir != current_dir:
            updates.append((catalog_no, current_dir, new_dir, os.path.basename(full_path)))

    if not updates:
        logger.info(
            "No archive paths matched '%s' in database '%s'.",
            os.path.normpath(old_prefix),
            database_path,
        )
        return 0

    logger.info(
        "Updating %d archive path(s) from '%s' to '%s' in database '%s'.",
        len(updates),
        os.path.normpath(old_prefix),
        os.path.normpath(new_prefix),
        database_path,
    )
    failures = 0
    for catalog_no, current_dir, new_dir, basename in updates:
        logger.info("Archive #%d (%s): %s -> %s", catalog_no, basename, current_dir, new_dir)
        if dry_run:
            continue
        result = _runner().run(
            ["dar_manager", "--base", database_path, "-p", str(catalog_no), new_dir],
            timeout=timeout,
        )
        if result.returncode != 0:
            failures += 1
            _log_command_failure(
                result,
                f"Failed updating archive #{catalog_no} path to '{new_dir}' (returncode={result.returncode}).",
            )

    if failures:
        logger.error("Relocate completed with %d failure(s).", failures)
        return 1
    logger.info("Relocate completed successfully.")
    return 0


def _parse_archive_info(archive_map: Dict[int, str]) -> List[Tuple[int, datetime, str]]:
    """Extract (catalog number, archive date, archive type) from an archive map.

    Args:
        archive_map: Mapping of catalog number to archive base path, as
            returned by _parse_archive_map.

    Returns:
        A list of (catalog_no, archive_date, archive_type) tuples, one per
        entry whose basename matches the standard archive naming convention.
        Entries that don't parse (unexpected name format) are skipped.
    """
    info: List[Tuple[int, datetime, str]] = []
    for catalog_no, path in archive_map.items():
        base = os.path.basename(path)
        parsed = ArchiveName.parse(base)
        if parsed is None:
            continue
        archive_date = parsed.as_datetime()
        if archive_date is None:
            continue
        info.append((catalog_no, archive_date, parsed.archive_type))
    return info


# Backup-sequence ordering used to tie-break archives that share a date
# (date-only archive names): a DIFF taken the same day as its FULL sorts after
# it, an INCR after its DIFF — mirroring the order the backups were taken.
# Shared by _select_archive_chain (directories) and _resolve_pitr_path (files)
# so both PITR branches order same-date archives identically.
_ARCHIVE_TYPE_ORDER: Dict[str, int] = {"FULL": 0, "DIFF": 1, "INCR": 2}


def _select_archive_chain(archive_info: List[Tuple[int, datetime, str]], when_dt: datetime) -> List[int]:
    """Select the FULL -> DIFF -> INCR archive chain that restores state as of when_dt.

    Only archives with a date at or before when_dt are eligible. Picks the
    latest eligible FULL as the chain's base, then the latest eligible DIFF
    taken after that FULL, then the latest eligible INCR taken after that DIFF
    (or after the FULL, if no DIFF qualifies) — mirroring how DIFF/INCR
    backups are always taken relative to the most recent FULL/DIFF.

    Args:
        archive_info: Parsed catalog entries as (catalog_no, date, archive_type),
            as returned by _parse_archive_info.
        when_dt: Restore to the state at this point in time.

    Returns:
        Catalog numbers in apply order: [FULL], optionally + [DIFF], optionally
        + [INCR]. Empty if no FULL archive is at or before when_dt.
    """
    order = _ARCHIVE_TYPE_ORDER
    candidates = [
        (catalog_no, date, archive_type)
        for catalog_no, date, archive_type in archive_info
        if date <= when_dt
    ]
    candidates.sort(key=lambda item: (item[1], order.get(item[2], 99), item[0]))
    last_full = None
    last_full_key = None
    for catalog_no, date, archive_type in candidates:
        if archive_type == "FULL":
            last_full = catalog_no
            last_full_key = (date, order["FULL"], catalog_no)
    if last_full is None:
        return []
    assert last_full_key is not None  # noqa: S101 — internal invariant — set together with last_full earlier in the loop

    last_diff = None
    last_diff_key = None
    for catalog_no, date, archive_type in candidates:
        key = (date, order.get(archive_type, 99), catalog_no)
        if key <= last_full_key:
            continue
        if archive_type == "DIFF":
            last_diff = catalog_no
            last_diff_key = key

    base_key = last_diff_key or last_full_key
    last_incr = None
    for catalog_no, date, archive_type in candidates:
        key = (date, order.get(archive_type, 99), catalog_no)
        if key <= base_key:
            continue
        if archive_type == "INCR":
            last_incr = catalog_no

    chain = [last_full]
    if last_diff is not None:
        chain.append(last_diff)
    if last_incr is not None:
        chain.append(last_incr)
    return chain


def _is_directory_path(path: str, root: str = os.sep) -> bool:
    """
    Check if path refers to an existing directory on the filesystem.

    Args:
        path: Relative path, as stored in the DAR catalog (i.e. relative to
            the backup definition's -R). May also be given as an absolute
            path, in which case it is resolved as-is, ignoring root.
        root: The backup definition's -R root. Defaults to "/" — the
            assumption held (incorrectly, for any other -R) before this
            parameter was added.

    Returns:
        True if the path exists as a directory on the filesystem.
    """
    return os.path.isdir(os.path.join(root, path.lstrip(os.sep)))


def _is_directory_in_archive(
    path: str,
    archive_path: str,
    runner: "CommandRunner",
    timeout: Optional[int],
) -> bool:
    """
    Check if path is a directory by inspecting dar -l output for the archive.

    dar -l output includes permission strings like ``drwxr-xr-x`` for
    directories or ``-rw-r--r--`` for regular files.  The leading ``d``
    distinguishes directories.

    Args:
        path: The relative path to check.
        archive_path: Full path to the dar archive (without slice suffix).
        runner: CommandRunner instance.
        timeout: Command timeout in seconds, or None for no timeout.

    Returns:
        True if the path appears as a directory in the archive.
    """
    try:
        result = runner.run(
            ['dar', '-l', archive_path, '-g', path, '--noconf', '-Q'],
            timeout=timeout,
        )
    except KeyboardInterrupt:
        msg = (
            f"PITR restore interrupted (Ctrl-C or SIGTERM) while checking if "
            f"'{path}' is a directory in '{archive_path}'. "
            f"Restore is incomplete."
        )
        logger.exception(msg)
        raise
    if result.returncode != 0:
        return False
    # Look for permission string starting with 'd' on a line ending with the path.
    # dar -l format example:
    #   [Saved][-] [---][ 0%][ ] drwxr-xr-x user group 4 kio ... path/name
    for line in cast(str, result.stdout).splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        # The permission field is whitespace-delimited. A trailing \b must NOT
        # be used here: modes ending in '-' (700 'drwx------', 750 'drwxr-x---',
        # 770 'drwxrwx---') have no word boundary between the final '-' and the
        # following space, so \b silently failed to match exactly those private
        # directories. The optional '+' tolerates an ACL marker suffix.
        if not re.search(r'(?:^|\s)d[rwxXsStT-]{9}\+?(?=\s|$)', stripped):
            continue
        candidate = stripped.rstrip()
        if _line_path_matches(candidate, path):
            return True
    return False


def _line_path_matches(line: str, path: str) -> bool:
    """Return True if *line* ends with *path* at a path/field boundary.

    A plain ``line.endswith(path)`` would let a query of "foo/bar" match a
    directory line ending in "otherfoo/bar".  This requires that the character
    immediately before the match is the start of the line, a path separator, or
    whitespace (dar prints the path as the final, space-separated field), so a
    match only counts on a real path-component boundary.

    Args:
        line: A single, right-stripped dar -l output line.
        path: The catalog-relative path being looked for.

    Returns:
        True if *line* ends with *path* on a component boundary.
    """
    if not path or not line.endswith(path):
        return False
    preceding = line[: len(line) - len(path)]
    return preceding == "" or preceding[-1] in ("/", " ", "\t")


def _detect_directory(
    path: str,
    archive_map: Dict[int, str],
    archive_info: List[Tuple[int, datetime, str]],
    runner: "CommandRunner",
    timeout: Optional[int],
    root: str = os.sep,
    when_dt: Optional[datetime] = None,
) -> bool:
    """
    Determine whether *path* is a directory using filesystem check first,
    then falling back to dar catalog inspection.

    The fallback inspects the archives of the chain selected for *when_dt*
    (newest chain member first), NOT simply the newest FULL in the catalog:
    a directory deleted before the newest FULL — or created only in a DIFF/
    INCR after its chain's FULL — exists in the when-selected chain but not
    in the newest FULL, and inspecting the wrong archive would misclassify
    it as a file (restoring it from a single archive instead of the chain).

    Args:
        path: Relative path to check.
        archive_map: Mapping of catalog numbers to archive paths.
        archive_info: Parsed archive info (catalog_no, datetime, type).
        runner: CommandRunner instance.
        timeout: Command timeout in seconds, or None for no timeout.
        root: The backup definition's -R root, used to resolve *path* against
            the live filesystem. Defaults to "/".
        when_dt: Restore-to timestamp used to pick which archives to inspect.
            When None (or when no FULL exists at or before it), the newest
            FULL overall is inspected as a classification-only fallback —
            archive *selection* later reports its own precise error.

    Returns:
        True if the path is a directory.
    """
    # Fast path: check filesystem
    if _is_directory_path(path, root):
        return True

    # Fallback: inspect archives via dar -l. Prefer the chain selected for
    # when_dt; inspect newest-first (INCR/DIFF are smaller than the FULL, and
    # a directory created after the chain's FULL only appears in them).
    inspect_nos: List[int] = []
    if when_dt is not None:
        inspect_nos = list(reversed(_select_archive_chain(archive_info, when_dt)))
    if not inspect_nos:
        full_archives = [
            (no, dt) for no, dt, atype in archive_info if atype == "FULL"
        ]
        if not full_archives:
            return False
        # Classification-only fallback: the most recent FULL archive.
        full_archives.sort(key=lambda item: item[1], reverse=True)
        inspect_nos = [full_archives[0][0]]

    for catalog_no in inspect_nos:
        archive_path = archive_map.get(catalog_no)
        if not archive_path:
            # Missing map entries are a selection-time error, not a
            # classification concern — try the next chain member.
            continue
        if _is_directory_in_archive(path, archive_path, runner, timeout):
            return True
    return False


def _resolve_backup_root(config_settings: ConfigSettings, backup_def: str) -> str:
    """Determine the -R root used by a backup definition, for directory detection.

    Args:
        config_settings: Loaded configuration, used to locate the backup
            definition file (BACKUP.D_DIR/<backup_def>).
        backup_def: Backup definition name.

    Returns:
        The -R root path, or "/" if it could not be determined (the file is
        missing/unreadable or has no -R line) — the previously-assumed
        default, kept as a safe fallback rather than raising.
    """
    backup_def_path = os.path.join(config_settings.backup_d_dir, backup_def)
    root = get_backup_definition_root(backup_def_path)
    if root is None:
        logger.warning(
            "Could not determine -R root for backup definition '%s'; "
            "assuming '/' for directory detection.",
            backup_def,
        )
        return os.sep
    return root



def _format_chain_item(
    catalog_no: int,
    info_by_no: Dict[int, Tuple[datetime, str]],
    status: str,
) -> str:
    """Format one archive chain entry for the --pitr-report display.

    Args:
        catalog_no: Catalog number of the chain entry.
        info_by_no: Maps catalog number to (archive_date, archive_type).
        status: Availability status to display, e.g. "ok" or "missing".

    Returns:
        A display string like "#3 DIFF@2026-01-15 10:00:00 [ok]", or
        "#3 [unknown] [ok]" if catalog_no has no entry in info_by_no.
    """
    info = info_by_no.get(catalog_no)
    if info:
        dt, archive_type = info
        return f"#{catalog_no} {archive_type}@{dt} [{status}]"
    return f"#{catalog_no} [unknown] [{status}]"


def _describe_archive(
    catalog_no: int,
    archive_map: Dict[int, str],
    info_by_no: Dict[int, Tuple[datetime, str]],
) -> str:
    """Format one archive for a PITR restore log message.

    Args:
        catalog_no: Catalog number of the archive.
        archive_map: Maps catalog number to archive base path.
        info_by_no: Maps catalog number to (archive_date, archive_type).

    Returns:
        A display string like "#3 DIFF@2026-01-15 10:00:00 archive_basename",
        or "#3 unknown" if catalog_no is missing from archive_map.
    """
    archive_path = archive_map.get(catalog_no)
    base = os.path.basename(archive_path) if archive_path else "unknown"
    info = info_by_no.get(catalog_no)
    if info:
        dt, archive_type = info
        dt_str = dt.strftime("%Y-%m-%d %H:%M:%S")
        return f"#{catalog_no} {archive_type}@{dt_str} {base}"
    return f"#{catalog_no} {base}"


def _missing_chain_elements(chain: List[int], archive_map: Dict[int, str]) -> List[str]:
    """Check which archives in a restore chain are missing from disk or the catalog.

    Args:
        chain: Catalog numbers in apply order, as returned by _select_archive_chain.
        archive_map: Maps catalog number to archive base path.

    Returns:
        A list of human-readable descriptions of missing chain elements
        (either "catalog #N missing from archive map" or an absent
        "<archive>.1.dar" slice path); empty if the preliminary check passes.
        PITR callers additionally run full slice-set validation before restore.
    """
    missing = []
    for catalog_no in chain:
        archive_path = archive_map.get(catalog_no)
        if not archive_path:
            missing.append(f"catalog #{catalog_no} missing from archive map")
            continue
        if not archive_exists(archive_path):
            missing.append(f"{archive_path}.1.dar")
    return missing


_PITR_SLICE_PROBE_PATH = ".dar-backup-internal-slice-validation-probe"


def _pitr_archive_sequence_error(archive_path: str) -> Optional[str]:
    """Return why DAR slice filenames do not form a sequence from slice 1.

    Args:
        archive_path: DAR archive base path without a slice suffix.

    Returns:
        None for one unambiguous numeric sequence beginning at 1; otherwise a
        human-readable failure reason.
    """
    try:
        inventory = inspect_archive_slices(archive_path)
    except (OSError, ValueError) as exc:
        return f"Could not inspect DAR slices for '{archive_path}': {exc}"

    if not inventory.slice_paths:
        return f"Archive '{archive_path}' has no DAR slices"
    if inventory.invalid_numbers:
        numbers = ", ".join(str(number) for number in inventory.invalid_numbers)
        return f"Archive '{archive_path}' has invalid DAR slice number(s): {numbers}"
    if inventory.duplicate_numbers:
        numbers = ", ".join(str(number) for number in inventory.duplicate_numbers)
        return f"Archive '{archive_path}' has duplicate DAR slice number(s): {numbers}"
    if inventory.missing_numbers:
        missing = ", ".join(str(number) for number in inventory.missing_numbers)
        found = ", ".join(str(number) for number in inventory.slice_numbers)
        return (
            f"Archive '{archive_path}' has an incomplete DAR slice sequence: "
            f"missing slice number(s) {missing}; found {found}"
        )
    return None


def _pitr_archive_validation_error(
    archive_path: str,
    command_runner: CommandRunner,
    timeout: Optional[int],
    darrc_path: Optional[str],
) -> Optional[str]:
    """Return why a DAR archive is unsafe for PITR, or None when usable.

    The filesystem inventory detects a missing first or interior slice. A
    filtered ``dar -l`` then loads the archive catalogue without emitting its
    contents; DAR rejects the highest available slice when it is not marked as
    the archive's final slice. Together these checks prove slice completeness
    without the full payload scan performed by ``dar -t``.

    Args:
        archive_path: DAR archive base path without a slice suffix.
        command_runner: CommandRunner used for the final-slice catalogue probe.
        timeout: Command timeout in seconds, or None to disable it.
        darrc_path: Optional darrc containing the restore-options section.

    Returns:
        None when the slice sequence is complete and DAR accepts the final
        catalogue; otherwise a human-readable failure reason.
    """
    sequence_error = _pitr_archive_sequence_error(archive_path)
    if sequence_error:
        return sequence_error

    cmd = [
        'dar', '-l', archive_path, '-g', _PITR_SLICE_PROBE_PATH,
        '-q', '--noconf', '-Q',
    ]
    if darrc_path:
        cmd.extend(['-B', darrc_path, 'restore-options'])
    result = command_runner.run(
        cmd,
        timeout=timeout,
        capture_output_limit_bytes=8192,
        log_output=False,
    )
    if result.returncode == 0:
        return None

    detail = (cast(str, result.stderr) or cast(str, result.stdout) or "").strip()
    detail_suffix = f": {detail}" if detail else ""
    return (
        f"Archive '{archive_path}' failed the DAR final-slice catalogue check "
        f"(dar -l rc={result.returncode}){detail_suffix}"
    )


def _cached_pitr_archive_validation_error(
    archive_path: str,
    command_runner: CommandRunner,
    timeout: Optional[int],
    darrc_path: Optional[str],
    cache: Dict[str, Optional[str]],
) -> Optional[str]:
    """Validate a PITR archive once per manager invocation.

    Args:
        archive_path: DAR archive base path without a slice suffix.
        command_runner: CommandRunner used for DAR catalogue probes.
        timeout: Command timeout in seconds, or None to disable it.
        darrc_path: Optional darrc containing the restore-options section.
        cache: Per-invocation mapping of archive paths to validation results.

    Returns:
        Cached or newly computed validation error; None means the archive is
        safe to use.
    """
    if archive_path not in cache:
        cache[archive_path] = _pitr_archive_validation_error(
            archive_path,
            command_runner,
            timeout,
            darrc_path,
        )
    return cache[archive_path]


def _resolve_directory_chain(
    archive_info: List[Tuple[int, datetime, str]],
    when_dt: datetime,
    archive_map: Dict[int, str],
) -> Tuple[List[int], List[str]]:
    """Select and validate the PITR restore chain for a directory path.

    Combines archive chain selection with on-disk availability checking so
    both _pitr_chain_report and _restore_with_dar use identical logic.

    Args:
        archive_info: Parsed catalog entries as (catalog_no, date, archive_type).
        when_dt: Restore to the state at this point in time.
        archive_map: Maps catalog number to archive base path on disk.

    Returns:
        A (chain, missing) tuple. chain is the ordered list of catalog numbers
        to apply (empty when no FULL archive covers when_dt). missing lists any
        chain elements whose .1.dar slices are absent on disk; PITR execution
        performs complete slice-set validation separately.
    """
    chain = _select_archive_chain(archive_info, when_dt)
    if not chain:
        return [], []
    return chain, _missing_chain_elements(chain, archive_map)


@dataclass
class _PitrPathPlan:
    """The archive-selection decision for a single PITR path.

    Produced by _resolve_pitr_path() and consumed by BOTH the dry-run report
    (_pitr_chain_report) and the real restore (_restore_with_dar), so the two can
    never disagree on directory-vs-file detection or which archives are selected.
    Each caller keeps its own logging/execution; only the *decision* is shared.

    Attributes:
        path: The catalog-relative path this plan describes.
        is_directory: True if restored via a FULL→DIFF→INCR chain; False if a
            single file version is selected.
        chain: Ordered catalog numbers to apply for a directory restore; empty
            for a file.
        chain_missing: Chain slices absent from disk or the catalog (directory
            restores only, as returned by _resolve_directory_chain); empty for a
            file or when the whole chain is present.
        candidates: (catalog_no, archive_date) archives that saved the path's
            data, filtered to archive creation date at or before the requested
            time and ordered newest archive first (file restores only); empty
            for a directory. Selection is by archive date — the PITR contract —
            not by the file mtimes that `dar_manager -f` reports; archives
            listing the file only as "present" (unchanged, no data) are never
            candidates.
        error: None when a target was selected; otherwise a human-readable reason
            selection failed (no FULL archive covers the time, no archive at or
            before the time recorded the path, or a recorded version could not
            be resolved to a dated archive).
    """
    path: str
    is_directory: bool
    chain: List[int]
    chain_missing: List[str]
    candidates: List[Tuple[int, datetime]]
    error: Optional[str]


def _resolve_pitr_path(
    path: str,
    when_dt: datetime,
    database_path: str,
    archive_map: Dict[int, str],
    archive_info: List[Tuple[int, datetime, str]],
    runner: "CommandRunner",
    timeout: Optional[int],
    root: str,
) -> _PitrPathPlan:
    """Decide which archive(s) restore *path* to its state at *when_dt*.

    Single source of truth for PITR directory-vs-file detection and archive
    chain/version selection.  _pitr_chain_report (dry run) and _restore_with_dar
    (real restore) both call this so their decisions can never drift; each then
    applies its own logging and (for restore) dar execution to the result.

    Both branches honor the PITR contract: selection is by archive creation
    date (parsed from the archive name) at or before when_dt.  For files,
    `dar_manager -f` only identifies which archives saved the path's data;
    its mtime column plays no part in selection (see
    doc/pitr-archive-date-vs-file-mtime.md — mtime-based selection would
    resurrect renamed/edited content from archives created after when_dt).

    Args:
        path: Catalog-relative path to resolve.
        when_dt: Restore-to timestamp (naive local, as used everywhere in PITR).
        database_path: Path to the backup definition's catalog DB (for the
            ``dar_manager -f`` file-version lookup).
        archive_map: Catalog-number → archive base path.
        archive_info: Parsed (catalog_no, date, type) catalog entries.
        runner: CommandRunner used for directory detection and file-version lookup.
        timeout: Command timeout in seconds, or None to disable.
        root: The backup definition's -R root, for filesystem directory detection.

    Returns:
        A _PitrPathPlan describing the selected chain (directory) or ordered
        candidates (file), any missing chain slices, and an error string when
        nothing could be selected.
    """
    is_directory = _detect_directory(path, archive_map, archive_info, runner, timeout, root, when_dt=when_dt)
    if is_directory:
        chain, chain_missing = _resolve_directory_chain(archive_info, when_dt, archive_map)
        if not chain:
            return _PitrPathPlan(
                path=path, is_directory=True, chain=[], chain_missing=[], candidates=[],
                error=f"No FULL archive found at or before {when_dt} for '{path}'",
            )
        return _PitrPathPlan(
            path=path, is_directory=True, chain=chain, chain_missing=chain_missing,
            candidates=[], error=None,
        )

    file_result = runner.run(['dar_manager', '--base', database_path, '-f', path], timeout=timeout)
    versions = _parse_file_versions(cast(str, file_result.stdout))

    # dar_manager -f exit codes are unreliable signals (verified empirically):
    # a path absent from the catalog exits 2 with "Non existent file in
    # database" (a benign "no versions" answer), while a corrupted/unreadable
    # database can exit 0 with "Corrupted database" text on stdout when no
    # terminal is attached. Distinguish the benign case by its marker; treat
    # every other nonzero exit or error marker as a failed lookup — selecting
    # from partial output could silently restore the wrong version.
    combined_output = f"{cast(str, file_result.stdout) or ''}\n{cast(str, file_result.stderr) or ''}"
    benign_absent = "Non existent file in database" in combined_output
    if not benign_absent and (
        file_result.returncode != 0
        or "Corrupted database" in combined_output
        or "FATAL error" in combined_output
    ):
        detail = (cast(str, file_result.stderr) or cast(str, file_result.stdout) or "").strip()
        return _PitrPathPlan(
            path=path, is_directory=False, chain=[], chain_missing=[], candidates=[],
            error=(
                f"Version lookup failed for '{path}': dar_manager -f exited with "
                f"rc={file_result.returncode}: {detail}"
            ),
        )

    # PITR contract: select by ARCHIVE creation date, exactly like directory
    # chains — never by the recorded file mtime that `dar_manager -f` reports.
    # A version whose mtime predates when_dt may live in an archive created
    # AFTER when_dt (a rename or edit captured by a later DIFF); the contract
    # says that archive did not exist at when_dt and must be excluded.
    # `dar_manager -f` is used only to learn WHICH archives saved the path's
    # data (its "present" entries — unchanged file, no data — are already
    # filtered out by _parse_file_versions).
    info_by_no = {catalog_no: (dt, archive_type) for catalog_no, dt, archive_type in archive_info}
    unresolved = sorted(num for num, _mtime in versions if num not in info_by_no)
    if unresolved:
        nums = ", ".join(f"#{num}" for num in unresolved)
        return _PitrPathPlan(
            path=path, is_directory=False, chain=[], chain_missing=[], candidates=[],
            error=(
                f"Cannot restore '{path}': catalog number(s) {nums} recorded versions of the "
                f"path but could not be resolved to a dated archive from `dar_manager --list` "
                f"output (missing entry or non-standard archive name). PITR cannot order these "
                f"versions by archive date safely — fix the catalog or archive names first."
            ),
        )

    eligible = [
        (num, info_by_no[num][0], info_by_no[num][1])
        for num, _mtime in versions
        if info_by_no[num][0] <= when_dt
    ]
    # Newest archive first; same-date archives tie-break by backup-sequence
    # order then catalog number, matching _select_archive_chain's ordering.
    eligible.sort(
        key=lambda item: (item[1], _ARCHIVE_TYPE_ORDER.get(item[2], 99), item[0]),
        reverse=True,
    )
    candidates = [(num, dt) for num, dt, _archive_type in eligible]
    if not candidates:
        return _PitrPathPlan(
            path=path, is_directory=False, chain=[], chain_missing=[], candidates=[],
            error=f"No archive version found for '{path}' at or before {when_dt}",
        )
    return _PitrPathPlan(
        path=path, is_directory=False, chain=[], chain_missing=[],
        candidates=candidates, error=None,
    )


def _pitr_chain_report(
    backup_def: str,
    paths: List[str],
    when: str,
    config_settings: ConfigSettings,
) -> int:
    """Report the PITR archive chain that would be used for a restore at `when`.

    Dry-run counterpart of restore_at()/_restore_with_dar(): performs the same
    directory-vs-file detection and archive chain/version selection, logging
    what would be used, but never invokes dar.

    Args:
        backup_def: Backup definition name (identifies the catalog database).
        paths: One or more file or directory paths as stored in the catalog.
        when: Date/time string to report "as of" (parsed via _parse_when).
        config_settings: Loaded configuration used to locate the catalog
            database and command timeout.

    Returns:
        0 if a usable chain/version was found for every path; 1 if `when` is
        missing or unparseable, any path is absolute/empty/contains ``..``,
        the catalog can't be read, or any path's chain/version could not be
        fully resolved.
    """
    if not when:
        logger.error("PITR report requires --when.")
        return 1

    invalid_paths_reason = _restore_paths_invalid_reason(paths)
    if invalid_paths_reason:
        logger.error(invalid_paths_reason)
        return 1

    parsed_date = _parse_when(when)
    if not parsed_date:
        logger.error(f"Could not parse date: '{when}'")
        return 1

    database = f"{backup_def}{DB_SUFFIX}"
    database_path = os.path.join(get_db_dir(config_settings), database)
    timeout = _coerce_timeout(config_settings.command_timeout_secs)
    root = _resolve_backup_root(config_settings, backup_def)
    list_result = _runner().run(['dar_manager', '--base', database_path, '--list'], timeout=timeout)
    # A failed listing may still emit parseable partial output — selecting from
    # a truncated archive list could silently pick the wrong (older) archive,
    # so fail instead of parsing whatever arrived.
    if list_result.returncode != 0:
        _log_command_failure(list_result, f'Error listing archive catalog for: "{database_path}"')
        return 1
    archive_map = _parse_archive_map(cast(str, list_result.stdout))
    if not archive_map:
        logger.error("Could not determine archive list from dar_manager output.")
        return 1

    archive_info = _parse_archive_info(archive_map)
    info_by_no = {catalog_no: (dt, archive_type) for catalog_no, dt, archive_type in archive_info}
    darrc_path = _guess_darrc_path(config_settings)
    validation_cache: Dict[str, Optional[str]] = {}
    failures = 0
    successes = 0

    for path in paths:
        # Shared detect/select decision (identical to what _restore_with_dar uses).
        plan = _resolve_pitr_path(
            path, parsed_date, database_path, archive_map, archive_info, _runner(), timeout, root
        )
        if plan.is_directory:
            logger.debug("Path '%s' detected as directory — using archive chain restore.", path)
            if plan.error:
                logger.error(plan.error)
                failures += 1
                continue
            chain_display_parts = []
            chain_errors = []
            for catalog_no in plan.chain:
                archive_path = archive_map.get(catalog_no)
                if not archive_path:
                    status = "missing"
                    chain_errors.append(f"catalog #{catalog_no} missing from archive map")
                else:
                    validation_error = _cached_pitr_archive_validation_error(
                        archive_path,
                        _runner(),
                        timeout,
                        darrc_path,
                        validation_cache,
                    )
                    status = "invalid" if validation_error else "ok"
                    if validation_error:
                        chain_errors.append(validation_error)
                chain_display_parts.append(_format_chain_item(catalog_no, info_by_no, status))
            logger.info("PITR chain report for '%s': %s", path, ", ".join(chain_display_parts))
            if chain_errors:
                for item in chain_errors:
                    if item.startswith("catalog #"):
                        logger.error("PITR chain report missing archive: %s", item)
                    else:
                        logger.error("PITR chain report unusable archive: %s", item)
                failures += 1
            else:
                successes += 1
            continue

        logger.info(
            "PITR chain report candidates for '%s': %s",
            path,
            ", ".join(f"#{num}@{dt}" for num, dt in plan.candidates) or "<none>",
        )
        if plan.error:
            logger.error(plan.error)
            failures += 1
            continue
        catalog_no, dt = plan.candidates[0]
        archive_path = archive_map.get(catalog_no)
        if not archive_path:
            logger.error("PITR chain report missing archive map entry for #%d (%s)", catalog_no, path)
            failures += 1
            continue
        validation_error = _cached_pitr_archive_validation_error(
            archive_path,
            _runner(),
            timeout,
            darrc_path,
            validation_cache,
        )
        if validation_error:
            logger.error("PITR chain report unusable archive: %s", validation_error)
            failures += 1
            continue
        logger.info("PITR chain report selected archive #%d (%s) for '%s'.", catalog_no, dt, path)
        successes += 1

    logger.info("PITR chain report summary: %d ok, %d failed.", successes, failures)
    return 0 if failures == 0 else 1


def _parse_file_versions(file_output: str) -> List[Tuple[int, datetime]]:
    """Parse `dar_manager -f <path>` output into (catalog number, mtime) pairs.

    Only entries whose data status is ``saved`` are returned: those are the
    archives that actually hold the file's data.  A DIFF/INCR that did not
    re-save an unchanged file lists it as ``present`` — restoring from such an
    archive would extract nothing (dar still exits 0), so ``present`` entries
    must never become restore candidates.

    Args:
        file_output: Raw stdout from `dar_manager --base <db> -f <path>`,
            listing every catalog entry that recorded the given file, one
            per line with a ctime-style timestamp and a data status (e.g.
            "1  Fri Mar 21 06:56:21 2026  saved").

    Returns:
        A list of (catalog_no, recorded_mtime) tuples for every ``saved``
        line that matches the expected format; ``present`` and other
        non-matching lines are skipped.
        Note: PITR selection uses only the catalog numbers — the recorded
        mtimes are informational (see _resolve_pitr_path).
    """
    versions: List[Tuple[int, datetime]] = []
    for line in file_output.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        match = re.match(
            r"^(\d+)\s+([A-Za-z]{3}\s+[A-Za-z]{3}\s+\d+\s+\d{2}:\d{2}:\d{2}\s+\d{4})\s+saved\b",
            stripped,
        )
        if not match:
            continue
        try:
            catalog_no = int(match.group(1))
            dt = datetime.strptime(match.group(2), "%a %b %d %H:%M:%S %Y")
        except Exception as exc:  # noqa: BLE001 — logs with context and continues
            logger.debug("Could not parse catalog version line '%s': %s", stripped, exc)
            continue
        versions.append((catalog_no, dt))
    return versions


def _guess_darrc_path(config_settings: ConfigSettings) -> Optional[str]:
    """Locate a .darrc file to pass to dar for PITR restore commands.

    Checks next to the config file first, then falls back to the package's
    installed default .darrc.

    Args:
        config_settings: Loaded configuration providing the config file path.

    Returns:
        Path to a usable .darrc file, or None if neither location has one.
    """
    config_dir = os.path.dirname(config_settings.config_file)
    candidate = os.path.join(config_dir, ".darrc")
    if os.path.exists(candidate):
        return candidate
    script_dir = os.path.dirname(os.path.realpath(__file__))
    fallback = os.path.join(script_dir, ".darrc")
    if os.path.exists(fallback):
        return fallback
    return None


def _restore_with_dar(backup_def: str, paths: List[str], when_dt: datetime, target: str,
                      config_settings: ConfigSettings, ignore_ownership: bool = True,
                      no_deleted: bool = False) -> int:
    """
    Restore specific paths by selecting the best matching archive (<= when_dt)
    using dar_manager metadata, then invoking dar directly.

    This is a fallback for PITR when dar_manager reports that nothing could be
    restored for a dated request. It inspects the catalog to choose an archive
    for each path and restores into the provided target directory.

    File paths fail fast: only the newest version at or before when_dt is
    tried. If its archive is missing or dar fails to extract it, the path is
    reported as failed — there is deliberately no fallback to an older
    version, which would silently restore stale data with a success exit code.

    Args:
        backup_def: Backup definition name.
        paths: Paths to restore from the catalog.
        when_dt: Restore to the state at this point in time.
        target: Destination directory.
        config_settings: Loaded configuration.
        ignore_ownership: When True, passes --comparison-field=ignore-owner to dar.
        no_deleted: When True, passes --deleted=ignore to dar so deletion records
            in DIFF/INCR archives do not cause errors.
    """
    database = f"{backup_def}{DB_SUFFIX}"
    database_path = os.path.join(get_db_dir(config_settings), database)
    timeout = _coerce_timeout(config_settings.command_timeout_secs)
    root = _resolve_backup_root(config_settings, backup_def)
    list_result = _runner().run(['dar_manager', '--base', database_path, '--list'], timeout=timeout)
    # A failed listing may still emit parseable partial output — selecting from
    # a truncated archive list could silently pick the wrong (older) archive,
    # so fail instead of parsing whatever arrived.
    if list_result.returncode != 0:
        _log_command_failure(list_result, f'Error listing archive catalog for: "{database_path}"')
        return 1
    archive_map = _parse_archive_map(cast(str, list_result.stdout))
    if not archive_map:
        logger.error("Could not determine archive list from dar_manager output.")
        return 1
    logger.debug("PITR archive map: %s", ", ".join(f"#{k}={v}" for k, v in sorted(archive_map.items())))
    archive_info = _parse_archive_info(archive_map)
    info_by_no = {catalog_no: (dt, archive_type) for catalog_no, dt, archive_type in archive_info}

    darrc_path = _guess_darrc_path(config_settings)
    validation_cache: Dict[str, Optional[str]] = {}
    failures = 0
    successes = 0
    missing_archives = set()

    try:
        for path in paths:
            # Shared detect/select decision (identical to what _pitr_chain_report uses).
            plan = _resolve_pitr_path(
                path, when_dt, database_path, archive_map, archive_info, _runner(), timeout, root
            )
            if plan.is_directory:
                logger.debug("Path '%s' detected as directory — using archive chain restore.", path)
                if plan.error:
                    logger.error(plan.error)
                    failures += 1
                    continue
                chain_errors = []
                for catalog_no in plan.chain:
                    archive_path = archive_map.get(catalog_no)
                    if not archive_path:
                        chain_errors.append(f"catalog #{catalog_no} missing from archive map")
                        continue
                    validation_error = _cached_pitr_archive_validation_error(
                        archive_path,
                        _runner(),
                        timeout,
                        darrc_path,
                        validation_cache,
                    )
                    if validation_error:
                        chain_errors.append(validation_error)
                if chain_errors:
                    for item in chain_errors:
                        missing_archives.add(item)
                        if item.startswith("catalog #"):
                            logger.error("PITR restore missing archive in chain for '%s': %s", path, item)
                        else:
                            logger.error("PITR restore unusable archive in chain for '%s': %s", path, item)
                    failures += 1
                    continue
                logger.info(
                    "PITR restore directory '%s' using archive chain: %s",
                    path,
                    ", ".join(_describe_archive(num, archive_map, info_by_no) for num in plan.chain),
                )
                restored = True
                for catalog_no in plan.chain:
                    archive_path = archive_map.get(catalog_no)
                    if not archive_path:
                        missing_archives.add(f"catalog #{catalog_no} missing from archive map")
                        logger.error(f"Archive number {catalog_no} missing from archive list; cannot restore '{path}'.")
                        restored = False
                        break
                    sequence_error = _pitr_archive_sequence_error(archive_path)
                    if sequence_error:
                        missing_archives.add(sequence_error)
                        logger.error("%s; cannot complete restore for '%s'.", sequence_error, path)
                        restored = False
                        break
                    cmd = ['dar', '-x', archive_path, '-wa', '-g', path, '--noconf', '-Q']
                    if target:
                        cmd.extend(['-R', target])
                    if ignore_ownership:
                        cmd.append('--comparison-field=ignore-owner')
                    if no_deleted:
                        cmd.append('--deleted=ignore')
                    if darrc_path:
                        cmd.extend(['-B', darrc_path, 'restore-options'])
                    logger.info(
                        "Applying archive %s for '%s'.",
                        _describe_archive(catalog_no, archive_map, info_by_no),
                        path,
                    )
                    result = _runner().run(cmd, timeout=timeout)
                    if result.returncode != 0:
                        logger.error(f"dar restore failed for '{path}' from '{archive_path}': {cast(str, result.stderr)}")
                        restored = False
                        break
                    sequence_error = _pitr_archive_sequence_error(archive_path)
                    if sequence_error:
                        missing_archives.add(sequence_error)
                        logger.error(
                            "%s; a slice disappeared while restoring '%s'. Target may be incomplete.",
                            sequence_error,
                            path,
                        )
                        restored = False
                        break
                if restored:
                    successes += 1
                else:
                    failures += 1
                continue

            logger.debug(
                "PITR candidates for '%s': %s",
                path,
                ", ".join(f"#{num}@{dt}" for num, dt in plan.candidates) or "<none>",
            )
            if plan.error:
                logger.error(plan.error)
                failures += 1
                continue

            # Fail-fast policy: only the best candidate (newest version at or
            # before when_dt) is ever tried.  Falling back to an older version
            # when this one is missing or fails to extract would silently
            # restore stale data with a success exit code — the user must
            # rerun with an earlier --when to get an older version explicitly.
            catalog_no, _candidate_dt = plan.candidates[0]
            archive_path = archive_map.get(catalog_no)
            if not archive_path:
                missing_archives.add(f"catalog #{catalog_no} missing from archive map")
                logger.error(f"Archive number {catalog_no} missing from archive list; cannot restore '{path}'.")
                failures += 1
                continue
            validation_error = _cached_pitr_archive_validation_error(
                archive_path,
                _runner(),
                timeout,
                darrc_path,
                validation_cache,
            )
            if validation_error:
                missing_archives.add(validation_error)
                logger.error("%s; cannot restore '%s'.", validation_error, path)
                failures += 1
                continue
            logger.info(
                "PITR restore file '%s' using archive %s.",
                path,
                _describe_archive(catalog_no, archive_map, info_by_no),
            )
            cmd = ['dar', '-x', archive_path, '-wa', '-g', path, '--noconf', '-Q']
            if target:
                cmd.extend(['-R', target])
            if ignore_ownership:
                cmd.append('--comparison-field=ignore-owner')
            if no_deleted:
                cmd.append('--deleted=ignore')
            if darrc_path:
                cmd.extend(['-B', darrc_path, 'restore-options'])
            logger.info(
                "Restoring '%s' from archive %s using dar.",
                path,
                _describe_archive(catalog_no, archive_map, info_by_no),
            )
            result = _runner().run(cmd, timeout=timeout)
            if result.returncode != 0:
                logger.error(f"dar restore failed for '{path}' from '{archive_path}': {cast(str, result.stderr)}")
                # Give the operator everything needed to recover without a doc hunt:
                # the older versions (with the timestamps a rerun's --when must
                # target), the par2-repair-first hint, and the clean-target
                # requirement (a failed dar run may have left partial files that
                # would trip the pre-existence abort on rerun).
                older_versions = ", ".join(
                    f"#{num}@{dt.strftime('%Y-%m-%d %H:%M:%S')} "
                    f"({os.path.basename(archive_map[num]) if num in archive_map else 'unknown'})"
                    for num, dt in plan.candidates[1:]
                ) or "<none>"
                logger.error(
                    "Not falling back to an older version of '%s'. Older versions in the catalog: %s. "
                    "If the slice is damaged, try par2 repair first (see doc/par2.md), then rerun. "
                    "To restore an older version instead, rerun with --when at that version's timestamp, "
                    "into a clean target.",
                    path,
                    older_versions,
                )
                failures += 1
                continue
            sequence_error = _pitr_archive_sequence_error(archive_path)
            if sequence_error:
                missing_archives.add(sequence_error)
                logger.error(
                    "%s; a slice disappeared while restoring '%s'. Target may be incomplete.",
                    sequence_error,
                    path,
                )
                failures += 1
                continue
            successes += 1

    except KeyboardInterrupt:
        msg = (
            f"PITR restore interrupted (Ctrl-C or SIGTERM) mid-restore. "
            f"Target directory '{target}' may be incomplete and must NOT be used."
        )
        logger.exception(msg)
        raise

    logger.info("PITR restore summary: %d succeeded, %d failed.", successes, failures)
    if missing_archives:
        missing_list = sorted(missing_archives)
        sample = ", ".join(missing_list[:3])
        extra = f" (+{len(missing_list) - 3} more)" if len(missing_list) > 3 else ""
        logger.error("Missing archives detected during PITR restore: %s%s", sample, extra)
        ts = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M")
        send_discord_message(
            f"{ts} - manager: PITR restore missing archives ({len(missing_list)} missing).",
            config_settings=config_settings,
        )
    if failures:
        ts = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M")
        send_discord_message(
            f"{ts} - manager: PITR restore completed with failures ({failures} failed, {successes} succeeded).",
            config_settings=config_settings,
        )
    return 0 if failures == 0 else 1


def add_specific_archive(archive: str, config_settings: ConfigSettings, directory: Optional[str] = None) -> int:
    """Add the specified archive to its catalog database.

    Prompts for confirmation (see confirm_add_old_archive) if the archive's
    date is older than the latest entry already in the catalog, to guard
    against accidentally creating an inconsistent restore chain.

    Args:
        archive: Archive base name to add (path prefix, if any, is stripped).
        config_settings: Loaded configuration providing the database and
            backup.d directories.
        directory: Directory containing the archive's .1.dar slice. Defaults
            to config_settings.backup_dir.

    Returns:
        0 on success; 1 if the archive/backup definition can't be found or
        validated, or the user declines to add an older archive; otherwise
        the dar_manager `--add` process's own return code.
    """
    # Determine archive path
    if not directory:
        directory = config_settings.backup_dir
    archive = os.path.basename(archive)  # strip path if present
    archive_path = os.path.join(directory, archive)
    archive_test_path = os.path.join(directory, f'{archive}.1.dar')

    if not os.path.exists(archive_test_path):
        logger.error(f'dar backup: "{archive_test_path}" not found, exiting')
        return 1

    # Validate archive name and extract backup definition
    parsed_archive = ArchiveName.parse(archive)
    if not parsed_archive:
        logger.error(f'Archive name "{archive}" does not match the expected naming convention, exiting')
        return 1
    backup_definition = parsed_archive.definition
    backup_def_path = os.path.join(config_settings.backup_d_dir, backup_definition)
    if not os.path.exists(backup_def_path):
        logger.error(f'backup definition "{backup_definition}" not found (--add-specific-archive option probably not correct), exiting')
        return 1

    # Determine catalog DB path
    database = f"{backup_definition}{DB_SUFFIX}"
    database_path = os.path.realpath(os.path.join(get_db_dir(config_settings), database))

    # Safety check: is archive older than latest in catalog?
    timeout = _coerce_timeout(config_settings.command_timeout_secs)
    result = _runner().run(["dar_manager", "--base", database_path, "--list"], timeout=timeout)
    if result.returncode != 0:
        stderr_detail = (cast(str, result.stderr) or "").strip()
        detail = f" (returncode={result.returncode}): {stderr_detail}" if stderr_detail else f" (returncode={result.returncode})"
        logger.warning(
            "Chronological check skipped: dar_manager --list failed for catalog '%s'%s",
            database_path, detail,
        )
    else:
        all_lines = (cast(str, result.stdout) or "").splitlines()
        date_pattern = re.compile(r"\d{4}-\d{2}-\d{2}")

        catalog_dates = [
            datetime.strptime(date_match.group(), "%Y-%m-%d")
            for line in all_lines
            if (date_match := date_pattern.search(line))
        ]

        if catalog_dates:
            latest_date = max(catalog_dates)
            archive_date = parsed_archive.as_datetime()
            if archive_date and archive_date < latest_date:
                if not confirm_add_old_archive(archive, latest_date.strftime("%Y-%m-%d")):
                    logger.info(f"Archive {archive} skipped due to user declining to add older archive.")
                    return 1

    logger.info(f'Add "{archive_path}" to catalog: "{database}"')

    command = ['dar_manager', '--base', database_path, "--add", archive_path, "-Q", "--alter=ignore-order"]
    process = _runner().run(command)

    if process.returncode == 0:
        logger.info(f'"{archive_path}" added to its catalog')
    elif process.returncode == 5:
        logger.warning(f'Something did not go completely right adding "{archive_path}" to its catalog, dar_manager error: "{process.returncode}"')
    else:
        _log_command_failure(
            process,
            f'something went wrong adding "{archive_path}" to its catalog, dar_manager error: "{process.returncode}"',
        )

    return process.returncode



def add_directory(args: argparse.Namespace, config_settings: ConfigSettings) -> int:
    """
    Loop over the DAR archives in the given directory args.add_dir in increasing order by date and add them to their catalog database.

    Args:
        args (argparse.Namespace): The command-line arguments object containing the add_dir attribute.
        config_settings (ConfigSettings): The configuration settings object.

    Returns:
        0 if all archives were added successfully, 1 if any archive failed.

    This function performs the following steps:
    1. Checks if the specified directory exists. If not, raises a RuntimeError.
    2. Uses a regular expression to match DAR archive files with base names in the format <string>_{FULL, DIFF, INCR}_YYYY-MM-DD.
    3. Lists the DAR archives in the specified directory and extracts their base names and dates.
    4. Sorts the DAR archives by date.
    5. Loops over the sorted DAR archives and adds each archive to its catalog database using the add_specific_archive function.

    Example:
        args = parser.parse_args()
        args.add_dir = '/path/to/dar/archives'
        config_settings = ConfigSettings()
        add_directory(args, config_settings)
    """
    if not os.path.exists(args.add_dir):
        raise RuntimeError(f"Directory {args.add_dir} does not exist")

    dar_archives = []
    type_order = {"FULL": 0, "DIFF": 1, "INCR": 2}

    backup_def_filter = getattr(args, 'backup_def', None)
    if backup_def_filter:
        logger.debug(f"Filtering archives by backup definition: '{backup_def_filter}'")

    for filename in os.listdir(args.add_dir):
        logger.debug(f"check if '{filename}' is a dar archive slice #1?")
        if not filename.endswith('.1.dar'):
            continue
        base_name = filename[:-len('.1.dar')]
        parsed = ArchiveName.parse(base_name)
        if parsed is None:
            continue
        # Skip archives that don't belong to the requested backup definition
        if backup_def_filter and parsed.definition != backup_def_filter:
            logger.debug(f" -> skipping '{base_name}': does not match backup definition '{backup_def_filter}'")
            continue
        date_obj = parsed.as_datetime() or datetime.min
        dar_archives.append((date_obj, type_order.get(parsed.archive_type, 99), base_name, parsed.archive_type))
        logger.debug(f" -> yes: base name: {base_name}, type: {parsed.archive_type}, date: {parsed.date}")

    if not dar_archives or len(dar_archives) == 0:
        logger.info(f"No 'dar' archives found in directory {args.add_dir}")
        return 0

    # Sort the DAR archives by date then type (FULL -> DIFF -> INCR) to avoid interactive ordering prompts.
    dar_archives.sort()
    logger.debug("Sorted archives for add-dir: %s", [(d.strftime("%Y-%m-%d"), t, n) for d, t, n, _ in dar_archives])

    # Loop over the sorted DAR archives and process them
    result: List[Dict] = []
    for _date_obj, _type_order, base_name, _archive_type in dar_archives:
        logger.info(f"Adding dar archive: '{base_name}' to it's catalog database")
        result_archive = add_specific_archive(base_name, config_settings, args.add_dir)
        result.append({ f"{base_name}" : result_archive})
        if result_archive != 0:
            logger.error(f"Something went wrong added {base_name} to it's catalog")

    logger.debug(f"Results adding archives found in: '{args.add_dir}': {result}")
    return 1 if any(list(v.values())[0] != 0 for v in result) else 0


def confirm_add_old_archive(archive_name: str, latest_known_date: str, timeout_secs: int = 20) -> bool:
    """Prompt the user to confirm adding an archive older than the catalog's latest entry.

    Args:
        archive_name: Archive base name being added, shown in the prompt.
        latest_known_date: Date of the latest archive already in the catalog,
            shown in the prompt for context.
        timeout_secs: Seconds to wait for input before treating it as declined.

    Returns:
        True only if the user types "yes" (case-insensitive) before the
        timeout; False on any other input, timeout, or Ctrl-C.
    """
    try:
        prompt = (
            f"⚠️ Archive '{archive_name}' is older than the latest in the catalog ({latest_known_date}).\n"
            f"Adding older archives may lead to inconsistent restore chains.\n"
            f"Are you sure you want to continue? (yes/no): "
        )
        confirmation = inputimeout(prompt=prompt, timeout=timeout_secs)

        if confirmation is None:
            logger.info(f"No confirmation received for old archive: {archive_name}. Skipping.")
            return False
        return confirmation.strip().lower() == "yes"

    except TimeoutOccurred:
        logger.info(f"Timeout waiting for confirmation for old archive: {archive_name}. Skipping.")
        return False
    except KeyboardInterrupt:
        logger.info(f"User interrupted confirmation for old archive: {archive_name}. Skipping.")
        return False


def remove_specific_archive(archive: str, config_settings: ConfigSettings) -> int:
    """Remove the specified archive's entry from its catalog database.

    Args:
        archive: Archive base name to remove.
        config_settings: Loaded configuration providing the database directory
            and command timeout.

    Returns:
        - 0 if the archive was removed from it's catalog
        - 1 if the archive name is unparseable or dar_manager --delete failed
        - 2 if the archive was not found in the catalog
    """
    parsed = ArchiveName.parse(archive)
    if parsed is None:
        logger.error(f"Cannot parse archive name: '{archive}'")
        return 1
    database_path = os.path.join(get_db_dir(config_settings), f"{parsed.definition}{DB_SUFFIX}")
    cat_no:int = cat_no_for_name(archive, config_settings)
    if cat_no >= 0:
        command = ['dar_manager', '--base', database_path, "--delete", str(cat_no)]
        timeout = _coerce_timeout(config_settings.command_timeout_secs)
        process: CommandResult = _runner().run(command, timeout=timeout)
        logger.info(f"CommandResult: {process}")
    else:
        logger.warning(f"archive: '{archive}' not found in it's catalog database: {database_path}")
        return 2

    if process.returncode == 0:
        logger.info(f"'{archive}' removed from it's catalog")
        return 0
    else:
        _log_command_failure(process, f"Failed to remove '{archive}' from catalog '{database_path}'.")
        return 1


def build_arg_parser() -> argparse.ArgumentParser:
    """Build the `manager` CLI argument parser.

    Returns:
        Configured ArgumentParser with all manager subcommand options
        (--create-db, --add-specific-archive, --restore-path/--when for PITR,
        --relocate-archive-path, etc.) and shell-completion hooks attached.
    """
    parser = argparse.ArgumentParser(description="Creates/maintains `dar` database catalogs")
    parser.add_argument('-c', '--config-file', type=str, help="Path to 'dar-backup.conf'", default=None)
    parser.add_argument('--create-db', action='store_true', help='Create missing databases for all backup definitions')
    parser.add_argument('--alternate-archive-dir', type=str, help='Use this directory instead of BACKUP_DIR in config file')
    parser.add_argument('--add-dir', type=str, help='Add all archive catalogs in this directory to databases')
    # argcomplete's documented pattern is to set .completer on the Action returned by
    # add_argument(); argparse.Action's type stub doesn't declare it, hence the ignores below.
    parser.add_argument('-d', '--backup-def', type=str, help='Restrict to work only on this backup definition').completer = backup_definition_completer  # type: ignore[attr-defined] # noqa: E501
    parser.add_argument('--add-specific-archive', type=str, help='Add this archive to catalog database').completer = add_specific_archive_completer  # type: ignore[attr-defined]
    parser.add_argument('--remove-specific-archive', type=str, help='Remove this archive from catalog database').completer = archive_content_completer  # type: ignore[attr-defined]
    parser.add_argument('-l', '--list-catalogs', action='store_true', help='List catalogs in databases for all backup definitions')
    parser.add_argument('--list-archive-contents', type=str, help="List contents of the archive's catalog. Argument is the archive name.").completer = archive_content_completer  # type: ignore[attr-defined] # noqa: E501
    parser.add_argument('--find-file', type=str, help="List catalogs containing <path>/file. '-d <definition>' argument is also required")
    parser.add_argument('--restore-path', nargs='+', help="Restore specific path(s) (Point-in-Time Recovery).")
    parser.add_argument('--when', type=str, help="Date/time for restoration (used with --restore-path).")
    parser.add_argument('--target', type=str, default=None, help="Target directory for restoration (default: current dir).")
    parser.add_argument('--pitr-report', action='store_true', help="Report PITR archive chain for --restore-path/--when without restoring.")
    parser.add_argument(
        '--pitr-report-first',
        action='store_true',
        help="Run PITR chain report before restore and abort if archives are missing or incomplete.",
    )
    parser.add_argument(
        '--relocate-archive-path',
        nargs=2,
        metavar=("OLD", "NEW"),
        help="Rewrite archive path prefix in the catalog DB (requires --backup-def).",
    )
    parser.add_argument(
        '--relocate-archive-path-dry-run',
        action='store_true',
        help="Show archive path changes without applying them (use with --relocate-archive-path).",
    )
    parser.add_argument('--verbose', action='store_true', help='Be more verbose')
    ownership_group = parser.add_mutually_exclusive_group()
    ownership_group.add_argument(
        '--preserve-ownership', action='store_true',
        help="Force uid/gid restoration for this run (root only). Overrides RESTORE_OWNERSHIP = no in the config file.",
    )
    ownership_group.add_argument(
        '--ignore-ownership', action='store_true',
        help="Force --comparison-field=ignore-owner for this run. Overrides RESTORE_OWNERSHIP = yes in the config file.",
    )
    parser.add_argument(
        '--no-deleted', action='store_true',
        help="Do not process deletion records from DIFF/INCR archives (passes --deleted=ignore to dar). "
             "Useful when restoring a DIFF or INCR archive directly to an empty directory.",
    )
    parser.add_argument('--log-level', type=str, help="`debug` or `trace`, default is `info`", default="info")
    parser.add_argument('--log-stdout', action='store_true', help='also print log messages to stdout')
    parser.add_argument('--more-help', action='store_true', help='Show extended help message')
    parser.add_argument('-v', '--version', action='store_true', help='Show version & license')

    return parser


def main() -> None:
    """CLI entrypoint: parse arguments and dispatch to the requested operation.

    Handles --create-db, --add-specific-archive/--add-dir,
    --remove-specific-archive, --list-catalogs/--list-archive-contents,
    --find-file, --restore-path/--when (PITR restore or --pitr-report), and
    --relocate-archive-path. Initializes logging and the module-level
    logger/runner globals used by the rest of this module.

    Every code path terminates via sys.exit() with an appropriate exit code;
    this function never returns normally.
    """
    global logger, runner

    MIN_PYTHON_VERSION = (3, 9)
    if sys.version_info < MIN_PYTHON_VERSION:
        sys.stderr.write(f"Error: This script requires Python {'.'.join(map(str, MIN_PYTHON_VERSION))} or higher.\n")
        sys.exit(1)
        return

    # Install a SIGTERM handler so that `kill <pid>` triggers the same
    # KeyboardInterrupt handling chain as Ctrl-C (SIGINT). Without this,
    # SIGTERM terminates immediately without running finally blocks or logging.
    def _sigterm_handler(signum, frame):
        raise KeyboardInterrupt("SIGTERM received — manager terminated by kill signal")
    signal.signal(signal.SIGTERM, _sigterm_handler)

    parser = build_arg_parser()

    argcomplete.autocomplete(parser)

    args = parser.parse_args()

    if args.more_help:
        show_more_help()
        sys.exit(0)
        return

    if args.version:
        show_version()
        sys.exit(0)

    config_settings_path = get_config_file(args)
    if not (os.path.isfile(config_settings_path) and os.access(config_settings_path, os.R_OK)):
        print(f"Config file {config_settings_path} must exist and be readable.", file=stderr)
        raise SystemExit(127)
    args.config_file = config_settings_path

    try:
        config_settings = ConfigSettings(args.config_file)
    except Exception as exc:  # noqa: BLE001 — CLI-boundary catch: logs with context, reports, and exits
        msg = f"Config error: {exc}"
        print(msg, file=stderr)
        ts = datetime.now().astimezone().strftime("%Y-%m-%d_%H:%M")
        send_discord_message(f"{ts} - manager: FAILURE - {msg}")
        sys.exit(127)

    if not os.path.dirname(config_settings.logfile_location):
        print(f"Directory for log file '{config_settings.logfile_location}' does not exist, exiting")
        sys.exit(1)
        return

    logger, trace_log_file = init_logging(config_settings, args.log_level, args.log_stdout)
    command_logger = get_logger(command_output_logger=True)
    runner = CommandRunner(
        logger=logger,
        command_logger=command_logger,
        default_timeout=config_settings.command_timeout_secs,
        default_capture_limit_bytes=config_settings.command_capture_max_bytes,
    )

    start_msgs: List[Tuple[str, str]] = []

    start_msgs.append((f"{show_scriptname()}:", about.__version__))
    try:
        operation = None
        if args.create_db:
            operation = "create-db"
        elif args.add_specific_archive:
            operation = "add-archive"
        elif args.remove_specific_archive:
            operation = "remove archive"
        elif args.list_catalogs:
            operation = "list"
        elif args.restore_path:
            operation = "restore-path (PITR)"
        elif args.relocate_archive_path:
            operation = "relocate-archive-path"
        if operation:
            start_msgs.append(("Operation:", operation))
    except Exception as exc:  # noqa: BLE001 — logs with context and falls back to a safe default
        logger.warning("Could not determine operation: %s", exc)
        start_msgs.append(("Operation:", "unknown"))
    logger.debug(f"Command line: {get_invocation_command_line()}")
    logger.debug(f"`args`:\n{args}")
    logger.debug(f"`config_settings`:\n{config_settings}")
    start_msgs.append(("Config file:", args.config_file))
    if args.verbose:
        start_msgs.append(("Backup dir:", config_settings.backup_dir))
    start_msgs.append(("Logfile:", config_settings.logfile_location))
    if args.verbose:
        start_msgs.append(("Trace log:", trace_log_file))
        start_msgs.append(("Logfile max size (bytes):", str(config_settings.logfile_max_bytes)))
        start_msgs.append(("Logfile backup count:", str(config_settings.logfile_backup_count)))
        start_msgs.append(("--alternate-archive-dir:", args.alternate_archive_dir))
        start_msgs.append(("--remove-specific-archive:", args.remove_specific_archive))
        start_msgs.append(("--relocate-archive-path:", args.relocate_archive_path))
    dar_manager_properties = get_binary_info(command='dar_manager')
    start_msgs.append(("dar_manager:", dar_manager_properties['path']))
    start_msgs.append(("dar_manager v.:", dar_manager_properties['version']))

    print_aligned_settings(start_msgs, quiet=not args.verbose)

    # --- Sanity checks ---
    if args.add_dir and not args.add_dir.strip():
        logger.error("archive dir not given, exiting")
        sys.exit(1)
        return

    if args.add_specific_archive is not None and not args.add_specific_archive.strip():
        logger.error("specific archive to add not given, exiting")
        sys.exit(1)
        return

    if args.remove_specific_archive and not args.remove_specific_archive.strip():
        logger.error("specific archive to remove not given, exiting")
        sys.exit(1)
        return

    if args.add_specific_archive and args.remove_specific_archive:
        logger.error("you can't add and remove archives in the same operation, exiting")
        sys.exit(1)
        return

    if args.add_dir and args.add_specific_archive:
        logger.error("you cannot add both a directory and an archive")
        sys.exit(1)
        return

    if args.backup_def and not args.backup_def.strip():
        logger.error("No backup definition given to --backup-def")
        sys.exit(1)
        return

    if args.backup_def:
        backup_def_path = os.path.join(config_settings.backup_d_dir, args.backup_def)
        if not os.path.exists(backup_def_path):
            logger.error(f"Backup definition {args.backup_def} does not exist, exiting")
            sys.exit(1)
            return

    if args.list_archive_contents and not args.list_archive_contents.strip():
        logger.error("--list-archive-contents <param> not given, exiting")
        sys.exit(1)
        return

    if args.relocate_archive_path and not args.backup_def:
        logger.error("--relocate-archive-path requires the --backup-def, exiting")
        sys.exit(1)
        return

    if args.relocate_archive_path_dry_run and not args.relocate_archive_path:
        logger.error("--relocate-archive-path-dry-run requires --relocate-archive-path, exiting")
        sys.exit(1)
        return

    if args.find_file and not args.backup_def:
        logger.error("--find-file requires the --backup-def, exiting")
        sys.exit(1)
        return

    if args.restore_path and not args.backup_def:
        logger.error("--restore-path requires the --backup-def, exiting")
        sys.exit(1)

    if args.restore_path and not args.target and not args.pitr_report:
        logger.error("--restore-path requires the --target directory, exiting")
        sys.exit(1)
        return

    if args.pitr_report:
        if not args.restore_path:
            logger.error("--pitr-report requires --restore-path, exiting")
            sys.exit(1)
            return
        if not args.when:
            logger.error("--pitr-report requires --when, exiting")
            sys.exit(1)
            return

    if args.pitr_report_first and not args.restore_path:
        logger.error("--pitr-report-first requires --restore-path, exiting")
        sys.exit(1)
        return

    # --- Modify settings ---
    try:
        if args.alternate_archive_dir:
            if not os.path.exists(args.alternate_archive_dir):
                logger.error(f"Alternate archive dir '{args.alternate_archive_dir}' does not exist, exiting")
                sys.exit(1)
                return
            config_settings.backup_dir = args.alternate_archive_dir

        # --- Functional logic ---
        if args.create_db:
            if args.backup_def:
                sys.exit(create_db(args.backup_def, config_settings, logger, runner))
                return
            else:
                for _root, _dirs, files in os.walk(config_settings.backup_d_dir):
                    for file in files:
                        current_backupdef = os.path.basename(file)
                        logger.debug(f"Create catalog db for backup definition: '{current_backupdef}'")
                        result = create_db(current_backupdef, config_settings, logger, runner)
                        if result != 0:
                            sys.exit(result)
                            return

        if args.add_specific_archive:
            sys.exit(add_specific_archive(args.add_specific_archive, config_settings))
            return

        if args.add_dir:
            sys.exit(add_directory(args, config_settings))
            return

        if args.remove_specific_archive:
            sys.exit(remove_specific_archive(args.remove_specific_archive, config_settings))
            return

        if args.list_catalogs:
            if args.backup_def:
                process = list_catalogs(args.backup_def, config_settings)
                result = process.returncode
            else:
                result = 0
                for _root, _dirs, files in os.walk(config_settings.backup_d_dir):
                    for file in files:
                        current_backupdef = os.path.basename(file)
                        if list_catalogs(current_backupdef, config_settings).returncode != 0:
                            result = 1
            sys.exit(result)
            return

        if args.list_archive_contents:
            result = list_archive_contents(args.list_archive_contents, config_settings)
            sys.exit(result)
            return

        if args.relocate_archive_path:
            old_prefix, new_prefix = args.relocate_archive_path
            result = relocate_archive_paths(
                args.backup_def,
                old_prefix,
                new_prefix,
                config_settings,
                dry_run=args.relocate_archive_path_dry_run,
            )
            sys.exit(result)
            return


        if args.find_file:
            result = find_file(args.find_file, args.backup_def, config_settings)
            sys.exit(result)
            return

        if args.pitr_report:
            result = _pitr_chain_report(args.backup_def, args.restore_path, args.when, config_settings)
            sys.exit(result)
            return

        if args.restore_path:
            if args.pitr_report_first:
                report_when = args.when or "now"
                result = _pitr_chain_report(args.backup_def, args.restore_path, report_when, config_settings)
                if result != 0:
                    sys.exit(result)
                    return
            ignore_ownership = resolve_ownership_flag(args, config_settings)
            no_deleted = getattr(args, 'no_deleted', False)
            result = restore_at(args.backup_def, args.restore_path, args.when, args.target, config_settings,
                                verbose=args.verbose, ignore_ownership=ignore_ownership,
                                no_deleted=no_deleted)
            sys.exit(result)
            return

    except Exception as e:
        msg = f"Unexpected error during manager operation: {e}"
        logger.error(msg, exc_info=True)
        ts = datetime.now().astimezone().strftime("%Y-%m-%d_%H:%M")
        send_discord_message(f"{ts} - manager: FAILURE - {msg}", config_settings=config_settings)
        sys.exit(1)


if __name__ == "__main__":
    main()
