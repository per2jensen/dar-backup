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
import os
import re
import signal
import sys
import subprocess
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
from dar_backup.util import resolve_ownership_flag

from dar_backup.command_runner import CommandRunner
from dar_backup.command_runner import CommandResult
from dar_backup.util import backup_definition_completer, archive_content_completer, add_specific_archive_completer

from datetime import datetime, tzinfo
from sys import stderr
from time import time
from typing import Dict, List, Tuple, Optional, cast

# Constants
SCRIPTNAME = os.path.basename(__file__)
SCRIPTPATH = os.path.realpath(__file__)
SCRIPTDIRPATH = os.path.dirname(SCRIPTPATH)
DB_SUFFIX = ".db"

logger = get_logger()
runner: Optional[CommandRunner] = None


def _runner() -> CommandRunner:
    assert runner is not None, "CommandRunner not initialized; call main() first"
    return runner


def _open_command_log(command: List[str]):
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
        f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - COMMAND: "
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


def show_more_help():
    help_text = f"""
NAME
    {SCRIPTNAME} - creates/maintains `dar` databases with catalogs for backup definitions
"""
    print(help_text)


def create_db(backup_def: str, config_settings: ConfigSettings, logger, runner) -> int:
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


def list_catalogs(backup_def: str, config_settings: ConfigSettings, suppress_output=False) -> CommandResult:
    """
    List catalogs from the database for the given backup definition.

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
    """
    Find the catalog number for the given archive name

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
    """
    List the contents of a specific archive, given the archive name.
    Prints only actual file entries (lines beginning with '[ Saved ]').
    If none are found, a notice is printed instead.
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
    timeout = _coerce_timeout(config_settings.command_timeout_secs) or 10

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
    """
    List the contents of catalog # in catalog database for given backup definition
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


def find_file(file, backup_def, config_settings):
    """
    Find a specific file
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
            (must be relative, e.g. "tmp/unit-test/.../file.txt").
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
        parsed_date = datetime.now()
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
                except Exception as e:
                    logger.error(f"Could not create target directory '{target}': {e}")
                    return 1
                logger.debug("Created target directory: %s", target)

            try:
                lock_fd = os.open(target, os.O_RDONLY)
            except OSError as exc:
                logger.error("Could not open restore target '%s' for locking: %s", target, exc)
                return 1
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                logger.error(
                    "Restore target '%s' is locked by a concurrent PITR restore — "
                    "aborting to prevent silent data corruption",
                    target,
                )
                os.close(lock_fd)
                lock_fd = None
                return 1
            except OSError as exc:
                logger.error("Could not lock restore target '%s': %s", target, exc)
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
            logger.error(msg)
            raise
    finally:
        if lock_fd is not None:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
                os.close(lock_fd)
            except OSError:
                pass


def _restore_target_unsafe_reason(target: str) -> Optional[str]:
    # realpath() resolves symlinks to their canonical path so that a symlink
    # under /home pointing to /etc cannot bypass the protected-prefix check.
    # abspath() would NOT follow symlinks and would leave the check bypassable.
    # realpath() also normalises the path, so normpath() is not needed.
    target_norm = os.path.realpath(target)

    allow_prefixes = (
        "/tmp",
        "/var/tmp",
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
    return cast(tzinfo, datetime.now().astimezone().tzinfo)


def _normalize_when_dt(dt: datetime) -> datetime:
    if dt.tzinfo is None or dt.tzinfo.utcoffset(dt) is None:
        return dt
    local_tz = _local_tzinfo()
    return dt.astimezone(local_tz).replace(tzinfo=None)


def _parse_when(when: str) -> Optional[datetime]:
    parsed = dateparser.parse(when)
    if not parsed:
        return None
    normalized = _normalize_when_dt(parsed)
    if normalized is not parsed:
        logger.debug("Normalized PITR timestamp with timezone: %s -> %s", parsed, normalized)
    return normalized


def _coerce_timeout(value: Optional[int]) -> Optional[int]:
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
    archives: Dict[int, str] = {}
    for line in list_output.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("archive #") or stripped.startswith("-"):
            continue
        parts = stripped.split()
        if len(parts) < 3 or not parts[0].isdigit():
            continue
        num = int(parts[0])
        basename = parts[-1]
        path = " ".join(parts[1:-1])
        archives[num] = os.path.join(path, basename)
    return archives


def _replace_path_prefix(path: str, old_prefix: str, new_prefix: str) -> Optional[str]:
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


def _select_archive_chain(archive_info: List[Tuple[int, datetime, str]], when_dt: datetime) -> List[int]:
    order = {"FULL": 0, "DIFF": 1, "INCR": 2}
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
    assert last_full_key is not None  # set together with last_full in the loop above

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


def _is_directory_path(path: str) -> bool:
    """
    Check if path refers to an existing directory on the filesystem.

    Args:
        path: Relative path (rooted at /).

    Returns:
        True if the path exists as a directory on the filesystem.
    """
    return os.path.isdir(os.path.join(os.sep, path))


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
        logger.error(msg)
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
        if re.search(r'\bd[rwxXsStT-]{9}\b', stripped) and stripped.rstrip().endswith(path):
            return True
    return False


def _detect_directory(
    path: str,
    archive_map: Dict[int, str],
    archive_info: List[Tuple[int, datetime, str]],
    runner: "CommandRunner",
    timeout: Optional[int],
) -> bool:
    """
    Determine whether *path* is a directory using filesystem check first,
    then falling back to dar catalog inspection.

    Args:
        path: Relative path to check.
        archive_map: Mapping of catalog numbers to archive paths.
        archive_info: Parsed archive info (catalog_no, datetime, type).
        runner: CommandRunner instance.
        timeout: Command timeout in seconds, or None for no timeout.

    Returns:
        True if the path is a directory.
    """
    # Fast path: check filesystem
    if _is_directory_path(path):
        return True

    # Fallback: inspect the FULL archive via dar -l
    full_archives = [
        (no, dt) for no, dt, atype in archive_info if atype == "FULL"
    ]
    if not full_archives:
        return False
    # Use the most recent FULL archive
    full_archives.sort(key=lambda item: item[1], reverse=True)
    full_no = full_archives[0][0]
    full_path = archive_map.get(full_no)
    if not full_path:
        return False
    return _is_directory_in_archive(path, full_path, runner, timeout)



def _format_chain_item(
    catalog_no: int,
    info_by_no: Dict[int, Tuple[datetime, str]],
    status: str,
) -> str:
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
    archive_path = archive_map.get(catalog_no)
    base = os.path.basename(archive_path) if archive_path else "unknown"
    info = info_by_no.get(catalog_no)
    if info:
        dt, archive_type = info
        dt_str = dt.strftime("%Y-%m-%d %H:%M:%S")
        return f"#{catalog_no} {archive_type}@{dt_str} {base}"
    return f"#{catalog_no} {base}"


def _missing_chain_elements(chain: List[int], archive_map: Dict[int, str]) -> List[str]:
    missing = []
    for catalog_no in chain:
        archive_path = archive_map.get(catalog_no)
        if not archive_path:
            missing.append(f"catalog #{catalog_no} missing from archive map")
            continue
        if not archive_exists(archive_path):
            missing.append(f"{archive_path}.1.dar")
    return missing


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
        chain elements whose .1.dar slices are absent on disk.
    """
    chain = _select_archive_chain(archive_info, when_dt)
    if not chain:
        return [], []
    return chain, _missing_chain_elements(chain, archive_map)


def _pitr_chain_report(
    backup_def: str,
    paths: List[str],
    when: str,
    config_settings: ConfigSettings,
) -> int:
    """
    Report the PITR archive chain that would be used for a restore at `when`,
    without performing any restore actions. Returns non-zero if required
    archives are missing or no chain/candidates can be determined.
    """
    if not when:
        logger.error("PITR report requires --when.")
        return 1

    parsed_date = _parse_when(when)
    if not parsed_date:
        logger.error(f"Could not parse date: '{when}'")
        return 1

    database = f"{backup_def}{DB_SUFFIX}"
    database_path = os.path.join(get_db_dir(config_settings), database)
    timeout = _coerce_timeout(config_settings.command_timeout_secs)
    list_result = _runner().run(['dar_manager', '--base', database_path, '--list'], timeout=timeout)
    archive_map = _parse_archive_map(cast(str, list_result.stdout))
    if not archive_map:
        logger.error("Could not determine archive list from dar_manager output.")
        return 1

    archive_info = _parse_archive_info(archive_map)
    info_by_no = {catalog_no: (dt, archive_type) for catalog_no, dt, archive_type in archive_info}
    failures = 0
    successes = 0

    for path in paths:
        is_directory = _detect_directory(path, archive_map, archive_info, _runner(), timeout)
        if is_directory:
            logger.debug("Path '%s' detected as directory — using archive chain restore.", path)
            chain, missing = _resolve_directory_chain(archive_info, parsed_date, archive_map)
            if not chain:
                logger.error(f"No FULL archive found at or before {parsed_date} for '{path}'")
                failures += 1
                continue
            missing_set = set(missing)
            chain_display_parts = []
            for catalog_no in chain:
                archive_path = archive_map.get(catalog_no)
                if not archive_path:
                    status = "missing"
                else:
                    status = "missing" if f"{archive_path}.1.dar" in missing_set else "ok"
                chain_display_parts.append(_format_chain_item(catalog_no, info_by_no, status))
            logger.info("PITR chain report for '%s': %s", path, ", ".join(chain_display_parts))
            if missing:
                for item in missing:
                    logger.error("PITR chain report missing archive: %s", item)
                failures += 1
            else:
                successes += 1
            continue

        file_result = _runner().run(['dar_manager', '--base', database_path, '-f', path], timeout=timeout)
        versions = _parse_file_versions(cast(str, file_result.stdout))
        candidates = [(num, dt) for num, dt in versions if dt <= parsed_date]
        candidates.sort(key=lambda item: item[1], reverse=True)
        logger.info(
            "PITR chain report candidates for '%s': %s",
            path,
            ", ".join(f"#{num}@{dt}" for num, dt in candidates) or "<none>",
        )
        if not candidates:
            logger.error(f"No archive version found for '{path}' at or before {parsed_date}")
            failures += 1
            continue
        catalog_no, dt = candidates[0]
        archive_path = archive_map.get(catalog_no)
        if not archive_path:
            logger.error("PITR chain report missing archive map entry for #%d (%s)", catalog_no, path)
            failures += 1
            continue
        if not archive_exists(archive_path):
            logger.error("PITR chain report missing archive slice: %s", f"{archive_path}.1.dar")
            failures += 1
            continue
        logger.info("PITR chain report selected archive #%d (%s) for '%s'.", catalog_no, dt, path)
        successes += 1

    logger.info("PITR chain report summary: %d ok, %d failed.", successes, failures)
    return 0 if failures == 0 else 1


def _parse_file_versions(file_output: str) -> List[Tuple[int, datetime]]:
    versions: List[Tuple[int, datetime]] = []
    for line in file_output.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        match = re.match(r"^(\d+)\s+([A-Za-z]{3}\s+[A-Za-z]{3}\s+\d+\s+\d{2}:\d{2}:\d{2}\s+\d{4})", stripped)
        if not match:
            continue
        try:
            catalog_no = int(match.group(1))
            dt = datetime.strptime(match.group(2), "%a %b %d %H:%M:%S %Y")
        except Exception:
            continue
        versions.append((catalog_no, dt))
    return versions


def _guess_darrc_path(config_settings: ConfigSettings) -> Optional[str]:
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
    list_result = _runner().run(['dar_manager', '--base', database_path, '--list'], timeout=timeout)
    archive_map = _parse_archive_map(cast(str, list_result.stdout))
    if not archive_map:
        logger.error("Could not determine archive list from dar_manager output.")
        return 1
    logger.debug("PITR archive map: %s", ", ".join(f"#{k}={v}" for k, v in sorted(archive_map.items())))
    archive_info = _parse_archive_info(archive_map)
    info_by_no = {catalog_no: (dt, archive_type) for catalog_no, dt, archive_type in archive_info}

    darrc_path = _guess_darrc_path(config_settings)
    failures = 0
    successes = 0
    missing_archives = set()

    try:
        for path in paths:
            is_directory = _detect_directory(path, archive_map, archive_info, _runner(), timeout)
            if is_directory:
                logger.debug("Path '%s' detected as directory — using archive chain restore.", path)
                chain, missing = _resolve_directory_chain(archive_info, when_dt, archive_map)
                if not chain:
                    logger.error(f"No FULL archive found at or before {when_dt} for '{path}'")
                    failures += 1
                    continue
                if missing:
                    for item in missing:
                        missing_archives.add(item)
                        logger.error("PITR restore missing archive in chain for '%s': %s", path, item)
                    failures += 1
                    continue
                logger.info(
                    "PITR restore directory '%s' using archive chain: %s",
                    path,
                    ", ".join(_describe_archive(num, archive_map, info_by_no) for num in chain),
                )
                restored = True
                for catalog_no in chain:
                    archive_path = archive_map.get(catalog_no)
                    if not archive_path:
                        missing_archives.add(f"catalog #{catalog_no} missing from archive map")
                        logger.error(f"Archive number {catalog_no} missing from archive list; cannot restore '{path}'.")
                        restored = False
                        break
                    if not archive_exists(archive_path):
                        missing_archives.add(f"{archive_path}.1.dar")
                        logger.error(f"Archive slice missing for '{archive_path}.1.dar', cannot complete restore.")
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
                if restored:
                    successes += 1
                else:
                    failures += 1
                continue

            file_result = _runner().run(['dar_manager', '--base', database_path, '-f', path], timeout=timeout)
            versions = _parse_file_versions(cast(str, file_result.stdout))
            candidates = [(num, dt) for num, dt in versions if dt <= when_dt]
            candidates.sort(key=lambda item: item[1], reverse=True)
            logger.debug(
                "PITR candidates for '%s': %s",
                path,
                ", ".join(f"#{num}@{dt}" for num, dt in candidates) or "<none>",
            )
            if not candidates:
                logger.error(f"No archive version found for '{path}' at or before {when_dt}")
                failures += 1
                continue

            restored = False
            for catalog_no, _dt in candidates:
                archive_path = archive_map.get(catalog_no)
                if not archive_path:
                    missing_archives.add(f"catalog #{catalog_no} missing from archive map")
                    logger.error(f"Archive number {catalog_no} missing from archive list; cannot restore '{path}'.")
                    restored = False
                    break
                if not archive_exists(archive_path):
                    missing_archives.add(f"{archive_path}.1.dar")
                    logger.error(f"Archive slice missing for '{archive_path}.1.dar', cannot restore '{path}'.")
                    restored = False
                    break
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
                if result.returncode == 0:
                    restored = True
                    successes += 1
                    break
                logger.error(f"dar restore failed for '{path}' from '{archive_path}': {cast(str, result.stderr)}")

            if not restored:
                failures += 1

    except KeyboardInterrupt:
        msg = (
            f"PITR restore interrupted (Ctrl-C or SIGTERM) mid-restore. "
            f"Target directory '{target}' may be incomplete and must NOT be used."
        )
        logger.error(msg)
        raise

    logger.info("PITR restore summary: %d succeeded, %d failed.", successes, failures)
    if missing_archives:
        missing_list = sorted(missing_archives)
        sample = ", ".join(missing_list[:3])
        extra = f" (+{len(missing_list) - 3} more)" if len(missing_list) > 3 else ""
        logger.error("Missing archives detected during PITR restore: %s%s", sample, extra)
        ts = datetime.now().strftime("%Y-%m-%d %H:%M")
        send_discord_message(
            f"{ts} - manager: PITR restore missing archives ({len(missing_list)} missing).",
            config_settings=config_settings,
        )
    if failures:
        ts = datetime.now().strftime("%Y-%m-%d %H:%M")
        send_discord_message(
            f"{ts} - manager: PITR restore completed with failures ({failures} failed, {successes} succeeded).",
            config_settings=config_settings,
        )
    return 0 if failures == 0 else 1


def add_specific_archive(archive: str, config_settings: ConfigSettings, directory: Optional[str] = None) -> int:
    """
    Adds the specified archive to its catalog database. Prompts for confirmation if it's older than existing entries.

    Returns:
        0 on success
        1 on failure
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
    try:
        result = subprocess.run(
            ["dar_manager", "--base", database_path, "--list"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True
        )
        all_lines = result.stdout.splitlines()
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

    except subprocess.CalledProcessError as e:
        stderr_detail = e.stderr.strip() if e.stderr else ""
        detail = f" (returncode={e.returncode}): {stderr_detail}" if stderr_detail else f" (returncode={e.returncode})"
        logger.warning(
            "Chronological check skipped: dar_manager --list failed for catalog '%s'%s",
            database_path, detail,
        )
    except OSError as e:
        logger.warning(
            "Chronological check skipped: dar_manager not available for catalog '%s': %s",
            database_path, e,
        )

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
    """
    Confirm with the user if they want to proceed with adding an archive older than the most recent in the catalog.
    Returns True if the user confirms with "yes", False otherwise.
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
    """

    Returns:
        - 0 if the archive was removed from it's catalog
        - 1 if there was an error removing the archive
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


def build_arg_parser():
    parser = argparse.ArgumentParser(description="Creates/maintains `dar` database catalogs")
    parser.add_argument('-c', '--config-file', type=str, help="Path to 'dar-backup.conf'", default=None)
    parser.add_argument('--create-db', action='store_true', help='Create missing databases for all backup definitions')
    parser.add_argument('--alternate-archive-dir', type=str, help='Use this directory instead of BACKUP_DIR in config file')
    parser.add_argument('--add-dir', type=str, help='Add all archive catalogs in this directory to databases')
    parser.add_argument('-d', '--backup-def', type=str, help='Restrict to work only on this backup definition').completer = backup_definition_completer  # noqa: E501
    parser.add_argument('--add-specific-archive', type=str, help='Add this archive to catalog database').completer = add_specific_archive_completer
    parser.add_argument('--remove-specific-archive', type=str, help='Remove this archive from catalog database').completer = archive_content_completer
    parser.add_argument('-l', '--list-catalogs', action='store_true', help='List catalogs in databases for all backup definitions')
    parser.add_argument('--list-archive-contents', type=str, help="List contents of the archive's catalog. Argument is the archive name.").completer = archive_content_completer  # noqa: E501
    parser.add_argument('--find-file', type=str, help="List catalogs containing <path>/file. '-d <definition>' argument is also required")
    parser.add_argument('--restore-path', nargs='+', help="Restore specific path(s) (Point-in-Time Recovery).")
    parser.add_argument('--when', type=str, help="Date/time for restoration (used with --restore-path).")
    parser.add_argument('--target', type=str, default=None, help="Target directory for restoration (default: current dir).")
    parser.add_argument('--pitr-report', action='store_true', help="Report PITR archive chain for --restore-path/--when without restoring.")
    parser.add_argument(
        '--pitr-report-first',
        action='store_true',
        help="Run PITR chain report before restore and abort if missing archives.",
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


def main():
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
    except Exception as exc:
        msg = f"Config error: {exc}"
        print(msg, file=stderr)
        ts = datetime.now().strftime("%Y-%m-%d_%H:%M")
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
    except Exception as exc:
        logger.warning("Could not determine operation: %s", exc)
        start_msgs.append(("Operation:", "unknown"))
    logger.debug(f"Command line: {get_invocation_command_line()}")
    logger.debug(f"`args`:\n{args}")
    logger.debug(f"`config_settings`:\n{config_settings}")
    start_msgs.append(("Config file:", args.config_file))
    args.verbose and start_msgs.append(("Backup dir:", config_settings.backup_dir))
    start_msgs.append(("Logfile:", config_settings.logfile_location))
    args.verbose and start_msgs.append(("Trace log:", trace_log_file))
    args.verbose and start_msgs.append(("Logfile max size (bytes):", config_settings.logfile_max_bytes))
    args.verbose and start_msgs.append(("Logfile backup count:", config_settings.logfile_backup_count))
    args.verbose and start_msgs.append(("--alternate-archive-dir:", args.alternate_archive_dir))
    args.verbose and start_msgs.append(("--remove-specific-archive:", args.remove_specific_archive))
    args.verbose and start_msgs.append(("--relocate-archive-path:", args.relocate_archive_path))
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
            return remove_specific_archive(args.remove_specific_archive, config_settings)

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
        ts = datetime.now().strftime("%Y-%m-%d_%H:%M")
        send_discord_message(f"{ts} - manager: FAILURE - {msg}", config_settings=config_settings)
        sys.exit(1)


if __name__ == "__main__":
    main()
