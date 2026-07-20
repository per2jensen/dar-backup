#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""
installer.py source code is here: https://github.com/per2jensen/dar-backup/tree/main/v2/src/dar_backup/installer.py
This script is part of dar-backup, a backup solution for Linux using dar and systemd.

Licensed under GNU GENERAL PUBLIC LICENSE v3, see the supplied file "LICENSE" for details.

THERE IS NO WARRANTY FOR THE PROGRAM, TO THE EXTENT PERMITTED BY APPLICABLE LAW,
not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
See section 15 and section 16 in the supplied "LICENSE" file

This script can be used to control `dar` to backup parts of or the whole system.
"""
import fcntl
import argcomplete
import argparse
import filecmp

import glob
import os
import platform
import random
import re
import shlex
import shutil
import signal
import subprocess
import configparser
import uuid
import xml.etree.ElementTree as ET
import tempfile

from datetime import UTC, datetime
from pathlib import Path
from sys import exit
from sys import stderr
from sys import version_info
from time import time
from rich.console import Console
from rich.text import Text
from dataclasses import dataclass
from typing import IO, Iterable, Iterator, List, NamedTuple, Optional, Tuple, cast

from . import __about__ as about
from dar_backup.config_settings import ConfigSettings
from dar_backup.util import list_backups
from dar_backup.util import init_logging
from dar_backup.util import get_logger
from dar_backup.util import BackupError
from dar_backup.util import RestoreError
from dar_backup.util import requirements
from dar_backup.util import show_version
from dar_backup.util import get_config_file
from dar_backup.util import get_invocation_command_line
from dar_backup.util import get_binary_info
from dar_backup.util import print_aligned_settings
from dar_backup.util import backup_definition_completer, list_archive_completer
from dar_backup.util import ArchiveName
from dar_backup.util import show_scriptname
from dar_backup.util import send_discord_message, render_discord_report
from dar_backup.util import write_metrics_row, update_postreq_status
from dar_backup.util import parse_dar_stats
from dar_backup.util import compare_metadata
from dar_backup.util import write_restore_test_samples
from dar_backup.util import validate_directory
from dar_backup.util import archive_exists
from dar_backup.util import inspect_archive_slices
from dar_backup.util import get_backup_definition_root
from dar_backup.util import resolve_ownership_flag
from dar_backup.util import (
    RESTORE_FAIL_CONTENT_MISMATCH,
    RESTORE_FAIL_METADATA_MISMATCH,
    RESTORE_FAIL_SOURCE_MISSING,
    RESTORE_FAIL_RESTORED_MISSING,
    RESTORE_FAIL_PERMISSION_ERROR,
    RESTORE_FAIL_UNKNOWN_ERROR,
)

from dar_backup.command_runner import CommandRunner

# Module-level by design: tests inject real logger/runner objects via save/restore
# (see logger_runner_globals_accepted memory) — not a bug.
logger = get_logger()
runner: Optional[CommandRunner] = None


def _runner() -> CommandRunner:
    assert runner is not None, "CommandRunner not initialized; call main() first"  # noqa: S101 — internal invariant, not user input — module must be initialized by main()
    return runner


class BackupResult(NamedTuple):
    """Return the DAR-phase status and parsed inode statistics."""

    dar_exit_code: int  # raw dar return code; -1 if dar never ran
    dar_stats: dict[str, Optional[int]]


@dataclass
class VerifyResult:
    passed: bool                         # overall result; False if restore-compare failed
    restore_test_passed: Optional[bool]  # None = not attempted (do_not_compare or no eligible files)
    files_verified: int                  # number of files selected for restore testing

    def __bool__(self):
        return self.passed


_BACKUP_DEFINITION_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9 \\-]*[A-Za-z0-9])?$")
_BACKUP_DEFINITION_RULES = (
    "must contain only letters, numbers, spaces, or hyphens (no underscores)"
)
_BACKUP_DEFINITION_OPT_OUT = "--allow-unsafe-definition-names"


def _normalize_backup_definition_name(raw_name: str, *, allow_unsafe: bool = False) -> Optional[str]:
    if not raw_name:
        return None
    base = os.path.basename(str(raw_name))
    stem = Path(base).stem
    if not stem:
        return None
    if allow_unsafe:
        return stem
    if not _BACKUP_DEFINITION_RE.fullmatch(stem):
        return None
    return stem


def _log_partial_backup_slices(backup_file: str, dar_exit_code: int) -> None:
    """Log any archive slices left behind by an unsuccessful DAR run.

    Args:
        backup_file: Archive base path without a slice suffix.
        dar_exit_code: Nonzero exit code returned by DAR.

    Returns:
        None.

    Raises:
        ValueError: If ``backup_file`` is empty or ``dar_exit_code`` is zero.
    """
    if not backup_file:
        raise ValueError("backup_file must not be empty")
    if dar_exit_code == 0:
        raise ValueError("dar_exit_code must be nonzero for a partial backup")

    partial_slices = sorted(glob.glob(f"{backup_file}.*.dar"))
    if not partial_slices:
        return
    logger.error(
        "PARTIAL BACKUP on disk — dar failed (exit code %d) but left %d slice(s) behind. "
        "These files are INCOMPLETE and must NOT be used for restore: %s",
        dar_exit_code,
        len(partial_slices),
        partial_slices,
    )


def _register_backup_catalog(
    backup_file: str,
    config_settings: ConfigSettings,
    args: argparse.Namespace,
) -> Tuple[bool, Optional[Tuple[str, int]]]:
    """Register a verified archive in its manager catalog.

    Args:
        backup_file: Verified archive base path without a slice suffix.
        config_settings: Configuration providing the command timeout.
        args: Parsed CLI arguments providing the config-file path.

    Returns:
        A pair of ``(catalog_updated, issue)``. ``issue`` is None on success;
        otherwise it is the error tuple consumed by the CLI result aggregator.

    Raises:
        ValueError: If ``backup_file`` or ``args.config_file`` is empty.
    """
    if not backup_file:
        raise ValueError("backup_file must not be empty")
    config_file = getattr(args, "config_file", None)
    if not config_file:
        raise ValueError("args.config_file must not be empty")

    add_catalog_command = [
        "manager",
        "--add-specific-archive",
        backup_file,
        "--config-file",
        config_file,
    ]
    command_result = _runner().run(
        add_catalog_command,
        timeout=config_settings.command_timeout_secs,
    )
    if command_result.returncode == 0:
        logger.info(
            "Catalog for verified archive '%s' added successfully to its manager.",
            backup_file,
        )
        return True, None

    msg = (
        f"Catalog entry not added for verified archive '{backup_file}' "
        f"(manager returncode={command_result.returncode}). "
        f"The verified archive is safely on disk. To register it manually: "
        f"manager --add-specific-archive '{backup_file}' "
        f"--config-file '{config_file}'"
    )
    logger.error(msg)
    return False, (msg, 1)


def generic_backup(
    type: str, command: List[str], backup_file: str, backup_definition: str,
    darrc: str, config_settings: ConfigSettings, args: argparse.Namespace
) -> BackupResult:
    """
    Performs a backup using the 'dar' command.

    This function initiates a full backup operation by constructing and executing a command
    with the 'dar' utility. It checks if the backup file already exists to avoid overwriting
    previous backups. If the backup file does not exist, it proceeds with the backup operation.

    Args:
        type (str): The type of backup (FULL, DIFF, INCR).
        command (List[str]): The command to execute for the backup operation.
        backup_file (str): The base name of the backup file. The actual backup will be saved
                           as '{backup_file}.1.dar'.
        backup_definition (str): The path to the backup definition file. This file contains
                                 specific instructions for the 'dar' utility, such as which
                                 directories to include or exclude.
        darrc (str): The path to the '.darrc' configuration file.
        config_settings (ConfigSettings): An instance of the ConfigSettings class.
        args: Parsed command-line arguments. Retained for call-site compatibility;
            catalog registration is performed later by ``perform_backup``.


    Raises:
        BackupError: If an error leading to a bad backup occurs during the backup process.

    Returns:
        BackupResult: The accepted DAR exit code and parsed inode statistics.
    """

    dar_exit_code: int = -1
    dar_stats: dict[str, Optional[int]] = {}

    logger.info(f"Starting {type} backup for {backup_definition}")
    try:
        try:
            process = _runner().run(command, timeout=config_settings.command_timeout_secs)
        except Exception:
            logger.exception("Backup command could not be run for '%s'", backup_definition)
            raise

        dar_exit_code = process.returncode
        # Parse inode summary from the tail buffers, which always hold the last
        # 500 lines regardless of the main capture limit.  The summary appears at
        # the very end of dar's output, so the tail is reliable even for large
        # backups where process.stdout may have been truncated.
        dar_stats = parse_dar_stats((process.stdout_tail or "") + (process.stderr_tail or ""))
        if process.returncode in (0, 5) and dar_stats.get("inodes_saved") is None:
            logger.warning(
                "dar inode summary not parsed — inodes_saved is None after successful backup "
                "(exit code %d); check command log for split output or locale issues",
                process.returncode,
            )

        if process.returncode == 0:
            logger.info(f"{type} backup completed successfully.")
        elif process.returncode == 4:
            logger.error(
                "%s backup: dar exited with code 4 — the operation was aborted. "
                "Check for interactive prompts (for example passphrase or slice confirmation) "
                "that must be suppressed in non-interactive configuration. Any archive slices "
                "left behind are incomplete, will not be verified or cataloged, and must be "
                "moved or removed before retrying.",
                type,
            )
            _log_partial_backup_slices(backup_file, process.returncode)
            raise BackupError(
                "dar aborted with exit code 4; archive is incomplete",
                dar_exit_code=process.returncode,
            )
        elif process.returncode == 5:
            logger.warning(
                f"{type} backup: dar exited with code 5 — some files were not saved due to "
                f"filesystem errors (e.g. files changed or became unreadable during backup). "
                f"Archive is usable."
            )
        else:
            # Exit codes 1, 2, 3, 6, 7, 8, 9 are genuine failures
            _log_partial_backup_slices(backup_file, process.returncode)
            raise BackupError(
                f"dar exited with code {process.returncode}",
                dar_exit_code=process.returncode,
            )

        return BackupResult(dar_exit_code=dar_exit_code, dar_stats=dar_stats)

    except BackupError:
        raise  # pass through without re-wrapping so dar_exit_code is preserved
    except subprocess.CalledProcessError as e:
        logger.exception("Backup command failed")
        raise BackupError(f"Backup command failed: {e}") from e
    except Exception as e:
        logger.exception("Unexpected error during backup")
        raise BackupError(f"Unexpected error during backup: {e}") from e



class DoctypeStripper:
    """File-like wrapper that strips DOCTYPE lines to prevent XXE.

    Must be used as a context manager so that the underlying file handle is
    released promptly if the XML parser raises mid-parse.  Without __exit__,
    an abandoned parse leaves the handle open until the GC runs.
    """

    def __init__(self, path: str) -> None:
        self.f = open(path, encoding="utf-8")
        self.buf = ""

    def read(self, n: int = -1) -> str:
        """Read up to n bytes, stripping any DOCTYPE line encountered.

        Args:
            n: Number of bytes to read; -1 or None reads to EOF.

        Returns:
            Filtered file content with DOCTYPE declarations removed.
        """
        if n is None or n < 0:
            out = []
            for line in self.f:
                if "<!DOCTYPE" not in line:
                    out.append(line)
            return "".join(out)
        while len(self.buf) < n:
            line = self.f.readline()
            if not line:
                break
            if "<!DOCTYPE" not in line:
                self.buf += line
        result, self.buf = self.buf[:n], self.buf[n:]
        return result

    def close(self) -> None:
        """Close the underlying file handle."""
        self.f.close()

    def __enter__(self) -> "DoctypeStripper":
        return self

    def __exit__(self, *args: object) -> None:
        self.close()


def iter_files_with_paths_from_xml(xml_path: str) -> Iterator[Tuple[str, Optional[str]]]:
    """
    Stream file paths and sizes from a DAR XML listing to keep memory usage low.
    """
    path_stack: List[str] = []
    # DoctypeStripper is used as a context manager so the file handle is closed
    # promptly on normal exit, parse error, or abandoned iteration (GeneratorExit).
    with DoctypeStripper(xml_path) as stripper:
        context = ET.iterparse(stripper, events=("start", "end"))  # noqa: S314 — dar's own -Txml output, not untrusted external data
        for event, elem in context:
            if event == "start" and elem.tag == "Directory":
                dir_name = elem.get("name")
                if dir_name:
                    path_stack.append(dir_name)
            elif event == "end" and elem.tag == "File":
                file_name = elem.get("name")
                file_size = elem.get("size")
                if file_name:
                    if path_stack:
                        file_path = "/".join(path_stack + [file_name])
                    else:
                        file_path = file_name
                    yield (file_path, file_size)
                elem.clear()
            elif event == "end" and elem.tag == "Directory":
                if path_stack:
                    path_stack.pop()
                elem.clear()


def _is_restoretest_candidate(path: str, config_settings: ConfigSettings) -> bool:
    prefixes = [
        prefix.lstrip("/").lower()
        for prefix in config_settings.restoretest_exclude_prefixes
    ]
    suffixes = [
        suffix.lower()
        for suffix in config_settings.restoretest_exclude_suffixes
    ]
    regex = config_settings.restoretest_exclude_regex

    normalized = path.lstrip("/")
    lowered = normalized.lower()
    if prefixes and any(lowered.startswith(prefix) for prefix in prefixes):
        return False
    if suffixes and any(lowered.endswith(suffix) for suffix in suffixes):
        return False
    if regex and regex.search(normalized):
        return False
    return True


_DAR_SIZE_UNITS: dict[str, int] = {
    "o"  : 1,
    "kio": 1024,
    "Mio": 1024 * 1024,
    "Gio": 1024 * 1024 * 1024,
    "Tio": 1024 * 1024 * 1024 * 1024,
}


def _parse_size_bytes(size_text: str) -> Optional[int]:
    """Parse a dar size string (e.g. '10 Mio') to bytes.

    Args:
        size_text: Size string as returned by dar's file listing.

    Returns:
        Size in bytes, or None if the string cannot be parsed.
    """
    match = re.match(r'(\d+)\s*(\w+)', size_text or "")
    if not match:
        return None
    unit = match.group(2).strip()
    if unit not in _DAR_SIZE_UNITS:
        return None
    return int(match.group(1)) * _DAR_SIZE_UNITS[unit]


def _size_in_verification_range(size_text: str, config_settings: ConfigSettings) -> bool:
    """Check whether a dar-formatted size string falls within the configured verification window.

    Delegates to _parse_size_bytes() so that any future addition to _DAR_SIZE_UNITS
    is automatically reflected here without a second update.

    Args:
        size_text: Size string as returned by dar's file listing (e.g. '10 Mio').
        config_settings: Configuration with min_size_verification_mb and
            max_size_verification_mb attributes.

    Returns:
        True if the file size is within [min_size_verification_mb, max_size_verification_mb],
        False if the size cannot be parsed or falls outside the window.
    """
    try:
        file_size = _parse_size_bytes(size_text)
    except Exception as exc:  # noqa: BLE001 — logs with context and falls back to a safe default (see comment above)
        # An unexpected internal failure in _parse_size_bytes must not silently
        # empty the sample pool.  Including the file is the conservative fallback:
        # better to verify a file whose size is unknown than to verify nothing.
        logger.warning(
            "_parse_size_bytes raised unexpectedly for %r: %s — including file in sample pool",
            size_text, exc,
        )
        return True
    if file_size is None:
        return False
    min_size = config_settings.min_size_verification_mb * 1024 * 1024
    max_size = config_settings.max_size_verification_mb * 1024 * 1024
    return min_size <= file_size <= max_size


def select_restoretest_samples(
    backed_up_files: Iterable[Tuple[str, Optional[str]]],
    config_settings: ConfigSettings,
    sample_size: int
) -> List[str]:
    if sample_size <= 0:
        return []
    reservoir: List[str] = []
    candidates_seen = 0
    size_filtered_total = 0
    excluded = 0
    for item in backed_up_files:
        if item is None or len(item) < 2:
            continue
        path, size_text = item[0], item[1]
        if not path or not size_text:
            continue
        if not _size_in_verification_range(size_text, config_settings):
            continue
        size_filtered_total += 1
        if not _is_restoretest_candidate(path, config_settings):
            excluded += 1
            continue
        candidates_seen += 1
        if candidates_seen <= sample_size:
            reservoir.append(path)
        else:
            idx = random.randint(1, candidates_seen)  # noqa: S311 — reservoir sampling for restore-test file selection, not a security context
            if idx <= sample_size:
                reservoir[idx - 1] = path
    if size_filtered_total and excluded:
        logger.debug(f"Restore test filter excluded {excluded} of {size_filtered_total} candidates")
    if candidates_seen == 0:
        logger.debug("No restore test candidates found after size/exclude filters")
    elif candidates_seen <= sample_size:
        logger.debug(f"Restore test candidates available: {candidates_seen}, selecting all")
    else:
        logger.debug(f"Restore test candidates available: {candidates_seen}, sampled: {sample_size}")
    return reservoir


def verify(
    args: argparse.Namespace,
    backup_file: str,
    backup_definition: str,
    config_settings: ConfigSettings,
    run_id: Optional[str] = None,
):
    """
    Verify the integrity of a DAR backup by performing the following steps:
    1. Run an archive integrity test on the backup file.
    2. Retrieve the list of backed up files.
    3. Restore a sample of files and compare content and metadata against the originals.
    4. Write per-file results to the metrics DB (no-op when metrics_db_path is unset).

    Args:
        args: Command-line arguments.
        backup_file: Path to the DAR backup file (no slice suffix).
        backup_definition: Path to the backup definition file.
        config_settings: An instance of the ConfigSettings class.
        run_id: UUID from the enclosing perform_backup() call; used to link
                restore_test_samples rows to the backup_runs row.  None when
                verify() is called standalone (samples are still collected but
                not written to the DB).

    Returns:
        VerifyResult with passed, restore_test_passed, and files_verified fields.

    Raises:
        BackupError: If the backup definition has no -R root path, the
                     restore directory cannot be created, or the dar archive
                     integrity test fails.
    """
    result = True
    command = ['dar', '-t', backup_file, '-N', '-Q']


    try:
        process = _runner().run(command, timeout=config_settings.command_timeout_secs)
    except KeyboardInterrupt:
        msg = (
            f"Verification interrupted (Ctrl-C or SIGTERM) for '{backup_file}'. "
            f"Archive integrity is unconfirmed."
        )
        logger.exception(msg)
        raise
    except Exception:
        logger.exception("Verification command could not be run for '%s'", backup_file)
        raise


    if process.returncode == 0:
        logger.info("Archive integrity test passed.")
    else:
        raise BackupError(str(process))

    if args.do_not_compare:
        return VerifyResult(passed=True, restore_test_passed=None, files_verified=0)

    # Materialise the generator so it can be iterated twice: once for the size
    # lookup dict and once by select_restoretest_samples.
    backed_up_files: list[tuple[str, Optional[str]]] = list(get_backed_up_files(
        backup_file,
        config_settings.backup_dir,
        timeout=config_settings.command_timeout_secs
    ))

    # Build size lookup before sampling so we can record file_size_bytes per sample.
    # Wrapped so a metrics failure here cannot abort the backup.
    try:
        size_lookup: dict[str, str] = {
            path: size for path, size in backed_up_files if path and size
        }
    except Exception as exc:  # noqa: BLE001 — logs with context and falls back to a safe default
        logger.warning(f"Failed to build size lookup for metrics; file_size_bytes will be NULL: {exc}")
        size_lookup = {}

    files = select_restoretest_samples(
        backed_up_files,
        config_settings,
        config_settings.no_files_verification
    )
    if len(files) == 0:
        logger.info(
            "No files eligible for verification after size and restore-test filters, skipping"
        )
        return VerifyResult(passed=True, restore_test_passed=None, files_verified=0)

    # find Root path in backup definition
    root_path = get_backup_definition_root(backup_definition)
    if root_path is None:
        msg = f"No Root (-R) path found in the backup definition file: '{backup_definition}', restore verification skipped"
        raise BackupError(msg)

    random_files = files

    # Ensure restore directory exists for verification restores
    try:
        os.makedirs(config_settings.test_restore_dir, exist_ok=True)
    except OSError as exc:
        raise BackupError(f"Cannot create restore directory '{config_settings.test_restore_dir}': {exc}") from exc

    samples: list[dict] = []
    tested_at = datetime.now(UTC).isoformat()

    for restored_file_path in random_files:
        restore_path = os.path.join(config_settings.test_restore_dir, restored_file_path.lstrip("/"))
        source_path = os.path.join(root_path, restored_file_path.lstrip("/"))

        try:
            sample: dict = {
                "file_path":       restored_file_path,
                "file_size_bytes": _parse_size_bytes(size_lookup.get(restored_file_path, "")),
                "result":          "PASS",
                "fail_reason_id":  None,
                "fail_detail":     None,
                "tested_at":       tested_at,
            }
        except Exception as exc:  # noqa: BLE001 — logs with context and falls back to a safe default
            logger.warning(f"Failed to initialise metrics sample for '{restored_file_path}': {exc}")
            sample = {
                "file_path":       restored_file_path,
                "file_size_bytes": None,
                "result":          "PASS",
                "fail_reason_id":  None,
                "fail_detail":     None,
                "tested_at":       tested_at,
            }

        _stale_removal_failed = False
        try:
            if os.path.exists(restore_path):
                try:
                    os.remove(restore_path)
                except OSError as exc:
                    result = False
                    sample["result"] = "FAIL"
                    sample["fail_reason_id"] = RESTORE_FAIL_PERMISSION_ERROR
                    sample["fail_detail"] = f"could not remove stale restore file: {exc}"[:500]
                    logger.exception(
                        "Cannot remove stale restore file '%s' — skipping restore-test for this file",
                        restore_path,
                    )
                    _stale_removal_failed = True
            if not _stale_removal_failed:
                if args.verbose:
                    logger.info(f"Restoring file: '{restored_file_path}' from backup to: '{config_settings.test_restore_dir}' for file comparing")  # noqa: E501
                ignore_ownership = resolve_ownership_flag(args, config_settings)
                command = [
                    'dar', '-x', backup_file, '-wa', '-g', restored_file_path.lstrip("/"),
                    '-R', config_settings.test_restore_dir, '--noconf', '-Q',
                ]
                if ignore_ownership:
                    command.append('--comparison-field=ignore-owner')
                command.extend(['-B', args.darrc, 'restore-options'])
                if args.verbose:
                    logger.info(f"Running command: {' '.join(map(shlex.quote, command))}")
                process = _runner().run(command, timeout = config_settings.command_timeout_secs)
                if process.returncode != 0:
                    raise BackupError(str(process))

                if not filecmp.cmp(restore_path, source_path, shallow=False):
                    result = False
                    sample["result"] = "FAIL"
                    sample["fail_reason_id"] = RESTORE_FAIL_CONTENT_MISMATCH
                    logger.error(f"Failure: file '{restored_file_path}' did not match the original")
                else:
                    mismatches = compare_metadata(source_path, restore_path, check_ownership=not ignore_ownership)
                    if mismatches:
                        result = False
                        sample["result"] = "FAIL"
                        sample["fail_reason_id"] = RESTORE_FAIL_METADATA_MISMATCH
                        sample["fail_detail"] = "; ".join(mismatches)[:500]
                        for m in mismatches:
                            logger.error(f"Metadata failure for '{restored_file_path}': {m}")
                    else:
                        if args.verbose:
                            logger.info(f"Success: file '{restored_file_path}' matches the original")

        except KeyboardInterrupt:
            msg = (
                f"Verification interrupted (Ctrl-C or SIGTERM) during restore-test of "
                f"'{restored_file_path}' from '{backup_file}'. Verification is incomplete."
            )
            logger.exception(msg)
            raise
        except PermissionError as exc:
            result = False
            sample["result"] = "FAIL"
            sample["fail_reason_id"] = RESTORE_FAIL_PERMISSION_ERROR
            sample["fail_detail"] = str(exc)[:500]
            logger.exception("Permission error while comparing files, continuing....")
            logger.error("Exception details:", exc_info=True)
        except FileNotFoundError as exc:
            result = False
            sample["result"] = "FAIL"
            missing_path = exc.filename or "unknown path"
            if missing_path == source_path:
                sample["fail_reason_id"] = RESTORE_FAIL_SOURCE_MISSING
                logger.exception(
                    f"Restore verification failed for '{restored_file_path}': source file missing: '{source_path}'"
                )
            elif missing_path == restore_path:
                sample["fail_reason_id"] = RESTORE_FAIL_RESTORED_MISSING
                logger.exception(
                    f"Restore verification failed for '{restored_file_path}': restored file missing: '{restore_path}'"
                )
            else:
                sample["fail_reason_id"] = RESTORE_FAIL_UNKNOWN_ERROR
                sample["fail_detail"] = f"file not found: {missing_path}"[:500]
                logger.exception(
                    f"Restore verification failed for '{restored_file_path}': file not found: '{missing_path}'"
                )
        except Exception as exc:
            result = False
            sample["result"] = "FAIL"
            sample["fail_reason_id"] = RESTORE_FAIL_UNKNOWN_ERROR
            sample["fail_detail"] = str(exc)[:500]
            logger.exception(f"Unexpected error verifying '{restored_file_path}'")

        try:
            samples.append(sample)
        except Exception as exc:  # noqa: BLE001 — logs with context and continues
            logger.warning(f"Failed to record metrics sample for '{restored_file_path}': {exc}")

    if run_id:
        try:
            write_restore_test_samples(
                run_id=run_id,
                backup_definition=os.path.basename(backup_definition),
                archive_name=os.path.basename(backup_file),
                samples=samples,
                config_settings=config_settings,
            )
        except Exception as exc:  # noqa: BLE001 — logs with context and continues
            logger.warning(f"Failed to write restore-test samples to metrics DB: {exc}")

    return VerifyResult(passed=result, restore_test_passed=result, files_verified=len(random_files))



def restore_backup(backup_name: str, config_settings: ConfigSettings, restore_dir: str, darrc: str,
                   selection: Optional[str] = None, ignore_ownership: bool = True, no_deleted: bool = False) -> None:
    """
    Restores a backup file to a specified directory.

    Args:
        backup_name (str): The base name of the backup file, without the "slice number.dar"
        config_settings (ConfigSettings): Parsed configuration.
        restore_dir (str): The directory where the backup should be restored to.
        darrc (str): Path to the .darrc file.
        selection (str, optional): A selection criteria to restore specific files or directories. Defaults to None.
        ignore_ownership (bool): When True, passes --comparison-field=ignore-owner to dar so uid/gid
            are not restored.  Defaults to True (safe for non-root).  Set to False only when running
            as root and RESTORE_OWNERSHIP = yes is configured.
        no_deleted (bool): When True, passes --deleted=ignore to dar so deletion records in DIFF/INCR
            archives do not cause errors when restoring to an empty directory.  Defaults to False.

    Raises:
        RestoreError: If the restore command fails or the restore directory cannot be created.
    """
    try:
        if ignore_ownership and os.getuid() == 0:
            logger.warning(
                "Running as root but ownership restoration is disabled. "
                "uid/gid will NOT be preserved. "
                "Set RESTORE_OWNERSHIP = yes in the config file to restore original ownership, "
                "or remove --ignore-ownership from the command line if you passed it explicitly."
            )
        backup_file = os.path.join(config_settings.backup_dir, backup_name)
        command = ['dar', '-x', backup_file, '-wa', '--noconf', '-Q']
        if "_FULL_" in backup_name:
            command.append('-D')
        if restore_dir:
            if not os.path.exists(restore_dir):
                os.makedirs(restore_dir)
            command.extend(['-R', restore_dir])
        else:
            raise RestoreError("Restore directory ('-R <dir>') not specified")
        if selection:
            selection_criteria = shlex.split(selection)
            command.extend(selection_criteria)
        if ignore_ownership:
            command.append('--comparison-field=ignore-owner')
        if no_deleted:
            command.append('--deleted=ignore')
        command.extend(['-B', darrc, 'restore-options'])  # the .darrc `restore-options` section
        logger.info(f"Running restore command: {' '.join(map(shlex.quote, command))}")
        process = _runner().run(command, timeout = config_settings.command_timeout_secs)
        if process.returncode == 0:
            logger.info(f"Restore completed successfully to: '{restore_dir}'")
        else:
            logger.error(f"Restore command failed: \n ==> stdout: {cast(str, process.stdout)}, \n ==> stderr: {cast(str, process.stderr)}")
            raise RestoreError(str(process))
    except subprocess.CalledProcessError as e:
        raise RestoreError(f"Restore command failed: {e}") from e
    except OSError as e:
        logger.exception("Failed to create restore directory")
        raise RestoreError("Could not create restore directory") from e
    except KeyboardInterrupt:
        msg = (
            f"Restore interrupted (Ctrl-C or SIGTERM) for '{backup_name}'. "
            f"The restore directory '{restore_dir}' may be incomplete and must NOT be used."
        )
        logger.exception(msg)
        raise
    except Exception as e:
        raise RestoreError(f"Unexpected error during restore: {e}") from e


def get_backed_up_files(backup_name: str, backup_dir: str, timeout: Optional[int] = None) -> Iterable[Tuple[str, Optional[str]]]:
    """
    Retrieves the list of backed up files from a DAR archive.

    Args:
        backup_name (str): The name of the DAR archive.
        backup_dir (str): The directory where the DAR archive is located.
        timeout (int, optional): Seconds before the dar process is killed. None means no timeout.

    Returns:
        Iterable[Tuple[str, Optional[str]]]: Stream of (file path, size) tuples for all backed
        up files; size is None if dar's XML listing omitted the size attribute.

    Raises:
        BackupError: If dar returns a non-zero exit code or an unexpected error occurs.
    """
    logger.debug("Getting backed up files in xml from DAR archive: '%s'", backup_name)
    backup_path = os.path.join(backup_dir, backup_name)
    command = ['dar', '-l', backup_path, '--noconf', '-am', '-as', '-Txml', '-Q']
    logger.debug("Running command: %s", ' '.join(map(shlex.quote, command)))

    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", delete=False, suffix=".xml") as temp_file:
            temp_path = temp_file.name

            def on_line(line: str) -> None:
                if "<!DOCTYPE" not in line:
                    temp_file.write(line + "\n")

            result = _runner().stream_command(command, on_line, timeout=timeout)
    except Exception as e:
        if temp_path:
            try:
                os.remove(temp_path)
            except OSError:
                logger.warning("Could not delete temporary file: %s", temp_path)
        raise BackupError(f"Unexpected error listing backed up files from DAR archive: '{backup_name}'") from e

    if result.returncode != 0:
        logger.error("Error listing backed up files from DAR archive: '%s'", backup_name)
        if temp_path:
            try:
                os.remove(temp_path)
            except OSError:
                logger.warning("Could not delete temporary file: %s", temp_path)
        raise BackupError(
            f"Error listing backed up files from DAR archive: '{backup_name}'"
            f"\nStderr: {cast(str, result.stderr) or ''}"
        )

    def iter_files() -> Iterator[Tuple[str, Optional[str]]]:
        try:
            yield from iter_files_with_paths_from_xml(temp_path)
        finally:
            try:
                os.remove(temp_path)
            except OSError:
                logger.warning("Could not delete temporary file: %s", temp_path)

    return iter_files()


def list_contents(backup_name, backup_dir, selection=None, timeout: Optional[int] = None):
    """
    Lists the contents of a backup.

    Args:
        backup_name (str): The name of the backup.
        backup_dir (str): The directory where the backup is located.
        selection (str, optional): The selection criteria for listing specific contents. Defaults to None.
        timeout (int, optional): Seconds before the dar process is killed. None means no timeout.

    Returns:
        None
    """
    backup_path = os.path.join(backup_dir, backup_name)
    command = ['dar', '-l', backup_path, '--noconf', '-am', '-as', '-Q']
    if selection:
        selection_criteria = shlex.split(selection)
        from dar_backup.command_runner import is_safe_arg
        for token in selection_criteria:
            if not is_safe_arg(token):
                raise ValueError(f"Unsafe token in --selection argument: {token!r}")
        command.extend(selection_criteria)

    def on_line(line: str) -> None:
        if "[--- REMOVED ENTRY ----]" in line or "[Saved]" in line:
            print(line)

    try:
        result = _runner().stream_command(command, on_line, timeout=timeout)
    except subprocess.CalledProcessError as e:
        logger.exception(f"Error listing contents of backup: '{backup_name}'")
        raise BackupError(f"Error listing contents of backup: '{backup_name}'") from e
    except (RuntimeError, BackupError):
        raise
    except Exception as e:
        logger.error(
            "Unexpected error listing contents of backup: '%s': %s",
            backup_name,
            e,
            exc_info=True,
        )
        raise RuntimeError(f"Unexpected error listing contents of backup: '{backup_name}'") from e

    if result.returncode != 0:
        logger.error(f"Error listing contents of backup: '{backup_name}'")
        raise RuntimeError(
            f"Error listing contents of backup: '{backup_name}'"
            f"\nStderr: {cast(str, result.stderr) or ''}"
        )




def create_backup_command(
    backup_type: str, backup_file: str, darrc: str, backup_definition_path: str,
    latest_base_backup: Optional[str] = None
) -> List[str]:
    """
    Generate the backup command for the specified backup type.

    Args:
        backup_type (str): The type of backup (FULL, DIFF, INCR).
        backup_file (str): The backup file path. Example: /path/to/example_2021-01-01_FULL
        darrc (str): Path to the .darrc configuration file.
        backup_definition_path (str): Path to the backup definition file.
        latest_base_backup (str, optional): Path to the latest base backup for DIFF or INCR types.

    Returns:
        List[str]: The constructed backup command.
    """
    base_command = ['dar', '-c', backup_file, "-N", '-B', darrc, '-B', backup_definition_path, '-Q', "compress-exclusion", "verbose"]

    if backup_type in ['DIFF', 'INCR']:
        if not latest_base_backup:
            raise ValueError(f"Base backup is required for {backup_type} backups.")
        base_command.extend(['-A', latest_base_backup])

    return base_command


def validate_required_directories(config_settings: ConfigSettings) -> None:
    """
    Ensure configured directories exist; raise if any are missing.
    """
    required = [
        ("BACKUP_DIR", config_settings.backup_dir),
        ("BACKUP.D_DIR", config_settings.backup_d_dir),
        ("TEST_RESTORE_DIR", config_settings.test_restore_dir),
    ]
    if config_settings.manager_db_dir:
        required.append(("MANAGER_DB_DIR", config_settings.manager_db_dir))

    missing = [(name, path) for name, path in required if not path or not os.path.isdir(path)]
    if missing:
        details = "; ".join(f"{name}={path}" for name, path in missing)
        raise RuntimeError(f"Required directories missing or not accessible: {details}")


def initialize_runtime_logging(args: argparse.Namespace, config_settings: ConfigSettings) -> str:
    """
    Configure runtime logging early so startup/preflight issues are captured.

    If the configured log files are unavailable, setup_logging() will fall back
    to temporary files or stderr so the run can continue.
    """
    global logger, runner
    runner = None

    logger, trace_log_file = init_logging(config_settings, args.log_level, args.log_stdout)
    command_logger = get_logger(command_output_logger=True)
    runner = CommandRunner(
        logger=logger,
        command_logger=command_logger,
        default_capture_limit_bytes=config_settings.command_capture_max_bytes,
    )

    return trace_log_file


def preflight_check(args: argparse.Namespace, config_settings: ConfigSettings) -> bool:
    """
    Run preflight checks to validate environment before backup.
    """
    errors: List[str] = []
    warnings: List[str] = []

    def check_dir(name: str, path: str, require_write: bool = True, issues=None):
        if issues is None:
            issues = errors
        error = validate_directory(path, name, require_write)
        if error:
            issues.append(error)

    def probe_write(name: str, path: str):
        if not path or not os.path.isdir(path):
            return
        probe_file = os.path.join(path, ".dar-backup-preflight")
        try:
            with open(probe_file, "w", encoding="utf-8") as f:
                f.write("ok")
        except Exception as exc:  # noqa: BLE001 — context captured in errors list, reported by the caller
            errors.append(f"Cannot write to {name} ({path}): {exc}")
        finally:
            try:
                if os.path.exists(probe_file):
                    os.remove(probe_file)
            except OSError:
                pass

    # Prod NFS mounts before checking — lazy mounts may not respond to
    # os.access() until the kernel establishes the connection.
    _nfs_dirs = [
        config_settings.backup_dir,
        config_settings.test_restore_dir,
        config_settings.manager_db_dir,
    ]
    for _d in _nfs_dirs:
        if _d and os.path.isdir(_d):
            try:
                os.listdir(_d)
            except OSError:
                pass  # let check_dir below report the real error

    # Directories and permissions
    check_dir("BACKUP_DIR", config_settings.backup_dir)
    check_dir("BACKUP.D_DIR", config_settings.backup_d_dir)
    check_dir("TEST_RESTORE_DIR", config_settings.test_restore_dir)
    if config_settings.manager_db_dir:
        check_dir("MANAGER_DB_DIR", config_settings.manager_db_dir)

    # Log directory write access
    log_dir = os.path.dirname(config_settings.logfile_location)
    check_dir("LOGFILE_LOCATION directory", log_dir, issues=warnings)

    # Write probes catch unavailable/stale mounts that may still pass os.access().
    probe_write("BACKUP_DIR", config_settings.backup_dir)
    probe_write("TEST_RESTORE_DIR", config_settings.test_restore_dir)
    if config_settings.manager_db_dir:
        probe_write("MANAGER_DB_DIR", config_settings.manager_db_dir)

    # Binaries present
    for cmd in ("dar",):
        if shutil.which(cmd) is None:
            errors.append(f"Binary not found on PATH: {cmd}")
    if config_settings.par2_enabled:
        if shutil.which("par2") is None:
            errors.append("Binary not found on PATH: par2 (required when PAR2.ENABLED is true)")

    # Binaries respond to --version (basic health)
    for cmd in ("dar",):
        cmd_path = shutil.which(cmd)
        if cmd_path:
            try:
                subprocess.run([cmd_path, "--version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)  # noqa: S603 — cmd_path resolved via shutil.which() above
            except Exception as exc:  # noqa: BLE001 — any failure to run '--version' is treated the same way; context captured in errors list
                errors.append(f"Failed to run '{cmd} --version': {exc}")
    par2_path = shutil.which("par2")
    if config_settings.par2_enabled and par2_path:
        try:
            subprocess.run([par2_path, "--version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)  # noqa: S603 — par2_path resolved via shutil.which() above
        except Exception as exc:  # noqa: BLE001 — any failure to run '--version' is treated the same way; context captured in errors list
            errors.append(f"Failed to run 'par2 --version': {exc}")

    # Config sanity: backup definition exists if provided
    if args.backup_definition:
        allow_unsafe = getattr(args, "allow_unsafe_definition_names", False)
        normalized_name = _normalize_backup_definition_name(
            args.backup_definition,
            allow_unsafe=allow_unsafe,
        )
        if not normalized_name:
            errors.append(
                f"Invalid backup definition name: '{args.backup_definition}' "
                f"({_BACKUP_DEFINITION_RULES}). Use {_BACKUP_DEFINITION_OPT_OUT} to disable this check."
            )
        else:
            candidate = os.path.join(config_settings.backup_d_dir, args.backup_definition)
            if not os.path.isfile(candidate):
                errors.append(f"Backup definition not found: {candidate}")

    if errors:
        print("Preflight checks failed:")
        logger.error("Preflight checks failed.")
        for err in errors:
            print(f" - {err}")
            logger.error("Preflight check failed: %s", err)
        return False

    if warnings:
        print("Preflight warnings:")
        for warning in warnings:
            print(f" - {warning}")
            logger.warning("Preflight warning: %s", warning)

    if os.environ.get("PYTEST_CURRENT_TEST"):
        print("Preflight checks passed.")
    logger.debug("Preflight checks passed.")

    return True


def _record_prereq_failure(
    args: argparse.Namespace,
    config_settings: ConfigSettings,
    stats_accumulator: list,
    error: RuntimeError,
    backup_type: str,
    run_id: Optional[str] = None,
) -> None:
    """
    Record a PREREQ failure in the metrics DB and stats accumulator for every
    backup definition that would have run.

    Called when requirements('PREREQ', ...) raises RuntimeError so that the
    Dashboard and SQLite DB show a FAILURE row even though no actual backup ran.

    Args:
        args: Parsed CLI arguments; args.backup_definition selects a single
              definition, or None/empty means all definitions.
        config_settings: Configuration settings object.
        stats_accumulator: List to append per-definition failure dicts to
                           (same list consumed by the Discord report).
        error: The RuntimeError raised by requirements().
        backup_type: One of "FULL", "DIFF", "INCR".
        run_id: UUID generated once per main() invocation so that
                postreq_status can be back-filled via UPDATE later.
    """
    if args.backup_definition:
        definitions = [args.backup_definition]
    else:
        try:
            definitions = list_definitions(config_settings.backup_d_dir)
        except Exception:
            logger.exception("_record_prereq_failure: could not list definitions")
            definitions = []

    now = datetime.now(UTC)
    error_summary = f"PREREQ failed: {error}"[:500]

    for definition in definitions:
        if definition.lower() == "example":
            continue
        metrics: dict = {
            "backup_definition":             definition,
            "backup_type":                   backup_type,
            "archive_name":                  "no archive produced",
            "dar_backup_version":            about.__version__,
            "dar_version":                   getattr(args, "dar_version", None),
            "run_started_at":                now.isoformat(),
            "backup_dir_free_bytes":         None,
            "run_finished_at":               now.isoformat(),
            "duration_secs":                 0.0,
            "dar_duration_secs":             None,
            "verify_duration_secs":          None,
            "par2_duration_secs":            None,
            "status":                        "FAILURE",
            "dar_exit_code":                 None,
            "failed_phase":                  "PREREQ",
            "error_summary":                 error_summary,
            "catalog_updated":               None,
            "verify_passed":                 None,
            "restore_test_passed":           None,
            "par2_passed":                   None,
            "archive_size_bytes":            None,
            "num_slices":                    None,
            "par2_size_bytes":               None,
            "files_verified":                None,
            "hostname":                      platform.node() or None,
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
            "run_id":                        run_id,
            "prereq_status":                 "FAILURE",
            "postreq_status":                None,
        }
        try:
            write_metrics_row(metrics, config_settings)
        except Exception as metrics_exc:  # noqa: BLE001 — logs with context and continues
            logger.warning("_record_prereq_failure: metrics write failed: %s", metrics_exc)

        stats_accumulator.append({
            "definition": definition,
            "status":     "FAILURE",
            "type":       backup_type,
            "end_time":   now.astimezone().isoformat(timespec='seconds'),
            "warning_count": 0,
            "error_count":   1,
        })


def perform_backup(
    args: argparse.Namespace,
    config_settings: ConfigSettings,
    backup_type: str,
    stats_accumulator: list,
    run_id: Optional[str] = None,
    prereq_status: Optional[str] = None,
) -> List[Tuple[str, int]]:
    """
    Perform backup operation.

    Args:
        args: Command-line arguments.
        config_settings: An instance of the ConfigSettings class.
        backup_type: Type of backup (FULL, DIFF, INCR).
        stats_accumulator: List to collect backup statuses.
        run_id: UUID generated once per main() invocation; written into every
                metrics row so that postreq_status can be back-filled via UPDATE.
        prereq_status: 'SUCCESS' if PREREQ ran and passed (always the case when
                       perform_backup is reached), or None if no PREREQ section.

    Returns:
      List[tuples] - each tuple consists of (<str message>, <exit code>)
    """
    backup_definitions = []
    results: List[tuple] = []

    # Gather backup definitions
    if args.backup_definition:
        allow_unsafe = getattr(args, "allow_unsafe_definition_names", False)
        normalized_name = _normalize_backup_definition_name(
            args.backup_definition,
            allow_unsafe=allow_unsafe,
        )
        if not normalized_name:
            msg = (
                f"Skipping backup definition: '{args.backup_definition}' "
                f"({_BACKUP_DEFINITION_RULES}). Use {_BACKUP_DEFINITION_OPT_OUT} to disable this check."
            )
            logger.error(msg)
            results.append((msg, 1))
            return results
        backup_definitions.append((normalized_name, os.path.join(config_settings.backup_d_dir, args.backup_definition)))
    else:
        for root, _, files in os.walk(config_settings.backup_d_dir):
            for file in files:
                normalized_name = _normalize_backup_definition_name(
                    file,
                    allow_unsafe=getattr(args, "allow_unsafe_definition_names", False),
                )
                if not normalized_name:
                    msg = (
                        f"Skipping backup definition: '{file}' "
                        f"({_BACKUP_DEFINITION_RULES}). Use {_BACKUP_DEFINITION_OPT_OUT} to disable this check."
                    )
                    logger.error(msg)
                    results.append((msg, 1))
                    continue
                backup_definitions.append((normalized_name, os.path.join(root, file)))

    for backup_definition, backup_definition_path in backup_definitions:
        start_len = len(results)
        success = True
        _current_phase = "DAR"

        # --- Per-definition banner ---
        def_start = datetime.now(UTC)
        _banner_text = f"  dar-backup {backup_type}  {backup_definition}  {def_start.astimezone().strftime('%Y-%m-%d %H:%M:%S')}  "
        _banner_bar  = "#" * (len(_banner_text) + 4)
        logger.info("")
        logger.info(_banner_bar)
        logger.info(f"##{_banner_text}##")
        logger.info(_banner_bar)
        try:
            _free_bytes = shutil.disk_usage(config_settings.backup_dir).free
        except OSError as e:
            logger.warning("Could not determine free space for '%s': %s", config_settings.backup_dir, e)
            _free_bytes = None
        metrics = {
            "backup_definition":             backup_definition,
            "backup_type":                   backup_type,
            "archive_name":                  None,
            "dar_backup_version":            about.__version__,
            "dar_version":                   getattr(args, "dar_version", None),
            "run_started_at":                def_start.isoformat(),
            "backup_dir_free_bytes":         _free_bytes,
            "run_finished_at":               None,
            "duration_secs":                 None,
            "dar_duration_secs":             None,
            "verify_duration_secs":          None,
            "par2_duration_secs":            None,
            "status":                        "FAILURE",
            "dar_exit_code":                 None,
            "failed_phase":                  None,
            "error_summary":                 None,
            "catalog_updated":               None,
            "verify_passed":                 None,
            "restore_test_passed":           None,
            "par2_passed":                   None,
            "archive_size_bytes":            None,
            "num_slices":                    None,
            "par2_size_bytes":               None,
            "files_verified":                None,
            "hostname":                      platform.node() or None,
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
            "run_id":                        run_id,
            "prereq_status":                 prereq_status,
            "postreq_status":                None,
        }

        backup_file: Optional[str] = None
        try:
            date = datetime.now().astimezone().strftime('%Y-%m-%d')
            backup_file = os.path.join(config_settings.backup_dir, f"{backup_definition}_{backup_type}_{date}")
            metrics["archive_name"] = os.path.basename(backup_file)

            if archive_exists(backup_file):
                msg = f"Backup file {backup_file}.1.dar already exists. Skipping backup [1]."
                logger.warning(msg)
                results.append((msg, 2))
                metrics["error_summary"] = msg
                continue

            latest_base_backup = None
            if backup_type in ['DIFF', 'INCR']:
                base_backup_type = 'FULL' if backup_type == 'DIFF' else 'DIFF'

                if args.alternate_reference_archive:
                    latest_base_backup = os.path.join(config_settings.backup_dir, args.alternate_reference_archive)
                    logger.info(f"Using alternate reference archive: {latest_base_backup}")
                    if not archive_exists(latest_base_backup):
                        msg = f"Alternate reference archive: \"{latest_base_backup}.1.dar\" does not exist, skipping..."
                        logger.error(msg)
                        results.append((msg, 1))
                        continue
                else:
                    base_backups = sorted(
                        [
                            f for f in os.listdir(config_settings.backup_dir)
                            if f.startswith(f"{backup_definition}_{base_backup_type}_") and f.endswith('.1.dar')
                        ],
                        key=lambda x: (p := ArchiveName.from_filename(x)) and p.as_datetime() or datetime.min
                    )
                    if not base_backups:
                        msg = (
                            f"Required parent backup missing for {backup_definition}: "
                            f"{base_backup_type} archive not found (needed for {backup_type})."
                        )
                        logger.error(msg)
                        results.append((msg, 1))
                        continue
                    latest_base_backup = os.path.join(config_settings.backup_dir, base_backups[-1].rsplit('.', 2)[0])

            # Generate the backup command
            command = create_backup_command(backup_type, backup_file, args.darrc, backup_definition_path, latest_base_backup)

            # --- DAR phase ---
            _t0 = datetime.now(UTC)
            # Once DAR starts, the archive is explicitly unpublished until a
            # later successful verification and catalog phase prove otherwise.
            metrics["catalog_updated"] = 0
            backup_result = generic_backup(backup_type, command, backup_file, backup_definition_path, args.darrc, config_settings, args)
            metrics["dar_duration_secs"] = (datetime.now(UTC) - _t0).total_seconds()
            metrics["dar_exit_code"]     = backup_result.dar_exit_code

            # Inode stats parsed from dar's summary output; any unparsed field stays None
            metrics.update(backup_result.dar_stats)

            # Somewhere <  version ~2.7.21 dar omits "Total number of inode(s) considered:" for DIFF/INCR.
            # Derive it from component counters so the column is never NULL when
            # the individual counters were parsed successfully.
            if metrics.get("inodes_total") is None:
                components = [
                    metrics.get("inodes_saved"),
                    metrics.get("inodes_not_saved"),
                    metrics.get("inodes_failed"),
                    metrics.get("inodes_excluded"),
                    metrics.get("inodes_deleted"),
                    metrics.get("inodes_metadata_only"),
                ]
                known = [v for v in components if v is not None]
                if known:
                    metrics["inodes_total"] = sum(cast(List[int], known))
                    logger.debug(
                        "inodes_total not in dar output (dar < ~2.7.21); "
                        "derived from components: %d", metrics["inodes_total"]
                    )

            # Archive slice count and total size
            dar_slices = _list_dar_slices(config_settings.backup_dir, os.path.basename(backup_file))
            metrics["num_slices"] = len(dar_slices)
            try:
                metrics["archive_size_bytes"] = sum(
                    os.path.getsize(os.path.join(config_settings.backup_dir, s)) for s in dar_slices
                )
            except OSError:
                # A missing slice means the archive is incomplete — this is a genuine failure.
                # Re-raise so the backup is marked FAILURE, but log clearly so the blame does
                # not fall on the dar phase (which already exited successfully).
                logger.exception(
                    "Archive slice missing or unreadable after dar completed for '%s'"
                    " — archive is incomplete, backup is FAILED",
                    backup_file,
                )
                raise

            # --- VERIFY phase ---
            _current_phase = "VERIFY"
            logger.info("Starting verification...")
            _t1 = datetime.now(UTC)
            verify_result = verify(args, backup_file, backup_definition_path, config_settings, run_id=run_id)
            metrics["verify_duration_secs"] = (datetime.now(UTC) - _t1).total_seconds()
            metrics["verify_passed"] = 1  # archive integrity passed (no exception raised)
            metrics["restore_test_passed"] = (
                1 if verify_result.restore_test_passed is True
                else 0 if verify_result.restore_test_passed is False
                else None
            )
            metrics["files_verified"] = verify_result.files_verified if verify_result.files_verified > 0 else None
            if verify_result:
                logger.info("Verification completed successfully.")

                # --- CATALOG phase ---
                # Registration is deliberately after verification. Publishing
                # an archive earlier creates a window where PITR can select a
                # backup that the same pipeline later rejects.
                _current_phase = "CATALOG"
                catalog_updated, catalog_issue = _register_backup_catalog(
                    backup_file,
                    config_settings,
                    args,
                )
                metrics["catalog_updated"] = 1 if catalog_updated else 0
                if catalog_issue is not None:
                    results.append(catalog_issue)
                    if metrics["failed_phase"] is None:
                        metrics["failed_phase"] = "CATALOG"
            else:
                msg = f"Verification of '{backup_file}' failed."
                logger.error(msg)
                results.append((msg, 1))
                if metrics["failed_phase"] is None:
                    metrics["failed_phase"] = "VERIFY"
                logger.error(
                    "Catalog registration skipped for '%s' because verification failed.",
                    backup_file,
                )

            # --- PAR2 phase ---
            _current_phase = "PAR2"
            logger.info("Generate par2 redundancy files.")
            _t2 = datetime.now(UTC)
            generate_par2_files(backup_file, config_settings, args, backup_definition=backup_definition)
            metrics["par2_duration_secs"] = (datetime.now(UTC) - _t2).total_seconds()
            metrics["par2_passed"] = 1
            logger.info("par2 files completed successfully.")

            # par2 total size
            par2_cfg = config_settings.get_par2_config(backup_definition) if hasattr(config_settings, "get_par2_config") else {}
            par2_dir = par2_cfg.get("par2_dir") or config_settings.backup_dir
            par2_files = glob.glob(os.path.join(par2_dir, f"{os.path.basename(backup_file)}*.par2"))
            if par2_files:
                # Measure per-file so a single missing file does not zero out the metric.
                # par2 files are redundancy protection, not the archive itself; a missing
                # file after successful generation is degraded but not a data-loss failure.
                par2_total = 0
                for p in par2_files:
                    try:
                        par2_total += os.path.getsize(p)
                    except OSError as exc:
                        logger.warning(
                            "Could not measure par2 file '%s': %s — excluded from size metric",
                            p, exc,
                        )
                metrics["par2_size_bytes"] = par2_total if par2_total > 0 else None

        except KeyboardInterrupt:
            msg = (
                f"Backup interrupted by user (Ctrl-C) during {_current_phase} phase "
                f"for '{backup_definition}'. "
                f"Any partial archive slices on disk are INCOMPLETE and must NOT be used for restore."
            )
            logger.exception(msg)
            results.append((msg, 1))
            metrics["failed_phase"] = metrics["failed_phase"] or _current_phase
            metrics["error_summary"] = msg[:500]
            success = False
            raise  # re-raise so the process still exits on Ctrl-C
        except Exception as e:
            if metrics["failed_phase"] is None:
                metrics["failed_phase"] = _current_phase
            if metrics["dar_exit_code"] is None:
                metrics["dar_exit_code"] = getattr(e, "dar_exit_code", None)
            results.append((f"Exception: {e}", 1))
            logger.error(f"Error during {backup_type} backup process for {backup_definition}: {e}", exc_info=True)
            success = False
        finally:
            # Determine status based on new results for this backup definition
            new_results = results[start_len:]
            has_error = any(code == 1 for _, code in new_results)
            has_warning = any(code == 2 for _, code in new_results)
            if has_error:
                success = False

            # Avoid spamming from example/demo backup definitions — skip both stats and metrics
            if backup_definition.lower() == "example":
                logger.debug("Skipping stats/metrics collection for example backup definition.")
            else:
                _existing_slices = glob.glob(f"{backup_file}.*.dar") if backup_file is not None else []
                slices_written = bool(_existing_slices)

                if not success or has_error or not slices_written:
                    status = "FAILURE"
                    if not slices_written and not has_error:
                        if backup_file is None:
                            msg = "Archive path not constructed — exception raised before backup path was set up"
                        else:
                            msg = f"No archive slices found for '{backup_file}' - backup may have failed silently"
                        logger.error(msg)
                        results.append((msg, 1))
                        metrics["error_summary"] = msg
                        metrics["failed_phase"] = metrics["failed_phase"] or "DAR"
                elif has_warning:
                    status = "WARNING"
                else:
                    status = "SUCCESS"

                # Finalise and write metrics row
                run_finished_at = datetime.now(UTC)
                metrics["run_finished_at"] = run_finished_at.isoformat()
                metrics["duration_secs"]   = (run_finished_at - def_start).total_seconds()
                metrics["status"]          = status
                if metrics["error_summary"] is None:
                    first_error = next(((msg, code) for msg, code in new_results if code != 0), None)
                    if first_error:
                        metrics["error_summary"] = first_error[0][:500]
                try:
                    write_metrics_row(metrics, config_settings)
                except Exception as metrics_exc:  # noqa: BLE001 — logs with context and continues
                    logger.warning(f"Metrics write failed (backup unaffected): {metrics_exc}")

                # Aggregate stats instead of sending immediately
                stats_accumulator.append({
                    "definition": backup_definition,
                    "status": status,
                    "type": backup_type,
                    "end_time": run_finished_at.astimezone().isoformat(timespec='seconds'),
                    "warning_count": sum(1 for _, code in new_results if code == 2),
                    "error_count": sum(1 for _, code in new_results if code == 1),
                })

    logger.trace(f"perform_backup() results[]: {results}")  # type: ignore[attr-defined]
    return results

def _parse_archive_base(backup_file: str) -> str:
    return os.path.basename(backup_file)


def _slice_number(pattern: "re.Pattern[str]", filename: str) -> int:
    """Extract the slice number from a filename already known to match *pattern*."""
    match = pattern.match(filename)
    assert match is not None, f"filename does not match slice pattern: {filename}"  # noqa: S101 — internal invariant — caller guarantees filename already matched pattern
    return int(match.group(1))


def _list_dar_slices(archive_dir: str, archive_base: str) -> List[str]:
    """List DAR slice filenames in numeric order.

    Args:
        archive_dir: Directory containing the archive slices.
        archive_base: Archive basename without a slice suffix.

    Returns:
        Matching slice filenames ordered by numeric slice number.
    """
    inventory = inspect_archive_slices(os.path.join(archive_dir, archive_base))
    return [os.path.basename(path) for path in inventory.slice_paths]


def _validate_slice_sequence(dar_slices: List[str], archive_base: str) -> None:
    pattern = re.compile(rf"{re.escape(archive_base)}\.([0-9]+)\.dar$")
    if not dar_slices:
        raise RuntimeError(f"No dar slices found for archive base: {archive_base}")
    slice_numbers = [_slice_number(pattern, s) for s in dar_slices]
    expected = list(range(1, max(slice_numbers) + 1))
    if slice_numbers != expected:
        raise RuntimeError(f"Missing dar slices for archive {archive_base}: expected {expected}, got {slice_numbers}")


def _get_backup_type_from_archive_base(archive_base: str) -> str:
    parts = archive_base.split('_')
    if len(parts) < 3:
        raise RuntimeError(f"Unexpected archive name format: {archive_base}")
    return parts[1]


def _get_par2_ratio(backup_type: str, par2_config: dict, default_ratio: int) -> int:
    backup_type = backup_type.upper()
    if backup_type == "FULL" and par2_config.get("par2_ratio_full") is not None:
        return par2_config["par2_ratio_full"]
    if backup_type == "DIFF" and par2_config.get("par2_ratio_diff") is not None:
        return par2_config["par2_ratio_diff"]
    if backup_type == "INCR" and par2_config.get("par2_ratio_incr") is not None:
        return par2_config["par2_ratio_incr"]
    return default_ratio


def _write_par2_manifest(
    manifest_path: str,
    archive_dir_relative: str,
    archive_base: str,
    archive_files: List[str],
    dar_backup_version: str,
    dar_version: str
) -> None:
    config = configparser.ConfigParser()
    config["MANIFEST"] = {
        "archive_dir_relative": archive_dir_relative,
        "archive_base": archive_base,
        "dar_backup_version": dar_backup_version,
        "dar_version": dar_version,
        "created_utc": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    config["ARCHIVE_FILES"] = {
        "files": "\n".join(archive_files)
    }

    with open(manifest_path, "w", encoding="utf-8") as f:
        config.write(f)


def _default_par2_config(config_settings: ConfigSettings) -> dict:
    return {
        "par2_dir": config_settings.par2_dir,
        "par2_ratio_full": config_settings.par2_ratio_full,
        "par2_ratio_diff": config_settings.par2_ratio_diff,
        "par2_ratio_incr": config_settings.par2_ratio_incr,
        "par2_run_verify": config_settings.par2_run_verify,
        "par2_enabled": config_settings.par2_enabled,
    }


def generate_par2_files(backup_file: str, config_settings: ConfigSettings, args, backup_definition: Optional[str] = None):
    """
    Generate PAR2 files for a given backup file in the specified backup directory.

    Args:
        backup_file (str): The name of the backup file.
        config_settings: The configuration settings object.
        args: The command-line arguments object.
        backup_definition (str): The backup definition name used for per-backup overrides.

    Raises:
        subprocess.CalledProcessError: If the par2 command fails to execute.

    Returns:
        None
    """
    if hasattr(config_settings, "get_par2_config"):
        par2_config = config_settings.get_par2_config(backup_definition)
    else:
        par2_config = _default_par2_config(config_settings)
    if not par2_config.get("par2_enabled", False):
        logger.debug("PAR2 disabled for this backup definition, skipping.")
        return

    archive_dir = config_settings.backup_dir
    archive_base = _parse_archive_base(backup_file)
    backup_type = _get_backup_type_from_archive_base(archive_base)
    par2_dir = par2_config.get("par2_dir")
    if par2_dir:
        par2_dir = os.path.expanduser(os.path.expandvars(par2_dir))
        os.makedirs(par2_dir, exist_ok=True)

    ratio = _get_par2_ratio(backup_type, par2_config, config_settings.error_correction_percent)

    dar_slices = _list_dar_slices(archive_dir, archive_base)
    _validate_slice_sequence(dar_slices, archive_base)
    number_of_slices = len(dar_slices)

    par2_output_dir = par2_dir or archive_dir

    # Run par2 per-slice so that each invocation sees only one ~slice-sized input.
    # Previously (commit 998906f, Jan 2026) this was changed to pass all slices in
    # one command, which caused par2 to hold a recovery matrix proportional to the
    # full archive size in RAM — OOM on large archives.  Per-slice preserves the
    # -B portability flag: paths stored inside each par2 set are still relative to
    # archive_dir, so the files remain relocatable across mount points.
    #
    # Each slice's par2 set is self-contained.  On failure we do NOT abort — we
    # continue to the remaining slices so 9 out of 10 good redundancy files is
    # better than stopping at the first failure and producing none.  Failed slices
    # are collected and reported at the end; the function then raises so the caller
    # marks this backup as FAILURE while still continuing to the next definition.
    failed_slices: list[str] = []
    succeeded_slices: list[str] = []

    for counter, slice_file in enumerate(dar_slices, start=1):
        slice_path = os.path.join(archive_dir, slice_file)
        par2_path = os.path.join(par2_output_dir, f"{slice_file}.par2")
        logger.info(f"{counter}/{number_of_slices}: Generating par2 for {slice_file}")
        if par2_dir:
            command = ['par2', 'create', '-B', archive_dir, f'-r{ratio}', '-q', '-q', par2_path, slice_path]
        else:
            command = ['par2', 'create', f'-r{ratio}', '-q', '-q', slice_path]
        process = _runner().run(command, timeout=config_settings.command_timeout_secs)
        if process.returncode != 0:
            logger.error(
                "%d/%d: par2 create failed for %s (returncode=%d) — continuing to remaining slices",
                counter, number_of_slices, slice_file, process.returncode,
            )
            failed_slices.append(slice_file)
            continue

        if par2_config.get("par2_run_verify"):
            logger.info(f"{counter}/{number_of_slices}: Verifying par2 for {slice_file}")
            verify_command = ['par2', 'verify', '-B', archive_dir, par2_path]
            verify_process = _runner().run(verify_command, timeout=config_settings.command_timeout_secs)
            if verify_process.returncode != 0:
                logger.error(
                    "%d/%d: par2 verify failed for %s (returncode=%d) — continuing to remaining slices",
                    counter, number_of_slices, slice_file, verify_process.returncode,
                )
                failed_slices.append(slice_file)
                continue

        succeeded_slices.append(slice_file)
        logger.info(f"{counter}/{number_of_slices}: Done")

    if failed_slices:
        if succeeded_slices:
            logger.error(
                "PAR2 generation incomplete for '%s': %d/%d slice(s) failed — %s. "
                "%d slice(s) have par2 coverage: %s",
                archive_base, len(failed_slices), number_of_slices, ", ".join(failed_slices),
                len(succeeded_slices), ", ".join(succeeded_slices),
            )
        else:
            logger.error(
                "PAR2 generation failed for '%s': all %d slice(s) failed — %s",
                archive_base, number_of_slices, ", ".join(failed_slices),
            )
        # Write a partial manifest so operators can see which slices have coverage.
        if par2_dir and succeeded_slices:
            archive_dir_relative = os.path.relpath(archive_dir, par2_dir)
            manifest_path = os.path.join(par2_output_dir, f"{archive_base}.par2.manifest.ini")
            _write_par2_manifest(
                manifest_path=manifest_path,
                archive_dir_relative=archive_dir_relative,
                archive_base=archive_base,
                archive_files=succeeded_slices,
                dar_backup_version=about.__version__,
                dar_version=getattr(args, "dar_version", "unknown"),
            )
            logger.info("Wrote partial par2 manifest (%d/%d slices): %s", len(succeeded_slices), number_of_slices, manifest_path)
        raise subprocess.CalledProcessError(1, ["par2", "create"])

    # All slices succeeded — write the full manifest.
    if par2_dir:
        archive_dir_relative = os.path.relpath(archive_dir, par2_dir)
        manifest_path = os.path.join(par2_output_dir, f"{archive_base}.par2.manifest.ini")
        _write_par2_manifest(
            manifest_path=manifest_path,
            archive_dir_relative=archive_dir_relative,
            archive_base=archive_base,
            archive_files=dar_slices,
            dar_backup_version=about.__version__,
            dar_version=getattr(args, "dar_version", "unknown")
        )
        logger.info(f"Wrote par2 manifest: {manifest_path}")
    return


def filter_darrc_file(darrc_path):
    """
    Filters the .darrc file to remove lines containing the options: -vt, -vs, -vd, -vf, and -va.
    The filtered version is stored in a uniquely named file alongside the source .darrc
    (or a writable temp directory if needed).
    The file permissions are set to 440.

    Params:
      darrc_path: Path to the original .darrc file.

    Raises:
      RuntimeError if something went wrong

    Returns:
      Path to the filtered .darrc file.
    """
    # Define options to filter out
    options_to_remove = {"-vt", "-vs", "-vd", "-vf", "-va"}

    candidate_dirs = [
        os.path.dirname(os.path.abspath(darrc_path)),
        os.path.expanduser("~"),
        tempfile.gettempdir(),
    ]
    last_error = None

    for candidate_dir in candidate_dirs:
        filtered_darrc_path = None
        try:
            fd, filtered_darrc_path = tempfile.mkstemp(
                suffix=".darrc", prefix="filtered_darrc_", dir=candidate_dir
            )
            with os.fdopen(fd, "w") as outfile, open(darrc_path) as infile:
                for line in infile:
                    # Check if any unwanted option is in the line
                    if not any(option in line for option in options_to_remove):
                        outfile.write(line)

            # Set file permissions to 440 (read-only for owner and group, no permissions for others)
            os.chmod(filtered_darrc_path, 0o440)

            return filtered_darrc_path

        except Exception as e:  # noqa: BLE001 — context captured (last_error), re-raised with full detail after the loop
            last_error = e
            if filtered_darrc_path and os.path.exists(filtered_darrc_path):
                os.remove(filtered_darrc_path)

    raise RuntimeError(f"Error filtering .darrc file: {last_error}")




def show_examples():
    examples = """
FULL back of all backup definitions in backup.d:
  'python3 dar-backup.py  --full-backup'

FULL back of a single backup definition in backup.d
  'python3 dar-backup.py --full-backup -d <name of file in backup.d/>'

DIFF backup (differences to the latest FULL) of all backup definitions:
  'python3 dar-backup.py --differential-backup'

DIFF back of a single backup definition in backup.d
  'python3 dar-backup.py --differential-backup -d <name of file in backup.d/>'

INCR backup (differences to the latest DIFF) of all backup definitions:
  'python3 dar-backup.py --incremental-backup'

INCR back of a single backup definition in backup.d
  'python3 dar-backup.py --incremental-backup -d <name of file in backup.d/>'

Point In Time Restore (PITR) of 2 directories into a target location:
  'manager --backup-def homedir \
  --restore-path "Documents/Taxes" "Documents/Receipts" \
  --when "2026-01-15 08:00" \
  --target /tmp/restore_docs'

--alternate-reference-archive (useful if the calculated archive is broken)
    Use this to specify a different reference archive for DIFF or INCR backups.
    The specified archive can be any regardsless of type,  name does not include the slice number.
    Example: 'python3 dar-backup.py --differential-backup --alternate-reference-archive <name of dar archive>'

--log-level
    "trace" logs output from programs (typically dar and par2) run in a subprocess
    "debug" logs various statuses and notices to better understand how to script works

--log-stdout
     Print log messages to screen

--selection

    --selection takes dar file selection options inside a quoted string.

    💡 Shell quoting matters! Always wrap the entire selection string in double quotes to avoid shell splitting.

    ✅ Use:   --selection="-I '*.NEF'"
    ❌ Avoid: --selection "-I '*.NEF'" → may break due to how your shell parses it.

    Examples:
    1)
    select file names with "Z50_" in file names:
        python3 dar-backup.py --restore <name of dar archive>  --selection="-I '*Z50_*'"
    2)
    Filter out *.xmp files:
        python3 dar-backup.py --restore <name of dar archive>  --selection="-X '*.xmp'"

    3)
    Include all files in a directory:
        python3 dar-backup.py --restore <name of dar archive>  --selection="-g 'path/to/a/dir'"

    4)
    Exclude a directory:
        python3 dar-backup.py --restore <name of dar archive>  --selection="-P 'path/to/a/dir'"

    See dar documentation on file selection: http://dar.linux.free.fr/doc/man/dar.html#COMMANDS%20AND%20OPTIONS
"""
    print(examples)



def print_markdown(source: str, from_string: bool = False, pretty: bool = True):
    """
    Print Markdown content either from a file or directly from a string.

    Args:
        source: Path to the file or Markdown string itself.
        from_string: If True, treat `source` as Markdown string instead of file path.
        pretty: If True, render with rich formatting if available.
    """
    import os
    import sys

    content = ""
    if from_string:
        content = source
    else:
        if not os.path.exists(source):
            print(f"❌ File not found: {source}")
            sys.exit(1)
        with open(source, encoding="utf-8") as f:
            content = f.read()

    if pretty:
        try:
            from rich.console import Console
            from rich.markdown import Markdown
            console = Console()
            console.print(Markdown(content))
        except ImportError:
            print("⚠️ 'rich' not installed. Falling back to plain text.\n")
            print(content)
    else:
        print(content)



def _resolve_doc_path(path: Optional[str], filename: str) -> Path:
    if path:
        return Path(path)

    candidates = [
        Path.cwd() / "src" / "dar_backup" / filename,
        Path(__file__).parent / filename,
    ]

    try:
        candidates.append(Path(__file__).resolve().parents[2] / filename)
    except IndexError:
        pass

    for candidate in candidates:
        if candidate.exists():
            return candidate

    return candidates[0]


def print_changelog(path: Optional[str] = None, pretty: bool = True):
    resolved_path = _resolve_doc_path(path, "Changelog.md")
    print_markdown(str(resolved_path), pretty=pretty)


def print_readme(path: Optional[str] = None, pretty: bool = True):
    resolved_path = _resolve_doc_path(path, "README.md")
    print_markdown(str(resolved_path), pretty=pretty)


def _list_available_docs() -> list[str]:
    """Return sorted list of doc names available in the installed package.

    Returns:
        Sorted list of doc stems (filenames without .md extension),
        or an empty list if the doc directory cannot be found.
    """
    for doc_dir in [
        Path(__file__).parent / "doc",
        Path.cwd() / "src" / "dar_backup" / "doc",
    ]:
        if doc_dir.is_dir():
            return sorted(p.stem for p in doc_dir.glob("*.md"))
    return []


def _doc_completer(prefix: str, **kwargs) -> list[str]:
    """Argcomplete completer for --doc and --doc-pretty.

    Args:
        prefix: Characters typed so far.

    Returns:
        Doc stems that start with prefix.
    """
    return [name for name in _list_available_docs() if name.startswith(prefix)]


def print_doc(name: str, pretty: bool = False) -> None:
    """Print a documentation file from the installed doc/ directory.

    Args:
        name: Doc filename stem without .md extension (e.g. 'getting-started').
        pretty: If True, render with rich Markdown formatting.

    Raises:
        SystemExit: If the named doc cannot be found.
    """
    candidates = [
        Path(__file__).parent / "doc" / f"{name}.md",
        Path.cwd() / "src" / "dar_backup" / "doc" / f"{name}.md",
    ]
    for candidate in candidates:
        if candidate.exists():
            print_markdown(str(candidate), pretty=pretty)
            return

    available = _list_available_docs()
    print(f"❌ Doc '{name}' not found.", file=stderr)
    if available:
        print(f"Available docs: {', '.join(available)}", file=stderr)
    raise SystemExit(1)


def list_definitions(backup_d_dir: str, *, allow_unsafe: bool = False) -> List[str]:
    """
    Return backup definition filenames from BACKUP.D_DIR, sorted by name.
    """
    dir_path = Path(backup_d_dir)
    if not dir_path.is_dir():
        raise RuntimeError(f"BACKUP.D_DIR does not exist or is not a directory: {backup_d_dir}")
    valid: List[str] = []
    for entry in dir_path.iterdir():
        if not entry.is_file():
            continue
        if _normalize_backup_definition_name(entry.name, allow_unsafe=allow_unsafe):
            valid.append(entry.name)
        else:
            print(
                f"Warning: skipping invalid backup definition '{entry.name}' "
                f"({_BACKUP_DEFINITION_RULES}). Use {_BACKUP_DEFINITION_OPT_OUT} to disable this check.",
                file=stderr,
            )
    return sorted(valid)


def clean_restore_test_directory(config_settings: ConfigSettings):
    """
    Cleans up the restore test directory to ensure a clean slate.
    """
    restore_dir = config_settings.test_restore_dir
    if not restore_dir:
        return

    restore_dir = os.path.expanduser(os.path.expandvars(restore_dir))

    if not os.path.exists(restore_dir):
        return

    # Safety: Do not delete if it resolves to a critical path
    # "/tmp" here is a deny-list entry being checked against, not a temp file write — S108 false positive.
    critical_paths = ["/", "/home", "/root", "/usr", "/var", "/etc", "/tmp", "/opt", "/bin", "/sbin", "/boot", "/dev", "/proc", "/sys", "/run"]  # noqa: S108
    normalized = os.path.realpath(restore_dir)

    # Check exact matches
    if normalized in critical_paths:
        logger.warning(f"Refusing to clean critical directory: {normalized}")
        return

    # Check if it's the user's home directory
    home = os.path.expanduser("~")
    if normalized == home:
        logger.warning(f"Refusing to clean user home directory: {normalized}")
        return

    logger.debug(f"Cleaning restore test directory: {restore_dir}")
    try:
        for item in os.listdir(restore_dir):
            item_path = os.path.join(restore_dir, item)
            try:
                if os.path.isfile(item_path) or os.path.islink(item_path):
                    os.unlink(item_path)
                elif os.path.isdir(item_path):
                    shutil.rmtree(item_path)
            except Exception as e:  # noqa: BLE001 — logs with context and continues
                logger.warning(f"Failed to remove {item_path}: {e}")
    except Exception as e:  # noqa: BLE001 — logs with context and continues
        logger.warning(f"Failed to clean restore directory {restore_dir}: {e}")

def _normalize_restore_dir(path: Optional[str]) -> Optional[str]:
    if not path:
        return None
    return os.path.realpath(os.path.expanduser(os.path.expandvars(path)))


def should_clean_restore_test_directory(args: argparse.Namespace, config_settings: ConfigSettings) -> bool:
    if args.full_backup or args.differential_backup or args.incremental_backup:
        return not getattr(args, "do_not_compare", False)

    if args.restore:
        restore_dir = args.restore_dir if getattr(args, "restore_dir", None) else config_settings.test_restore_dir
        restore_dir_norm = _normalize_restore_dir(restore_dir)
        test_restore_dir_norm = _normalize_restore_dir(config_settings.test_restore_dir)
        return restore_dir_norm is not None and restore_dir_norm == test_restore_dir_norm

    return False


def main() -> None:
    """CLI entrypoint: parse arguments and dispatch to the requested operation.

    Handles -F/-D/-I (FULL/DIFF/INCR backup), --list/--list-contents,
    --list-definitions, --restore (PITR-aware restore), --preflight-check, and
    the various --readme/--changelog/--doc/--examples/--version print-and-exit
    flags. Initializes logging and the module-level logger/runner globals used
    by the rest of this module, acquires the per-config instance lock for
    backup runs, and runs PREREQ/POSTREQ around the requested operation.

    Every code path terminates via sys.exit()/exit(); this function never
    returns normally.
    """
    global logger, runner
    results: List[Tuple[str, int]] = []  # a list of tuples (<msg>, <exit code>)

    # Install a SIGTERM handler so that `kill <pid>` (SIGTERM) triggers the
    # same KeyboardInterrupt handling chain as Ctrl-C (SIGINT).  Without this,
    # SIGTERM terminates the process immediately without running finally blocks,
    # meaning metrics are not written and partial slices on disk go unrecorded.
    def _sigterm_handler(signum, frame):
        raise KeyboardInterrupt("SIGTERM received — backup terminated by kill signal")
    signal.signal(signal.SIGTERM, _sigterm_handler)

    MIN_PYTHON_VERSION = (3, 9)
    if version_info < MIN_PYTHON_VERSION:
        stderr.write(f"Error: This script requires Python {'.'.join(map(str, MIN_PYTHON_VERSION))} or higher.\n")
        exit(1)

    parser = argparse.ArgumentParser(description="Backup, verify & redundancy using dar and par2.")
    parser.add_argument('-F', '--full-backup', action='store_true', help="Perform a full backup.")
    parser.add_argument('-D', '--differential-backup', action='store_true', help="Perform differential backup.")
    parser.add_argument('-I', '--incremental-backup', action='store_true', help="Perform incremental backup.")
    parser.add_argument('-d', '--backup-definition', help="Specific 'recipe' to select directories and files.").completer = backup_definition_completer  # type: ignore[attr-defined] # noqa: E501
    parser.add_argument('--alternate-reference-archive', help="DIFF or INCR compared to specified archive.").completer = list_archive_completer  # type: ignore[attr-defined]
    parser.add_argument('-c', '--config-file', type=str, help="Path to 'dar-backup.conf'", default=None)
    parser.add_argument('--darrc', type=str, help='Optional path to .darrc')
    parser.add_argument(
        '-l',
        '--list',
        nargs='?',
        const=True,
        default=False,
        help="List available archives.",
    ).completer = list_archive_completer  # type: ignore[attr-defined]
    parser.add_argument('--list-contents', help="List the contents of the specified archive.").completer = list_archive_completer  # type: ignore[attr-defined]
    parser.add_argument('--list-definitions', action='store_true', help="List available backup definitions from BACKUP.D_DIR.")
    parser.add_argument(
        '--allow-unsafe-definition-names',
        action='store_true',
        help="Disable backup definition name validation (allows underscores or other characters).",
    )
    parser.add_argument('--selection', type=str, help="Selection string to pass to 'dar', e.g. --selection=\"-I '*.NEF'\"")
#    parser.add_argument('-r', '--restore', nargs=1, type=str, help="Restore specified archive.")
    parser.add_argument('-r', '--restore', type=str, help="Restore specified archive.").completer = list_archive_completer  # type: ignore[attr-defined]
    parser.add_argument('--restore-dir',   type=str, help="Directory to restore files to.")
    parser.add_argument('--verbose', action='store_true', help="Print various status messages to screen")
    parser.add_argument('--preflight-check', action='store_true', help="Run preflight checks and exit")
    parser.add_argument('--suppress-dar-msg', action='store_true', help="cancel dar options in .darrc: -vt, -vs, -vd, -vf and -va")
    parser.add_argument('--log-level', type=str, help="`debug` or `trace`", default="info")
    parser.add_argument('--log-stdout', action='store_true', help='also print log messages to stdout')
    parser.add_argument('--do-not-compare', action='store_true', help="do not compare restores to file system")
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
    parser.add_argument('--examples', action="store_true", help="Examples of using dar-backup.py.")
    parser.add_argument("--readme", action="store_true", help="Print README.md to stdout and exit.")
    parser.add_argument("--readme-pretty", action="store_true", help="Print README.md to stdout with Markdown styling and exit.")
    parser.add_argument("--changelog", action="store_true", help="Print Changelog.md to stdout and exit.")
    parser.add_argument("--changelog-pretty", action="store_true", help="Print Changelog.md to stdout with Markdown styling and exit.")
    doc_arg = parser.add_argument(
        "--doc", metavar="NAME",
        help="Print a documentation file by name and exit (use tab completion to list available docs).",
    )
    doc_arg.completer = _doc_completer  # type: ignore[attr-defined]
    doc_pretty_arg = parser.add_argument("--doc-pretty", metavar="NAME", help="Print a documentation file with Markdown styling and exit.")
    doc_pretty_arg.completer = _doc_completer  # type: ignore[attr-defined]
    parser.add_argument('-v', '--version', action='store_true', help="Show version and license information.")

    argcomplete.autocomplete(parser)
    args = parser.parse_args()
    # Ensure new flags are present when parse_args is mocked in tests
    if not hasattr(args, "preflight_check"):
        args.preflight_check = False
    if not hasattr(args, "list_definitions"):
        args.list_definitions = False
    if not hasattr(args, "allow_unsafe_definition_names"):
        args.allow_unsafe_definition_names = False
    if not hasattr(args, "ignore_ownership"):
        args.ignore_ownership = False
    if not hasattr(args, "preserve_ownership"):
        args.preserve_ownership = False
    if not hasattr(args, "no_deleted"):
        args.no_deleted = False
    if not hasattr(args, "doc"):
        args.doc = None
    if not hasattr(args, "doc_pretty"):
        args.doc_pretty = None

    if args.version:
        show_version()
        exit(0)
    elif args.examples:
        show_examples()
        exit(0)
    elif args.readme:
        print_readme(None, pretty=False)
        exit(0)
    elif args.readme_pretty:
        print_readme(None, pretty=True)
        exit(0)
    elif args.changelog:
        print_changelog(None, pretty=False)
        exit(0)
    elif args.changelog_pretty:
        print_changelog(None, pretty=True)
        exit(0)
    elif args.doc:
        print_doc(args.doc, pretty=False)
        exit(0)
    elif args.doc_pretty:
        print_doc(args.doc_pretty, pretty=True)
        exit(0)


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
        # config_settings is unbound here (ConfigSettings() raised), so the
        # webhook can only come from the environment variable; passing the
        # unbound name raised UnboundLocalError and masked the config error.
        send_discord_message(f"{ts} - dar-backup: FAILURE - config settings error)\n---- End of report ----")
        exit(127)

    if args.list_definitions:
        try:
            for name in list_definitions(
                config_settings.backup_d_dir,
                allow_unsafe=args.allow_unsafe_definition_names,
            ):
                print(name)
        except RuntimeError as exc:
            print(str(exc), file=stderr)
            exit(127)
        exit(0)

    trace_log_file = initialize_runtime_logging(args, config_settings)

    try:
        validate_required_directories(config_settings)
    except RuntimeError as exc:
        logger.exception("Required directories not found")
        ts = datetime.now().astimezone().strftime("%Y-%m-%d_%H:%M")
        send_discord_message(f"{ts} - dar-backup: FAILURE - required directories not found\n---- End of report ----", config_settings=config_settings)
        print(str(exc), file=stderr)
        exit(127)

    # Run preflight checks always; if --preflight-check is set, exit afterward.
    ok = preflight_check(args, config_settings)
    if not ok:
        logger.error("Aborting run because preflight checks failed.")
        ts = datetime.now().astimezone().strftime("%Y-%m-%d_%H:%M")
        send_discord_message(f"{ts} - dar-backup: FAILURE - preflight checks failed\n---- End of report ----", config_settings=config_settings)
        exit_code = 127 if args.backup_definition else 1
        exit(exit_code)
    if args.preflight_check:
        exit(0)

    if should_clean_restore_test_directory(args, config_settings):
        clean_restore_test_directory(config_settings)


    filtered_darrc_path = None
    is_backup_run = args.full_backup or args.differential_backup or args.incremental_backup
    _lock_fh:   Optional[IO[str]] = None
    _lock_path: Optional[str]     = None

    try:
        if not args.darrc:
            current_script_dir = os.path.dirname(os.path.abspath(__file__))
            args.darrc = os.path.join(current_script_dir, ".darrc")

        darrc_file = os.path.expanduser(os.path.expandvars(args.darrc))
        if os.path.exists(darrc_file) and os.path.isfile(darrc_file):
            logger.debug(f"Using .darrc: {args.darrc}")
        else:
            msg = f"Supplied .darrc: '{args.darrc}' does not exist or is not a file, exiting"
            logger.error(msg)
            print(msg, file=stderr)
            exit(127)

        if args.suppress_dar_msg:
            logger.info("Suppressing dar messages, do not use options: -vt, -vs, -vd, -vf, -va")
            filtered_darrc_path = filter_darrc_file(args.darrc)
            args.darrc = filtered_darrc_path
            logger.debug(f"Filtered .darrc file: {args.darrc}")

        start_msgs: List[Tuple[str, str]] = []

        start_time=int(time())
        run_start = datetime.now().astimezone()
        run_id = str(uuid.uuid4())
        start_msgs.append((f"{show_scriptname()}:", about.__version__))
        try:
            operation = None
            if args.full_backup:
                operation = "FULL backup"
            elif args.differential_backup:
                operation = "DIFF backup"
            elif args.incremental_backup:
                operation = "INCR backup"
            elif args.list:
                operation = "list archives"
            elif args.list_contents:
                operation = "list contents"
            elif args.restore:
                operation = "restore"
            if operation:
                start_msgs.append(("Operation:", operation))
        except Exception as exc:  # noqa: BLE001 — logs with context and falls back to a safe default
            logger.warning("Could not determine operation: %s", exc)
            start_msgs.append(("Operation:", "unknown"))
        if is_backup_run:
            backup_type = "FULL" if args.full_backup else "DIFF" if args.differential_backup else "INCR"
            run_start_str = run_start.strftime("%Y-%m-%d %H:%M:%S")
            banner_text = f"  dar-backup {backup_type}  {run_start_str}  "
            banner_bar = "#" * (len(banner_text) + 4)
            logger.info("")
            logger.info(banner_bar)
            logger.info(f"##{banner_text}##")
            logger.info(banner_bar)
            logger.info(f"START TIME: {start_time}")
        logger.debug(f"Command line:\n{get_invocation_command_line()}")
        logger.debug(f"`Args`:\n{args}")
        logger.debug(f"`Config_settings`:\n{config_settings}")
        dar_properties = get_binary_info(command='dar')
        args.dar_version = dar_properties.get('version', 'unknown')
        start_msgs.append(('dar path:', dar_properties['path']))
        start_msgs.append(('dar version:', dar_properties['version']))

        file_dir =  os.path.normpath(os.path.dirname(__file__))
        start_msgs.append(('Script directory:', os.path.abspath(file_dir)))
        start_msgs.append(('Config file:', os.path.abspath(args.config_file)))
        start_msgs.append((".darrc location:", args.darrc))

        restore_dir = args.restore_dir if args.restore_dir else config_settings.test_restore_dir
        if args.verbose:
            if args.backup_definition:
                start_msgs.append(("Backup definition:", args.backup_definition))
            if args.alternate_reference_archive:
                start_msgs.append(("Alternate ref archive:", args.alternate_reference_archive))
            start_msgs.append(("Backup.d dir:", config_settings.backup_d_dir))
            start_msgs.append(("Backup dir:", config_settings.backup_dir))
            start_msgs.append(("Restore dir:", restore_dir))
            start_msgs.append(("Logfile location:", config_settings.logfile_location))
            start_msgs.append(("Trace log:", trace_log_file))
            start_msgs.append(("Logfile max size (bytes):", str(config_settings.logfile_max_bytes)))
            start_msgs.append(("Logfile backup count:", str(config_settings.logfile_backup_count)))
            start_msgs.append(("PAR2 enabled:", str(config_settings.par2_enabled)))
            start_msgs.append(("--do-not-compare:", args.do_not_compare))

        highlight_keywords = ["--do-not", "alternate"] # TODO: add more dangerous keywords
        print_aligned_settings(start_msgs, quiet=not args.verbose, highlight_keywords=highlight_keywords)

        # sanity check
        if args.backup_definition and not os.path.exists(os.path.join(config_settings.backup_d_dir, args.backup_definition)):
            logger.error(f"Backup definition: '{args.backup_definition}' does not exist, exiting")
            exit(127)
        if args.backup_definition:
            normalized_name = _normalize_backup_definition_name(
                args.backup_definition,
                allow_unsafe=args.allow_unsafe_definition_names,
            )
            if not normalized_name:
                logger.error(
                    f"Backup definition: '{args.backup_definition}' is invalid "
                    f"({_BACKUP_DEFINITION_RULES}). Use {_BACKUP_DEFINITION_OPT_OUT} to disable this check."
                )
                exit(1)


        # --- Instance lock: one backup run per config at a time ---
        if is_backup_run:
            config_abs  = os.path.realpath(args.config_file)
            lock_name   = config_abs.replace('/', '_').replace(' ', '_').lstrip('_') + '.lock'
            lock_dir    = '/run/lock' if os.path.isdir('/run/lock') else tempfile.gettempdir()
            _lock_path  = os.path.join(lock_dir, lock_name)
            _lock_fh    = open(_lock_path, 'w')
            try:
                fcntl.flock(_lock_fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
                logger.debug("Lock acquired: %s (pid %d)", _lock_path, os.getpid())
            except BlockingIOError:
                _lock_fh.close()
                _lock_fh = None
                _bt  = "FULL" if args.full_backup else "DIFF" if args.differential_backup else "INCR"
                _err = RuntimeError(
                    f"Another dar-backup instance is already running (lock: {_lock_path})"
                )
                logger.exception(str(_err))
                _record_prereq_failure(args, config_settings, [], _err, _bt, run_id=run_id)
                exit(1)

        prereq_report: dict = {"status": "none", "failures": []}
        prereq_failed: Optional[RuntimeError] = None
        try:
            requirements('PREREQ', config_settings, report_out=prereq_report)
        except RuntimeError as prereq_err:
            logger.exception("PREREQ failed")
            prereq_failed = prereq_err
            results.append((str(prereq_err), 1))

        prereq_status: Optional[str] = (
            None          if prereq_report["status"] == "none"
            else "FAILURE" if prereq_failed is not None
            else "SUCCESS"
        )

        stats: List[dict] = []

        if prereq_failed is not None:
            backup_type = (
                "FULL" if args.full_backup
                else "DIFF" if args.differential_backup
                else "INCR" if args.incremental_backup
                else "FULL"
            )
            _record_prereq_failure(args, config_settings, stats, prereq_failed, backup_type, run_id=run_id)
        elif args.list:
            list_filter = args.backup_definition
            if isinstance(args.list, str):
                if list_filter:
                    if args.list.startswith(list_filter):
                        list_filter = args.list
                else:
                    list_filter = args.list
            list_backups(config_settings.backup_dir, list_filter)
        elif args.full_backup and not args.differential_backup and not args.incremental_backup:
            results.extend(perform_backup(args, config_settings, "FULL", stats, run_id=run_id, prereq_status=prereq_status))
        elif args.differential_backup and not args.full_backup and not args.incremental_backup:
            results.extend(perform_backup(args, config_settings, "DIFF", stats, run_id=run_id, prereq_status=prereq_status))
        elif args.incremental_backup  and not args.full_backup and not args.differential_backup:
            results.extend(perform_backup(args, config_settings, "INCR", stats, run_id=run_id, prereq_status=prereq_status))
            logger.debug(f"results from perform_backup(): {results}")
        elif args.list_contents:
            list_contents(args.list_contents, config_settings.backup_dir, args.selection, timeout=config_settings.command_timeout_secs)
        elif args.restore:
            logger.debug(f"Restoring {args.restore} to {restore_dir}")
            ignore_ownership = resolve_ownership_flag(args, config_settings)
            # restore_backup() raises RestoreError on failure (handled by the outer
            # try) and has no per-file issues to accumulate, so it is called directly.
            restore_backup(args.restore, config_settings, restore_dir, args.darrc, args.selection,
                           ignore_ownership=ignore_ownership,
                           no_deleted=args.no_deleted)
        else:
            parser.print_help()

        logger.debug(f"results[]: {results}")

        # POSTREQ: capture result without short-circuiting so the report is always sent
        postreq_report: dict = {"status": "none", "failures": []}
        postreq_failed = False
        try:
            requirements('POSTREQ', config_settings, report_out=postreq_report)
        except RuntimeError as postreq_err:
            logger.exception("POSTREQ failed")
            results.append((str(postreq_err), 1))
            postreq_failed = True

        if postreq_report["status"] != "none":
            postreq_db_status = "FAILURE" if postreq_failed else "SUCCESS"
            update_postreq_status(run_id, postreq_db_status, config_settings)

        # Send unified Discord report for any backup run
        if stats:
            run_end = datetime.now().astimezone()
            msg = render_discord_report(
                start_time=run_start.isoformat(timespec='seconds'),
                end_time=run_end.isoformat(timespec='seconds'),
                backups=sorted(stats, key=lambda s: s['definition']),
                prereqs=prereq_report,
                postreqs=postreq_report,
            )
            send_discord_message(msg, config_settings=config_settings)


    except Exception as e:
        msg = f"Unexpected error: {e}"
        logger.error(msg, exc_info=True)
        ts = datetime.now().astimezone().strftime("%Y-%m-%d_%H:%M")
        send_discord_message(f"{ts} - dar-backup: FAILURE - {msg}\n---- End of report ----", config_settings=config_settings)
        results.append((repr(e), 1))
    finally:
        if is_backup_run:
            end_time=int(time())
            logger.info(f"END TIME: {end_time}")
        if _lock_fh is not None:
            try:
                fcntl.flock(_lock_fh, fcntl.LOCK_UN)
                _lock_fh.close()
                logger.debug("Lock released: %s", _lock_path)
            except Exception as _lock_exc:  # noqa: BLE001 — logs with context and continues (lock release is best-effort)
                logger.warning("Failed to release instance lock %s: %s", _lock_path, _lock_exc)
        # Clean up
        if filtered_darrc_path and os.path.exists(filtered_darrc_path):
            os.remove(filtered_darrc_path)
            logger.debug(f"Removed filtered .darrc: {filtered_darrc_path}")


    # Determine exit code
    error = False
    final_exit_code = 0
    logger.debug(f"results[]: {results}")
    if results:
        i = 0
        for result in results:
            if isinstance(result, tuple) and len(result) == 2:
                msg, exit_code = result
                logger.debug(f"exit code: {exit_code}, msg: {msg}")
                if exit_code > 0:
                    error = True
                    args.verbose and print(msg)
                    if exit_code == 1:
                        final_exit_code = 1
                    elif exit_code == 2 and final_exit_code == 0:
                        final_exit_code = 2
            else:
                logger.error(f"not correct result type: {result}, which must be a tuple (<msg>, <exit_code>)")
                error = True
                final_exit_code = 1
            i=i+1

    console = Console()
    if error:
        if args.verbose:
            console.print(Text("Errors encountered", style="bold red"))
        exit(final_exit_code or 1)
    else:
        if args.verbose:
            console.print(Text("Success: all backups completed", style="bold green"))
        exit(0)


if __name__ == "__main__":
    main()
