#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later

"""
cleanup.py source code is here: https://github.com/per2jensen/dar-backup

Licensed under GNU GENERAL PUBLIC LICENSE v3, see the supplied file "LICENSE" for details.

THERE IS NO WARRANTY FOR THE PROGRAM, TO THE EXTENT PERMITTED BY APPLICABLE LAW,
not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
See section 15 and section 16 in the supplied "LICENSE" file

This script removes old DIFF and INCR archives + accompanying .par2 files according to the
[AGE] settings in the configuration file.
"""

import argcomplete
import argparse
import os
import re
import sys
from datetime import datetime, timedelta
from inputimeout import inputimeout, TimeoutOccurred
from pathlib import Path
from sys import stderr
from time import time
from typing import List, Optional, Tuple, cast
import glob


from . import __about__ as about
from dar_backup.config_settings import ConfigSettings
from dar_backup.util import list_backups
from dar_backup.util import init_logging
from dar_backup.util import get_config_file
from dar_backup.util import get_logger
from dar_backup.util import requirements
from dar_backup.util import show_version
from dar_backup.util import get_invocation_command_line
from dar_backup.util import print_aligned_settings
from dar_backup.util import backup_definition_completer, list_archive_completer
from dar_backup.util import is_archive_name_allowed
from dar_backup.util import ArchiveName
from dar_backup.util import safe_remove_file
from dar_backup.util import validate_directory
from dar_backup.util import show_scriptname
from dar_backup.util import send_discord_message

from dar_backup.command_runner import CommandRunner
from dar_backup.command_runner import CommandResult

logger = get_logger()
runner: Optional[CommandRunner] = None


def _runner() -> CommandRunner:
    assert runner is not None, "CommandRunner not initialized; call main() first"  # noqa: S101 — internal invariant, not user input — module must be initialized by main()
    return runner


def _remove_file(file_path: str, base_dir: Path, label: str, dry_run: bool) -> bool:
    """Delete one file, respecting dry_run and logging the outcome.

    Args:
        file_path: Absolute path of the file to remove.
        base_dir: Base directory passed to safe_remove_file for path-safety check.
        label: Short human-readable name used in log messages (e.g. "archive slice").
        dry_run: When True, only log what would happen; do not touch the filesystem.

    Returns:
        True if the file was removed or would have been removed in dry_run mode,
        False if safe_remove_file rejected the path or an exception occurred.
    """
    try:
        if dry_run:
            logger.info(f"Dry run: would delete {label}: {file_path}")
            return True
        removed = safe_remove_file(file_path, base_dir=base_dir)
        if removed:
            logger.info(f"Deleted {label}: {file_path}")
        else:
            logger.warning(f"Skipped deleting unsafe {label}: {file_path}")
        return removed
    except OSError:
        logger.exception(f"Error deleting {label} '{file_path}' — file remains on disk")
        return False


def _delete_par2_files(
    archive_name: str,
    backup_dir: str,
    config_settings: Optional[ConfigSettings] = None,
    backup_definition: Optional[str] = None,
    dry_run: bool = False,
) -> None:
    if config_settings and hasattr(config_settings, "get_par2_config"):
        par2_config = config_settings.get_par2_config(backup_definition)
    else:
        par2_config = {
            "par2_dir": None,
        }

    par2_dir = par2_config.get("par2_dir") or backup_dir
    par2_dir = os.path.expanduser(os.path.expandvars(par2_dir))
    if not os.path.isdir(par2_dir):
        logger.warning(f"PAR2 directory not found, skipping cleanup: {par2_dir}")
        return

    par2_glob = os.path.join(par2_dir, f"{archive_name}*.par2")
    targets = set(glob.glob(par2_glob))
    manifest_path = os.path.join(par2_dir, f"{archive_name}.par2.manifest.ini")
    if os.path.exists(manifest_path):
        targets.add(manifest_path)

    par2_regex = re.compile(rf"^{re.escape(archive_name)}\.[0-9]+\.dar.*\.par2$")
    for entry in os.scandir(par2_dir):
        if not entry.is_file():
            continue
        filename = entry.name
        if par2_regex.match(filename):
            targets.add(entry.path)

    if not targets:
        logger.info("No par2 files matched the cleanup patterns.")
        return

    for file_path in sorted(targets):
        _remove_file(file_path, Path(par2_dir), "PAR2 file", dry_run)


def delete_old_backups(backup_dir, age, backup_type, args, backup_definition=None, config_settings: Optional[ConfigSettings] = None):
    """
    Delete backups older than the specified age in days.
    Only .dar and .par2 files are considered for deletion.
    """
    logger.info(f"Deleting {backup_type} backups older than {age} days in {backup_dir} for backup definition: {backup_definition}")

    if backup_type not in ['DIFF', 'INCR']:
        logger.error(f"Invalid backup type: {backup_type}")
        return

    # Must stay naive: compared below against ArchiveName.as_datetime(), which is
    # also naive (archive filenames carry a calendar date only, no timezone).
    now = datetime.now()  # noqa: DTZ005
    cutoff_date = now - timedelta(days=age)

    archives_deleted = {}

    dry_run = getattr(args, "dry_run", False) is True
    for entry in os.scandir(backup_dir):
        if not entry.is_file():
            continue
        filename = entry.name
        if not filename.endswith('.dar'):
            continue
        if backup_definition and not filename.startswith(f"{backup_definition}_"):
            # Match on "<definition>_" so that a definition which is a prefix
            # of another (e.g. "media" vs "media2") cannot delete the other
            # definition's archives.
            continue
        if backup_type in filename:
            parsed = ArchiveName.from_filename(filename)
            file_date = parsed.as_datetime() if parsed else None
            if file_date is None:
                logger.warning(f"Skipping file with invalid date format: {filename}")
                continue

            if file_date < cutoff_date:
                file_path = entry.path
                if _remove_file(file_path, Path(backup_dir), f"{backup_type} backup", dry_run):
                    archive_name = filename.split('.')[0]
                    if archive_name not in archives_deleted:
                        logger.debug(f"Archive name: '{archive_name}' added to catalog deletion list")
                    archives_deleted[archive_name] = True

    for archive_name in archives_deleted.keys():
        if not is_archive_name_allowed(archive_name):
            raise ValueError(f"Refusing unsafe archive name: {archive_name}")
        _parsed_name = ArchiveName.parse(archive_name)
        archive_definition = _parsed_name.definition if _parsed_name else archive_name.split('_')[0]
        _delete_par2_files(archive_name, backup_dir, config_settings, archive_definition, dry_run=dry_run)
        if dry_run:
            logger.info(f"Dry run: would run manager to delete archive '{archive_name}'")
        else:
            if not delete_catalog(archive_name, args):
                logger.error(
                    "Catalog entry for '%s' was not removed — archive files are deleted but catalog entry remains",
                    archive_name,
                )


def delete_archive(backup_dir, archive_name, args, config_settings: Optional[ConfigSettings] = None):
    """
    Delete all .dar and .par2 files in the backup directory for the given archive name.

    This function will delete any type of archive, including FULL.
    """
    logger.info(f"Deleting all .dar and .par2 files for archive: `{archive_name}`")
    # Regex to match the archive files according to the naming convention
    archive_regex = re.compile(rf"^{re.escape(archive_name)}\.[0-9]+\.dar$")

    # Delete the specified .dar files according to the naming convention
    files_deleted = False
    dry_run = getattr(args, "dry_run", False) is True
    for entry in os.scandir(backup_dir):
        if not entry.is_file():
            continue
        filename = entry.name
        if archive_regex.match(filename):
            file_path = entry.path
            if _remove_file(file_path, Path(backup_dir), "archive slice", dry_run):
                files_deleted = True

    if files_deleted:
            if dry_run:
                logger.info(f"Dry run: would run manager to delete archive '{archive_name}'")
            else:
                if not delete_catalog(archive_name, args):
                    logger.error(
                        "Catalog entry for '%s' was not removed — archive files are deleted but catalog entry remains",
                        archive_name,
                    )
    else:
        logger.info("No .dar files matched the regex for deletion.")

    _an = ArchiveName.parse(archive_name)
    archive_definition = _an.definition if _an else archive_name.split('_')[0]
    _delete_par2_files(archive_name, backup_dir, config_settings, archive_definition, dry_run=dry_run)


def delete_catalog(catalog_name: str, args: argparse.Namespace) -> bool:
    """
    Call `manager.py` to delete the specified catalog in it's database
    """
    command = ["manager", "--remove-specific-archive", catalog_name, "--config-file", args.config_file, '--log-level', 'debug', '--log-stdout']
    logger.info(f"Deleting catalog '{catalog_name}' using config file: '{args.config_file}'")
    remediate = (
        f"To fix the stale catalog entry run: "
        f"manager --remove-specific-archive '{catalog_name}' --config-file '{args.config_file}'"
    )
    try:
        result:CommandResult = _runner().run(command)
        if result.returncode == 0:
            logger.info(f"Deleted catalog '{catalog_name}', using config file: '{args.config_file}'")
            logger.debug(f"Stdout: manager.py --remove-specific-archive output:\n{cast(str, result.stdout)}")
            return True
        elif result.returncode == 2:
            logger.warning(f"catalog '{catalog_name}' not found in the database, skipping deletion")
            return True
        else:
            logger.error(
                "Failed to remove catalog entry for '%s' (returncode=%d): %s — "
                "dar files are already deleted from disk. %s",
                catalog_name, result.returncode, result.stderr.strip(), remediate,
            )
            return False
    except OSError:
        logger.exception(
            "Failed to run manager for catalog '%s' — "
            "dar files are already deleted from disk. %s",
            catalog_name, remediate,
        )
        return False


def confirm_full_archive_deletion(archive_name: str, test_mode=False) -> bool:
    try:
        if test_mode:
            answer = os.getenv("CLEANUP_TEST_DELETE_FULL", "").lower()
            print(f"Simulated confirmation for FULL archive '{archive_name}': {answer}")
            return answer == "yes"
        else:
            confirmation = inputimeout(
                prompt=f"Are you sure you want to delete the FULL archive '{archive_name}'? (yes/no): ",
                timeout=30)
        if confirmation is None:
            logger.info(f"No confirmation received for FULL archive: {archive_name}. Skipping deletion.")
            return False
        return confirmation.strip().lower() == "yes"
    except TimeoutOccurred:
        logger.info(f"Timeout waiting for confirmation for FULL archive: {archive_name}. Skipping deletion.")
        return False
    except KeyboardInterrupt:
        logger.info(f"User interrupted confirmation for FULL archive: {archive_name}. Skipping deletion.")
        return False



def main() -> None:
    """CLI entrypoint: parse arguments and dispatch to the requested cleanup operation.

    Handles --list, --cleanup-specific-archives (and the positional archive-name
    list), and the default per-definition DIFF/INCR age-based cleanup. Initializes
    logging and the module-level logger/runner globals used by the rest of this
    module.

    Every code path terminates via sys.exit() with an appropriate exit code; this
    function never returns normally.
    """
    global logger, runner

    parser = argparse.ArgumentParser(description="Cleanup old archives according to AGE configuration.")
    parser.add_argument('-d', '--backup-definition', help="Specific backup definition to cleanup.").completer = backup_definition_completer  # type: ignore[attr-defined]
    parser.add_argument('-c', '--config-file', type=str, help="Path to 'dar-backup.conf'", default=None)
    parser.add_argument('-v', '--version', action='store_true', help="Show version information.")
    parser.add_argument('--alternate-archive-dir', type=str, help="Cleanup in this directory instead of the default one.")
    parser.add_argument(
        '--cleanup-specific-archives',
        type=str,
        nargs='?',
        const="",
        default=None,
        help="Comma separated list of archives to cleanup",
    ).completer = list_archive_completer  # type: ignore[attr-defined]
    parser.add_argument(
        'cleanup_specific_archives_list',
        nargs='*',
        help=argparse.SUPPRESS,
    ).completer = list_archive_completer  # type: ignore[attr-defined]
    parser.add_argument('-l', '--list', action='store_true', help="List available archives.")
    parser.add_argument('--verbose', action='store_true', help="Print various status messages to screen")
    parser.add_argument('--log-level', type=str, help="`debug` or `trace`, default is `info`", default="info")
    parser.add_argument('--log-stdout', action='store_true', help='also print log messages to stdout')
    parser.add_argument('--test-mode', action='store_true', help='Read envvars in order to run some pytest cases')
    parser.add_argument('--dry-run', action='store_true', help='Show what would be deleted without removing files')

    comp_line = os.environ.get("COMP_LINE", "")
    only_archives = "--cleanup-specific-archives" in comp_line
    argcomplete.autocomplete(parser, always_complete_options=not only_archives)

    args = parser.parse_args()

    if args.version:
        show_version()
        sys.exit(0)

    config_settings_path = get_config_file(args)
    if not (os.path.isfile(config_settings_path) and os.access(config_settings_path, os.R_OK)):
        if args.test_mode or os.getenv("PYTEST_CURRENT_TEST"):
            args.config_file = config_settings_path
        else:
            print(f"Config file {config_settings_path} must exist and be readable.", file=stderr)
            raise SystemExit(127)
    args.config_file = config_settings_path

    try:
        config_settings = ConfigSettings(args.config_file)
    except Exception as exc:  # noqa: BLE001 — CLI-boundary catch: logs with context, reports, and exits
        msg = f"Config error: {exc}"
        print(msg, file=stderr)
        ts = datetime.now().astimezone().strftime("%Y-%m-%d_%H:%M")
        send_discord_message(f"{ts} - cleanup: FAILURE - {msg}")
        sys.exit(127)

    logger, _ = init_logging(config_settings, args.log_level, args.log_stdout)
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
        if args.list:
            operation = "list archives"
        elif args.cleanup_specific_archives is not None:
            operation = "cleanup specific archives"
        else:
            operation = "cleanup"
        if args.dry_run:
            operation += " (dry run)"
        start_msgs.append(("Operation:", operation))
    except Exception as exc:  # noqa: BLE001 — logs with context and falls back to a safe default
        logger.warning("Could not determine operation: %s", exc)
        start_msgs.append(("Operation:", "unknown"))

    logger.debug(f"Command line: {get_invocation_command_line()}")
    logger.debug(f"`args`:\n{args}")
    logger.debug(f"`config_settings`:\n{config_settings}")

    file_dir =  os.path.normpath(os.path.dirname(__file__))
    if args.verbose:
        start_msgs.append(("Script directory:", file_dir))
    start_msgs.append(("Config file:", args.config_file))
    if args.verbose:
        start_msgs.append(("Backup dir:", config_settings.backup_dir))
    start_msgs.append(("Logfile:", config_settings.logfile_location))
    if args.verbose:
        start_msgs.append(("Logfile max size (bytes):", str(config_settings.logfile_max_bytes)))
        start_msgs.append(("Logfile backup count:", str(config_settings.logfile_backup_count)))
        start_msgs.append(("--alternate-archive-dir:", str(args.alternate_archive_dir)))
        start_msgs.append(("--cleanup-specific-archives:", str(args.cleanup_specific_archives)))
        start_msgs.append(("--dry-run:", str(args.dry_run)))

    dangerous_keywords = ["--cleanup", "_FULL_"] # TODO: add more dangerous keywords
    print_aligned_settings(start_msgs, highlight_keywords=dangerous_keywords, quiet=not args.verbose)

    # run PREREQ scripts
    try:
        requirements('PREREQ', config_settings)
    except Exception as exc:
        msg = f"PREREQ failed: {exc}"
        logger.exception(msg)
        ts = datetime.now().astimezone().strftime("%Y-%m-%d_%H:%M")
        send_discord_message(f"{ts} - cleanup: FAILURE - {msg}", config_settings=config_settings)
        sys.exit(1)

    try:
        if args.alternate_archive_dir:
            error = validate_directory(args.alternate_archive_dir, "Alternate archive directory", require_write=False)
            if error:
                logger.error(f"{error}, exiting")
                sys.exit(1)
            config_settings.backup_dir = args.alternate_archive_dir

        if args.cleanup_specific_archives is None and args.test_mode:
            logger.info("No --cleanup-specific-archives provided; skipping specific archive deletion in test mode.")

        if args.cleanup_specific_archives or args.cleanup_specific_archives_list:
            combined = []
            if args.cleanup_specific_archives:
                combined.extend(args.cleanup_specific_archives.split(','))
            combined.extend(args.cleanup_specific_archives_list or [])
            archive_names = [name.strip() for name in combined if name.strip()]
            logger.info(f"Cleaning up specific archives: {', '.join(archive_names)}")
            for archive_name in archive_names:
                if not is_archive_name_allowed(archive_name):
                    logger.error(f"Refusing unsafe archive name: {archive_name}")
                    continue
                if "_FULL_" in archive_name:
                    if not confirm_full_archive_deletion(archive_name, args.test_mode):
                        continue
                archive_path = os.path.join(config_settings.backup_dir, archive_name.strip())
                logger.info(f"Deleting archive: {archive_path}")
                delete_archive(config_settings.backup_dir, archive_name.strip(), args, config_settings)
        elif args.list:
            list_backups(config_settings.backup_dir, args.backup_definition)
        else:
            backup_definitions = []
            if args.backup_definition:
                backup_definitions.append(args.backup_definition)
            else:
                for _root, _, files in os.walk(config_settings.backup_d_dir):
                    for file in files:
                        backup_definitions.append(file.split('.')[0])

            for definition in backup_definitions:
                delete_old_backups(
                    config_settings.backup_dir,
                    config_settings.diff_age,
                    'DIFF',
                    args,
                    backup_definition=definition,
                    config_settings=config_settings
                )
                delete_old_backups(
                    config_settings.backup_dir,
                    config_settings.incr_age,
                    'INCR',
                    args,
                    backup_definition=definition,
                    config_settings=config_settings
                )
    except Exception as e:
        msg = f"Unexpected error during cleanup: {e}"
        logger.error(msg, exc_info=True)
        ts = datetime.now().astimezone().strftime("%Y-%m-%d_%H:%M")
        send_discord_message(f"{ts} - cleanup: FAILURE - {msg}", config_settings=config_settings)
        sys.exit(1)

    # run POST scripts
    try:
        requirements('POSTREQ', config_settings)
    except Exception as exc:
        msg = f"POSTREQ failed: {exc}"
        logger.exception(msg)
        ts = datetime.now().astimezone().strftime("%Y-%m-%d_%H:%M")
        send_discord_message(f"{ts} - cleanup: FAILURE - {msg}", config_settings=config_settings)
        sys.exit(1)


    end_time=int(time())
    logger.info(f"END TIME: {end_time}")
    sys.exit(0)

if __name__ == "__main__":
    main()
