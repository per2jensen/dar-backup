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
import os
import re
import sys
import subprocess

from inputimeout import inputimeout, TimeoutOccurred


from . import __about__ as about
from dar_backup.config_settings import ConfigSettings
from dar_backup.util import setup_logging
from dar_backup.util import CommandResult
from dar_backup.util import get_logger
from dar_backup.util import get_binary_info
from dar_backup.util import show_version
from dar_backup.util import get_invocation_command_line
from dar_backup.util import print_aligned_settings
from dar_backup.util import show_scriptname

from dar_backup.command_runner import CommandRunner   
from dar_backup.command_runner import CommandResult
from dar_backup.util import backup_definition_completer, list_archive_completer, archive_content_completer, add_specific_archive_completer

from datetime import datetime
from time import time
from typing import Dict, List, NamedTuple, Tuple

# Constants
SCRIPTNAME = os.path.basename(__file__)
SCRIPTPATH = os.path.realpath(__file__)
SCRIPTDIRPATH = os.path.dirname(SCRIPTPATH)
DB_SUFFIX = ".db"

logger = None
runner = None


def get_db_dir(config_settings: ConfigSettings) -> str:
    """
    Return the correct directory for storing catalog databases.
    Uses manager_db_dir if set, otherwise falls back to backup_dir.
    """
    return getattr(config_settings, "manager_db_dir", None) or config_settings.backup_dir


def show_more_help():
    help_text = f"""
NAME
    {SCRIPTNAME} - creates/maintains `dar` databases with catalogs for backup definitions
"""
    print(help_text)


def create_db(backup_def: str, config_settings: ConfigSettings, logger, runner) -> int:
    db_dir = get_db_dir(config_settings)

    if not os.path.exists(db_dir):
        logger.error(f"DB dir does not exist: {db_dir}")
        return 1
    if not os.path.isdir(db_dir):
        logger.error(f"DB path exists but is not a directory: {db_dir}")
        return 1
    if not os.access(db_dir, os.W_OK):
        logger.error(f"DB dir is not writable: {db_dir}")
        return 1

    database = f"{backup_def}{DB_SUFFIX}"
    database_path = os.path.join(db_dir, database)

    logger.debug(f"DB directory: {db_dir}")

    if os.path.exists(database_path):
        logger.info(f'"{database_path}" already exists, skipping creation')
        return 0
    else:
        logger.info(f'Create catalog database: "{database_path}"')
        command = ['dar_manager', '--create', database_path]
        process = runner.run(command)
        logger.debug(f"return code from 'db created': {process.returncode}")
        if process.returncode == 0:
            logger.info(f'Database created: "{database_path}"')
        else:
            logger.error(f'Something went wrong creating the database: "{database_path}"')
            stdout, stderr = process.stdout, process.stderr
            logger.error(f"stderr: {stderr}")
            logger.error(f"stdout: {stdout}")

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
    process = runner.run(command)
    stdout, stderr = process.stdout, process.stderr

    if process.returncode != 0:
        logger.error(f'Error listing catalogs for: "{database_path}"')
        logger.error(f"stderr: {stderr}")
        logger.error(f"stdout: {stdout}")
        return process

    # Extract only archive basenames from stdout
    archive_names = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line or "archive #" in line or "dar path" in line or "compression" in line:
            continue
        parts = line.split("\t")
        if len(parts) >= 3:
            archive_names.append(parts[2].strip())

    # Sort by prefix and date
    def extract_date(arch_name):
        match = re.search(r"(\d{4}-\d{2}-\d{2})", arch_name)
        if match:
            return datetime.strptime(match.group(1), "%Y-%m-%d")
        return datetime.min

    def sort_key(name):
        prefix = name.split("_", 1)[0]
        return (prefix, extract_date(name))

    archive_names = sorted(archive_names, key=sort_key)

    if not suppress_output:
        for name in archive_names:
            print(name)

    return process


def cat_no_for_name(archive: str, config_settings: ConfigSettings) -> int:
    """
    Find the catalog number for the given archive name

    Returns:
      - the found number, if the archive catalog is present in the database
      - "-1" if the archive is not found
    """
    
    backup_def = backup_def_from_archive(archive)
    process = list_catalogs(backup_def, config_settings, suppress_output=True)
    if process.returncode != 0:
        logger.error(f"Error listing catalogs for backup def: '{backup_def}'")
        return -1
    line_no = 1
    for line in process.stdout.splitlines():
        line_no += 1
        search = re.search(rf".*?(\d+)\s+.*?({archive}).*", line)
        if search:
            logger.info(f"Found archive: '{archive}', catalog #: '{search.group(1)}'")
            return int(search.group(1))
    return -1


def list_archive_contents(archive: str, config_settings: ConfigSettings) -> int:
    """
    List the contents of a specific archive, given the archive name.
    Prints only actual file entries (lines beginning with '[ Saved ]').
    If none are found, a notice is printed instead.
    """
    backup_def = backup_def_from_archive(archive)
    database = f"{backup_def}{DB_SUFFIX}"
    database_path = os.path.join(get_db_dir(config_settings), database)

    if not os.path.exists(database_path):
        logger.error(f'Database not found: "{database_path}"')
        return 1

    cat_no = cat_no_for_name(archive, config_settings)
    if cat_no < 0:
        logger.error(f"archive: '{archive}' not found in database: '{database_path}'")
        return 1


    command = ['dar_manager', '--base', database_path, '-u', f"{cat_no}"]
    process = runner.run(command, timeout = 10)


    stdout = process.stdout or ""
    stderr = process.stderr or ""


    if process.returncode != 0:
        logger.error(f'Error listing catalogs for: "{database_path}"')
        logger.error(f"stderr: {stderr}")
        logger.error(f"stdout: {stdout}")


    combined_lines = (stdout + "\n" + stderr).splitlines()
    file_lines = [line for line in combined_lines if line.strip().startswith("[ Saved ]")]

    if file_lines:
        for line in file_lines:
            print(line)
    else:
        print(f"[info] Archive '{archive}' is empty.")

    return process.returncode



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
    process = runner.run(command)
    stdout, stderr = process.stdout, process.stderr 
    if process.returncode != 0:
        logger.error(f'Error listing catalogs for: "{database_path}"')
        logger.error(f"stderr: {stderr}")  
        logger.error(f"stdout: {stdout}")
    else:
        print(stdout)
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
    process = runner.run(command)
    stdout, stderr = process.stdout, process.stderr 
    if process.returncode != 0:
        logger.error(f'Error finding file: {file} in: "{database_path}"')
        logger.error(f"stderr: {stderr}")  
        logger.error(f"stdout: {stdout}")
    else:
        print(stdout)
    return process.returncode


def add_specific_archive(archive: str, config_settings: ConfigSettings, directory: str = None) -> int:
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

    # Validate backup definition
    backup_definition = archive.split('_')[0]
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
            stderr=subprocess.DEVNULL,
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
            archive_date_match = date_pattern.search(archive)
            if archive_date_match:
                archive_date = datetime.strptime(archive_date_match.group(), "%Y-%m-%d")
                if archive_date < latest_date:
                    if not confirm_add_old_archive(archive, latest_date.strftime("%Y-%m-%d")):
                        logger.info(f"Archive {archive} skipped due to user declining to add older archive.")
                        return 1

    except subprocess.CalledProcessError:
        logger.warning("Could not determine latest catalog date for chronological check.")

    logger.info(f'Add "{archive_path}" to catalog: "{database}"')

    command = ['dar_manager', '--base', database_path, "--add", archive_path, "-Q", "--alter=ignore-order"]
    process = runner.run(command)
    stdout, stderr = process.stdout, process.stderr

    if process.returncode == 0:
        logger.info(f'"{archive_path}" added to its catalog')
    elif process.returncode == 5:
        logger.warning(f'Something did not go completely right adding "{archive_path}" to its catalog, dar_manager error: "{process.returncode}"')
    else:
        logger.error(f'something went wrong adding "{archive_path}" to its catalog, dar_manager error: "{process.returncode}"')
        logger.error(f"stderr: {stderr}")
        logger.error(f"stdout: {stdout}")

    return process.returncode



def add_directory(args: argparse.ArgumentParser, config_settings: ConfigSettings) -> None:
    """
    Loop over the DAR archives in the given directory args.add_dir in increasing order by date and add them to their catalog database.

    Args:
        args (argparse.ArgumentParser): The command-line arguments object containing the add_dir attribute.
        config_settings (ConfigSettings): The configuration settings object.

    This function performs the following steps:
    1. Checks if the specified directory exists. If not, raises a RuntimeError.
    2. Uses a regular expression to match DAR archive files with base names in the format <string>_{FULL, DIFF, INCR}_YYYY-MM-DD.
    3. Lists the DAR archives in the specified directory and extracts their base names and dates.
    4. Sorts the DAR archives by date.
    5. Loops over the sorted DAR archives and adds each archive to its catalog database using the add_specific_archive function.

    Example:
        args = argparse.ArgumentParser()
        args.add_dir = '/path/to/dar/archives'
        config_settings = ConfigSettings()
        add_directory(args, config_settings)
    """
    if not os.path.exists(args.add_dir):
        raise RuntimeError(f"Directory {args.add_dir} does not exist")

    # Regular expression to match DAR archive files with base name and date in the format <string>_{FULL, DIFF, INCR}_YYYY-MM-DD
    #dar_pattern = re.compile(r'^(.*?_(FULL|DIFF|INCR)_(\d{4}-\d{2}-\d{2}))\.\d+\.dar$')
    dar_pattern = re.compile(r'^(.*?_(FULL|DIFF|INCR)_(\d{4}-\d{2}-\d{2}))\.1.dar$') # just read slice #1 of an archive
    # List of DAR archives with their dates and base names
    dar_archives = []

    for filename in os.listdir(args.add_dir):
        logger.debug(f"check if '{filename}' is a dar archive slice #1?")
        match = dar_pattern.match(filename)
        if match:
            base_name = match.group(1)
            date_str = match.group(3)
            date_obj = datetime.strptime(date_str, '%Y-%m-%d')
            dar_archives.append((date_obj, base_name))
            logger.debug(f" -> yes: base name: {base_name}, date: {date_str}")

    if not dar_archives or len(dar_archives) == 0:
        logger.info(f"No 'dar' archives found in directory {args.add_dir}")
        return

    # Sort the DAR archives by date
    dar_archives.sort()

    # Loop over the sorted DAR archives and process them
    result: List[Dict] = []
    for date_obj, base_name in dar_archives:
        logger.info(f"Adding dar archive: '{base_name}' to it's catalog database")
        result_archive = add_specific_archive(base_name, config_settings, args.add_dir)
        result.append({ f"{base_name}" : result_archive})
        if result_archive != 0:
            logger.error(f"Something went wrong added {base_name} to it's catalog")
    
    logger.debug(f"Results adding archives found in: '{args.add_dir}': result")


def backup_def_from_archive(archive: str) -> str:
    """
    return the backup definition from archive name
    """
    logger.debug(f"Get backup definition from archive: '{archive}'")
    search = re.search("(.*?)_", archive)
    if search:
        backup_def = search.group(1)
        logger.debug(f"backup definition: '{backup_def}' from given archive '{archive}'")
        return backup_def
    logger.error(f"Could not find backup definition from archive name: '{archive}'")
    return None


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
    backup_def = backup_def_from_archive(archive)
    database_path = os.path.join(get_db_dir(config_settings), f"{backup_def}{DB_SUFFIX}")
    cat_no:int = cat_no_for_name(archive, config_settings)
    if cat_no >= 0:
        command = ['dar_manager', '--base', database_path, "--delete", str(cat_no)]
        process: CommandResult = runner.run(command)
        logger.info(f"CommandResult: {process}")
    else:
        logger.warning(f"archive: '{archive}' not found in it's catalog database: {database_path}")
        return 2

    if process.returncode == 0:
        logger.info(f"'{archive}' removed from it's catalog")
        return 0
    else:
        logger.error(process.stdout)
        logger.error(process.sterr)
        return 1    


def build_arg_parser():
    parser = argparse.ArgumentParser(description="Creates/maintains `dar` database catalogs")
    parser.add_argument('-c', '--config-file', type=str, help="Path to 'dar-backup.conf'", default='~/.config/dar-backup/dar-backup.conf')
    parser.add_argument('--create-db', action='store_true', help='Create missing databases for all backup definitions')
    parser.add_argument('--alternate-archive-dir', type=str, help='Use this directory instead of BACKUP_DIR in config file')
    parser.add_argument('--add-dir', type=str, help='Add all archive catalogs in this directory to databases')
    parser.add_argument('-d', '--backup-def', type=str, help='Restrict to work only on this backup definition').completer = backup_definition_completer
    parser.add_argument('--add-specific-archive', type=str, help='Add this archive to catalog database').completer = add_specific_archive_completer
    parser.add_argument('--remove-specific-archive', type=str, help='Remove this archive from catalog database').completer = archive_content_completer
    parser.add_argument('-l', '--list-catalogs', action='store_true', help='List catalogs in databases for all backup definitions')
    parser.add_argument('--list-archive-contents', type=str, help="List contents of the archive's catalog. Argument is the archive name.").completer = archive_content_completer
    parser.add_argument('--find-file', type=str, help="List catalogs containing <path>/file. '-d <definition>' argument is also required")
    parser.add_argument('--verbose', action='store_true', help='Be more verbose')
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

    parser = argparse.ArgumentParser(description="Creates/maintains `dar` database catalogs")
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

    args.config_file = os.path.expanduser(os.path.expandvars(args.config_file))
    config_settings = ConfigSettings(args.config_file)

    if not os.path.dirname(config_settings.logfile_location):
        print(f"Directory for log file '{config_settings.logfile_location}' does not exist, exiting")
        sys.exit(1)
        return

    command_output_log = config_settings.logfile_location.replace("dar-backup.log", "dar-backup-commands.log")
    logger = setup_logging(config_settings.logfile_location, command_output_log, args.log_level, args.log_stdout, logfile_max_bytes=config_settings.logfile_max_bytes, logfile_backup_count=config_settings.logfile_backup_count)
    command_logger = get_logger(command_output_logger=True)
    runner = CommandRunner(logger=logger, command_logger=command_logger)

    start_msgs: List[Tuple[str, str]] = []

    start_time = int(time())
    
    start_msgs.append((f"{show_scriptname()}:", about.__version__))
    logger.info(f"START TIME: {start_time}")
    logger.debug(f"Command line: {get_invocation_command_line()}")
    logger.debug(f"`args`:\n{args}")
    logger.debug(f"`config_settings`:\n{config_settings}")
    start_msgs.append(("Config file:", args.config_file))
    args.verbose and start_msgs.append(("Backup dir:", config_settings.backup_dir))
    start_msgs.append(("Logfile:", config_settings.logfile_location))
    args.verbose and start_msgs.append(("Logfile max size (bytes):", config_settings.logfile_max_bytes))
    args.verbose and start_msgs.append(("Logfile backup count:", config_settings.logfile_backup_count))
    args.verbose and start_msgs.append(("--alternate-archive-dir:", args.alternate_archive_dir))
    args.verbose and start_msgs.append(("--remove-specific-archive:", args.remove_specific_archive)) 
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
        logger.error(f"No backup definition given to --backup-def")
        sys.exit(1)
        return

    if args.backup_def:
        backup_def_path = os.path.join(config_settings.backup_d_dir, args.backup_def)
        if not os.path.exists(backup_def_path):
            logger.error(f"Backup definition {args.backup_def} does not exist, exiting")
            sys.exit(1)
            return

    if args.list_archive_contents and not args.list_archive_contents.strip():
        logger.error(f"--list-archive-contents <param> not given, exiting")
        sys.exit(1)
        return

    if args.find_file and not args.backup_def:
        logger.error(f"--find-file requires the --backup-def, exiting")
        sys.exit(1)
        return

    # --- Modify settings ---
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
            for root, dirs, files in os.walk(config_settings.backup_d_dir):
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
            for root, dirs, files in os.walk(config_settings.backup_d_dir):
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


    if args.find_file:
        result = find_file(args.find_file, args.backup_def, config_settings)
        sys.exit(result)
        return


if __name__ == "__main__":
    main()
