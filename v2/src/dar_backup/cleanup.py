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
import logging
import os
import re
import subprocess
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))



from datetime import datetime, timedelta
from inputimeout import inputimeout, TimeoutOccurred
from time import time
from typing import Dict, List, NamedTuple, Tuple


from . import __about__ as about
from dar_backup.config_settings import ConfigSettings
from dar_backup.util import list_backups
from dar_backup.util import setup_logging
from dar_backup.util import get_logger
from dar_backup.util import requirements
from dar_backup.util import show_version
from dar_backup.util import get_invocation_command_line
from dar_backup.util import print_aligned_settings
from dar_backup.util import backup_definition_completer, list_archive_completer
from dar_backup.util import is_safe_filename
from dar_backup.util import show_scriptname

from dar_backup.command_runner import CommandRunner   
from dar_backup.command_runner import CommandResult

logger = None 
runner = None

def delete_old_backups(backup_dir, age, backup_type, args, backup_definition=None):
    """
    Delete backups older than the specified age in days.
    Only .dar and .par2 files are considered for deletion.
    """
    logger.info(f"Deleting {backup_type} backups older than {age} days in {backup_dir} for backup definition: {backup_definition}")

    if backup_type not in ['DIFF', 'INCR']:
        logger.error(f"Invalid backup type: {backup_type}")
        return

    now = datetime.now()
    cutoff_date = now - timedelta(days=age)

    archives_deleted = {}

    for filename in sorted(os.listdir(backup_dir)):
        if not (filename.endswith('.dar') or filename.endswith('.par2')):
            continue
        if backup_definition and not filename.startswith(backup_definition):
            continue
        if backup_type in filename:
            try:
                date_str = filename.split(f"_{backup_type}_")[1].split('.')[0]
                file_date = datetime.strptime(date_str, '%Y-%m-%d')
            except Exception as e:
                logger.error(f"Error parsing date from filename {filename}: {e}")
                raise

            if file_date < cutoff_date:
                file_path = os.path.join(backup_dir, filename)
                try:
                    is_safe_filename(file_path) and os.remove(file_path)
                    logger.info(f"Deleted {backup_type} backup: {file_path}")
                    archive_name = filename.split('.')[0]
                    if not archive_name in archives_deleted:
                        logger.debug(f"Archive name: '{archive_name}' added to catalog deletion list")
                    archives_deleted[archive_name] = True
                except Exception as e:
                    logger.error(f"Error deleting file {file_path}: {e}")

    for archive_name in archives_deleted.keys():
        delete_catalog(archive_name, args)


def delete_archive(backup_dir, archive_name, args):
    """
    Delete all .dar and .par2 files in the backup directory for the given archive name.

    This function will delete any type of archive, including FULL. 
    """
    logger.info(f"Deleting all .dar and .par2 files for archive: `{archive_name}`")
    # Regex to match the archive files according to the naming convention
    archive_regex = re.compile(rf"^{re.escape(archive_name)}\.[0-9]+\.dar$")
    
    # Delete the specified .dar files according to the naming convention
    files_deleted = False
    for filename in sorted(os.listdir(backup_dir)):
        if archive_regex.match(filename):
            file_path = os.path.join(backup_dir, filename)
            try:
                is_safe_filename(file_path) and os.remove(file_path)
                logger.info(f"Deleted archive slice: {file_path}")
                files_deleted = True
            except Exception as e:
                logger.error(f"Error deleting archive slice {file_path}: {e}")
    
    if files_deleted:
            delete_catalog(archive_name, args)
    else:
        logger.info("No .dar files matched the regex for deletion.")

    # Delete associated .par2 files
    par2_regex = re.compile(rf"^{re.escape(archive_name)}\.[0-9]+\.dar.*\.par2$")
    files_deleted = False
    for filename in sorted(os.listdir(backup_dir)):
        if par2_regex.match(filename):
            file_path = os.path.join(backup_dir, filename)
            try:
                is_safe_filename(file_path) and os.remove(file_path)
                logger.info(f"Deleted PAR2 file: {file_path}")
                files_deleted = True
            except Exception as e:
                logger.error(f"Error deleting PAR2 file {file_path}: {e}")

    if not files_deleted:
        logger.info("No .par2 matched the regex for deletion.")


def delete_catalog(catalog_name: str, args: NamedTuple) -> bool:
    """
    Call `manager.py` to delete the specified catalog in it's database
    """
    command = [f"manager", "--remove-specific-archive", catalog_name, "--config-file", args.config_file, '--log-level', 'debug', '--log-stdout']
    logger.info(f"Deleting catalog '{catalog_name}' using config file: '{args.config_file}'")
    try:
        result:CommandResult = runner.run(command)
        if result.returncode == 0:
            logger.info(f"Deleted catalog '{catalog_name}', using config file: '{args.config_file}'")
            logger.debug(f"Stdout: manager.py --remove-specific-archive output:\n{result.stdout}")
            return True
        elif result.returncode == 2:
            logger.warning(f"catalog '{catalog_name}' not found in the database, skipping deletion")
            return True
        else:
            logger.error(f"Error deleting catalog {catalog_name}: {result.stderr}")
            return False
    except Exception as e:
        logger.error(f"Error deleting catalog {catalog_name}: {e}")
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
    


def main():
    global logger, runner

    parser = argparse.ArgumentParser(description="Cleanup old archives according to AGE configuration.")
    parser.add_argument('-d', '--backup-definition', help="Specific backup definition to cleanup.").completer = backup_definition_completer
    parser.add_argument('-c', '--config-file', '-c', type=str, help="Path to 'dar-backup.conf'", default='~/.config/dar-backup/dar-backup.conf')
    parser.add_argument('-v', '--version', action='store_true', help="Show version information.")
    parser.add_argument('--alternate-archive-dir', type=str, help="Cleanup in this directory instead of the default one.")
    parser.add_argument('--cleanup-specific-archives', type=str, help="Comma separated list of archives to cleanup").completer = list_archive_completer 
    parser.add_argument('-l', '--list', action='store_true', help="List available archives.")
    parser.add_argument('--verbose', action='store_true', help="Print various status messages to screen")
    parser.add_argument('--log-level', type=str, help="`debug` or `trace`, default is `info`", default="info")
    parser.add_argument('--log-stdout', action='store_true', help='also print log messages to stdout')
    parser.add_argument('--test-mode', action='store_true', help='Read envvars in order to run some pytest cases')

    argcomplete.autocomplete(parser)

    args = parser.parse_args()

    args.config_file = os.path.expanduser(os.path.expandvars(args.config_file))
    

    if args.version:
        show_version()
        sys.exit(0)

    config_settings = ConfigSettings(args.config_file)

    start_time=int(time())

#    command_output_log = os.path.join(config_settings.logfile_location.removesuffix("dar-backup.log"), "dar-backup-commands.log")
    command_output_log = config_settings.logfile_location.replace("dar-backup.log", "dar-backup-commands.log")
    logger = setup_logging(config_settings.logfile_location, command_output_log, args.log_level, args.log_stdout, logfile_max_bytes=config_settings.logfile_max_bytes, logfile_backup_count=config_settings.logfile_backup_count)
    command_logger = get_logger(command_output_logger = True)
    runner = CommandRunner(logger=logger, command_logger=command_logger)

    start_msgs: List[Tuple[str, str]] = []

    start_msgs.append((f"{show_scriptname()}:", about.__version__))

    logger.info(f"START TIME: {start_time}")
    logger.debug(f"Command line: {get_invocation_command_line()}")
    logger.debug(f"`args`:\n{args}")
    logger.debug(f"`config_settings`:\n{config_settings}")

    file_dir =  os.path.normpath(os.path.dirname(__file__))
    args.verbose and start_msgs.append(("Script directory:", file_dir))
    start_msgs.append(("Config file:", args.config_file))
    args.verbose and start_msgs.append(("Backup dir:", config_settings.backup_dir))
    start_msgs.append(("Logfile:", config_settings.logfile_location))
    args.verbose and start_msgs.append(("Logfile max size (bytes):", config_settings.logfile_max_bytes))
    args.verbose and start_msgs.append(("Logfile backup count:", config_settings.logfile_backup_count))
    args.verbose and start_msgs.append(("--alternate-archive-dir:", args.alternate_archive_dir))
    args.verbose and start_msgs.append(("--cleanup-specific-archives:", args.cleanup_specific_archives)) 

    dangerous_keywords = ["--cleanup", "_FULL_"] # TODO: add more dangerous keywords
    print_aligned_settings(start_msgs, highlight_keywords=dangerous_keywords, quiet=not args.verbose)

    # run PREREQ scripts
    requirements('PREREQ', config_settings)

    if args.alternate_archive_dir:
        if not os.path.exists(args.alternate_archive_dir):
            logger.error(f"Alternate archive directory does not exist: {args.alternate_archive_dir}, exiting")
            sys.exit(1) 
        if  not os.path.isdir(args.alternate_archive_dir):
            logger.error(f"Alternate archive directory is not a directory, exiting")
            sys.exit(1) 
        config_settings.backup_dir = args.alternate_archive_dir

    if args.cleanup_specific_archives is None and args.test_mode:
        logger.info("No --cleanup-specific-archives provided; skipping specific archive deletion in test mode.")

    if args.cleanup_specific_archives:
        logger.info(f"Cleaning up specific archives: {args.cleanup_specific_archives}")
        archive_names = args.cleanup_specific_archives.split(',')
        for archive_name in archive_names:
            if "_FULL_" in archive_name:
                if not confirm_full_archive_deletion(archive_name, args.test_mode):
                    continue
            archive_path = os.path.join(config_settings.backup_dir, archive_name.strip())
            logger.info(f"Deleting archive: {archive_path}")
            delete_archive(config_settings.backup_dir, archive_name.strip(), args)
    elif args.list:
        list_backups(config_settings.backup_dir, args.backup_definition)
    else:
        backup_definitions = []
        if args.backup_definition:
            backup_definitions.append(args.backup_definition)
        else:
            for root, _, files in os.walk(config_settings.backup_d_dir):
                for file in files:
                    backup_definitions.append(file.split('.')[0])

        for definition in backup_definitions:
            delete_old_backups(config_settings.backup_dir, config_settings.diff_age, 'DIFF', args, definition)
            delete_old_backups(config_settings.backup_dir, config_settings.incr_age, 'INCR', args, definition)

    # run POST scripts
    requirements('POSTREQ', config_settings)


    end_time=int(time())
    logger.info(f"END TIME: {end_time}")
    sys.exit(0)

if __name__ == "__main__":
    main()
