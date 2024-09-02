#!/usr/bin/env python3

"""
cleanup.py source code is here: https://github.com/per2jensen/dar-backup

Licensed under GNU GENERAL PUBLIC LICENSE v3, see the supplied file "LICENSE" for details.

THERE IS NO WARRANTY FOR THE PROGRAM, TO THE EXTENT PERMITTED BY APPLICABLE LAW, 
not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
See section 15 and section 16 in the supplied "LICENSE" file

This script removes old DIFF and INCR archives + accompanying .par2 files according to the
[AGE] settings in the configuration file.
"""

import argparse
import logging
import os
import re
import subprocess
import sys

from datetime import datetime, timedelta
from time import time

from . import __about__ as about
from dar_backup.config_settings import ConfigSettings
from dar_backup.util import extract_error_lines
from dar_backup.util import list_backups
from dar_backup.util import setup_logging


logger = None 

def delete_old_backups(backup_dir, age, backup_type, backup_definition=None):
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
                    os.remove(file_path)
                    logger.info(f"Deleted {backup_type} backup: {file_path}")
                except Exception as e:
                    logger.error(f"Error deleting file {file_path}: {e}")


def delete_archive(backup_dir, archive_name):
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
                os.remove(file_path)
                logger.info(f"Deleted archive slice: {file_path}")
                files_deleted = True
            except Exception as e:
                logger.error(f"Error deleting archive slice {file_path}: {e}")
    
    if not files_deleted:
        logger.info("No .dar files matched the regex for deletion.")

    # Delete associated .par2 files
    par2_regex = re.compile(rf"^{re.escape(archive_name)}\.[0-9]+\.dar.*\.par2$")
    files_deleted = False
    for filename in sorted(os.listdir(backup_dir)):
        if par2_regex.match(filename):
            file_path = os.path.join(backup_dir, filename)
            try:
                os.remove(file_path)
                logger.info(f"Deleted PAR2 file: {file_path}")
                files_deleted = True
            except Exception as e:
                logger.error(f"Error deleting PAR2 file {file_path}: {e}")

    if not files_deleted:
        logger.info("No .par2 matched the regex for deletion.")


def show_version():
    script_name = os.path.basename(sys.argv[0])
    print(f"{script_name} {about.__version__}")
    print('''Licensed under GNU GENERAL PUBLIC LICENSE v3, see the supplied file "LICENSE" for details.
THERE IS NO WARRANTY FOR THE PROGRAM, TO THE EXTENT PERMITTED BY APPLICABLE LAW, not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
See section 15 and section 16 in the supplied "LICENSE" file.''')

def main():

    
    global logger

    parser = argparse.ArgumentParser(description="Cleanup old archives according to AGE configuration.")
    parser.add_argument('-d', '--backup-definition', help="Specific backup definition to cleanup.")
    parser.add_argument('-c', '--config-file', '-c', type=str, help="Path to 'dar-backup.conf'", default='~/.config/dar-backup/dar-backup.conf')
    parser.add_argument('-v', '--version', action='store_true', help="Show version information.")
    parser.add_argument('--alternate-archive-dir', type=str, help="Cleanup in this directory instead of the default one.")
    parser.add_argument('--cleanup-specific-archive', type=str, help="List of archives to cleanup") 
    parser.add_argument('-l', '--list', action='store_true', help="List available archives.")
    parser.add_argument('--verbose', action='store_true', help="Print various status messages to screen")
    args = parser.parse_args()

    args.config_file = os.path.expanduser(args.config_file)
    

    if args.version:
        show_version()
        sys.exit(0)

    config_settings = ConfigSettings(args.config_file)

    start_time=int(time())
    logger = setup_logging(config_settings.logfile_location, logging.INFO)
    logger.info(f"=====================================")
    logger.info(f"cleanup.py started, version: {about.__version__}")

    logger.info(f"START TIME: {start_time}")
    logger.debug(f"`args`:\n{args}")
    logger.debug(f"`config_settings`:\n{config_settings}")

    file_dir =  os.path.normpath(os.path.dirname(__file__))
    args.verbose and (print(f"Script directory:           {file_dir}"))
    args.verbose and (print(f"Config file:                {args.config_file}"))
    args.verbose and (print(f"Backup dir:                 {config_settings.backup_dir}"))
    args.verbose and (print(f"Logfile location:           {config_settings.logfile_location}"))
    args.verbose and (print(f"--alternate-archive-dir:    {args.alternate_archive_dir}"))
    args.verbose and (print(f"--cleanup-specific-archive: {args.cleanup_specific_archive}")) 

    # run PREREQ scripts
    if 'PREREQ' in config_settings.config:
        for key in sorted(config_settings.config['PREREQ'].keys()):
            script = config_settings.config['PREREQ'][key]
            try:
                result = subprocess.run(script, shell=True, check=True)
                logger.info(f"PREREQ {key}: '{script}' run, return code: {result.returncode}")
                logger.info(f"PREREQ stdout:\n{result.stdout}")
            except subprocess.CalledProcessError as e:
                logger.error(f"Error executing {key}: '{script}': {e}")
                if result:
                    logger.error(f"PREREQ stderr:\n{result.stderr}")
                print(f"Error executing {script}: {e}") 
                sys.exit(1)


    if args.alternate_archive_dir:
        config_settings.backup_dir = args.alternate_archive_dir


    if args.cleanup_specific_archive:
        print(f"Cleaning up specific archives: {args.cleanup_specific_archive}")
        archive_names = args.cleanup_specific_archive.split(',')
        for archive_name in archive_names:
            print(f"Deleting archive: {archive_name}")
            delete_archive(config_settings.backup_dir, archive_name.strip())
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
            delete_old_backups(config_settings.backup_dir, config_settings.diff_age, 'DIFF', definition)
            delete_old_backups(config_settings.backup_dir, config_settings.incr_age, 'INCR', definition)


    end_time=int(time())
    logger.info(f"END TIME: {end_time}")

    error_lines = extract_error_lines(config_settings.logfile_location, start_time, end_time)
    if len(error_lines) > 0:
        args.verbose and print("\033[1m\033[31mErrors\033[0m encountered")
        for line in error_lines:
            args.verbose and print(line)
        sys.exit(1)
    else:
        args.verbose and print("\033[1m\033[32mSUCCESS\033[0m No errors encountered")
        sys.exit(0)

if __name__ == "__main__":
    main()
