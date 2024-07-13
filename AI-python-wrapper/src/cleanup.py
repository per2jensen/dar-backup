#!/usr/bin/env python3

"""
cleanup.py source code is here: https://github.com/per2jensen/dar-backup

Licensed under GNU GENERAL PUBLIC LICENSE v3, see the supplied file "LICENSE" for details.

THERE IS NO WARRANTY FOR THE PROGRAM, TO THE EXTENT PERMITTED BY APPLICABLE LAW, 
not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
See section 15 and section 16 in the supplied "LICENSE" file

Script that removes old DIFF and INCR archives according to the [AGE] settings in the configuration file.



"""

import argparse
import configparser
import logging
import os
import re
import sys

from datetime import datetime, timedelta
from util import list_backups
from util import setup_logging

VERSION = "aplha-0.3"

logger = None 

def read_config(config_file):
    config = configparser.ConfigParser()
    if not config_file:   
        config_file = os.path.join(os.path.dirname(__file__), '../conf/dar-backup.conf')
    try:
        config.read(config_file)
        logfile_location = config['MISC']['LOGFILE_LOCATION']
        backup_dir = config['DIRECTORIES']['BACKUP_DIR']
        backup_d = config['DIRECTORIES']['BACKUP.D_DIR']
        diff_age = int(config['AGE']['DIFF_AGE'])
        incr_age = int(config['AGE']['INCR_AGE'])
    except Exception as e:
        logger.exception(f"Error reading config file {config_file}: {e}")
        sys.exit(1)
    return logfile_location, backup_dir, backup_d, diff_age, incr_age


def delete_old_backups(backup_dir, age, backup_type, backup_definition=None):
    """
    Delete backups older than the specified age in days.
    Only .dar and .par2 files are considered for deletion.
    """
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


def delete_archives(backup_dir, archive_name):
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
    print(f"{script_name} {VERSION}")
    print('''Licensed under GNU GENERAL PUBLIC LICENSE v3, see the supplied file "LICENSE" for details.
THERE IS NO WARRANTY FOR THE PROGRAM, TO THE EXTENT PERMITTED BY APPLICABLE LAW, not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
See section 15 and section 16 in the supplied "LICENSE" file.''')

def main():
    global logger

    parser = argparse.ArgumentParser(description="Cleanup old backup files.")
    parser.add_argument('--backup-definition', '-d', help="Specific backup definition to clean.")
    parser.add_argument('--config-file', '-c', type=str, help="Path to 'dar-backup.conf'", default=os.path.join(os.path.dirname(__file__), '../conf/dar-backup.conf'))
    parser.add_argument('--version', '-v', action='store_true', help="Show version information.")
    parser.add_argument('--alternate-archive-dir', type=str, help="Cleanup in this directory instead of the default one.")
    parser.add_argument('--cleanup-specific-archive', type=str, help="Force delete all .dar and .par2 files in the backup directory for given archive name")
    parser.add_argument('--list', action='store_true', help="List available archives.")


    args = parser.parse_args()

    if args.version:
        show_version()
        sys.exit(0)


    logfile_location, backup_dir, backup_d, diff_age, incr_age = read_config(args.config_file)
    logger = setup_logging(logfile_location)
    logger.info(f"=====================================")
    logger.info(f"cleanup.py started, version: {VERSION}")
    logger.info(f"START TIME: {start_time}")
    logger.debug(f"`args`:\n{args}")



    if args.alternate_archive_dir:
        backup_dir = args.alternate_archive_dir

    if args.cleanup_specific_archive:
        delete_archives(backup_dir, args.cleanup_specific_archive)
        sys.exit(0)
    elif args.list:
        list_backups(backup_dir, args.backup_definition)
    else:
        backup_definitions = []
        if args.backup_definition:
            backup_definitions.append(args.backup_definition)
        else:
            for root, _, files in os.walk(backup_d):
                for file in files:
                    backup_definitions.append(file.split('.')[0])

        for definition in backup_definitions:
            delete_old_backups(backup_dir, diff_age, 'DIFF', definition)
            delete_old_backups(backup_dir, incr_age, 'INCR', definition)

if __name__ == "__main__":
    main()
