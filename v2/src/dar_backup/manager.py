#!/usr/bin/env python3

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


import os
import argparse
import subprocess
import sys


from . import __about__ as about
from dar_backup.config_settings import ConfigSettings
from dar_backup.util import run_command
from dar_backup.util import setup_logging
from time import time
# Constants
SCRIPTNAME = os.path.basename(__file__)
SCRIPTPATH = os.path.realpath(__file__)
SCRIPTDIRPATH = os.path.dirname(SCRIPTPATH)
DB_SUFFIX = ".db"

# Helper functions
def show_help():
    help_text = f"""
NAME
    {SCRIPTNAME} - creates/maintains dar catalogs for dar archives for backup definitions
"""
    print(help_text)


def log_error(message):
    print(f"ERROR: {message}", file=sys.stderr)


def create_db(backup_def: str, config_settings: ConfigSettings):
    catalog = f"{backup_def}{DB_SUFFIX}"
    
    catalog_path = os.path.join(config_settings.backup_dir, catalog)
    
    print(f"backups dir: {config_settings.backup_dir}")
    print(f"catalog: {catalog_path}")

    if os.path.exists(catalog_path):
        logger.warning(f'"{catalog_path}" already exists, skipping creation')
    else:
        logger.info(f'Create catalog database: "{catalog_path}"')
        command = ['dar_manager', '--create' , f"{catalog_path}"]
        process = run_command(command)
        stdout, stderr = process.communicate()
        print (f"out: {stdout}")
        print (f"err: {stderr}")
        print (f"return code from 'db created': {process.returncode}")
        if process.returncode == 0:
            logger.info(f'Catalog created: "{catalog_path}"')
        else:
            logger.error(f'Something went wrong creating the catalog: "{catalog_path}"')
            logger.error(f"stderr: {stderr}")


def main():
    MIN_PYTHON_VERSION = (3, 9)
    if sys.version_info < MIN_PYTHON_VERSION:
        sys.stderr.write(f"Error: This script requires Python {'.'.join(map(str, MIN_PYTHON_VERSION))} or higher.\n")
        sys.exit(1)


    global logger 

    parser = argparse.ArgumentParser(description="Creates/maintains dar catalogs for dar archives for backup definitions")
    parser.add_argument('-c', '--config-file', type=str, help="Path to 'dar-backup.conf'", default='~/.config/dar-backup/dar-backup.conf')
    parser.add_argument('--create-db', action='store_true', help='Create missing catalogs')
    parser.add_argument('--alternate-archive-dir', type=str, help='Work on this dir instead of MOUNT_POINT')
    parser.add_argument('--add-dir', type=str, help='Add all archives in a dir')
    parser.add_argument('-d', '--backup-def', type=str, help='Restrict to add only archives for this backup definition')
    parser.add_argument('--add-specific-archive', type=str, help='Add this archive to catalog')
    parser.add_argument('--remove-specific-archive', type=str, help='Remove this archive from catalog')
    parser.add_argument('--list-db', action='store_true', help='List db for catalogs')
    parser.add_argument('--verbose', action='store_true', help='Output a single notice on adding an archive to its catalog')
    parser.add_argument('--log-level', type=str, help="`debug` or `trace`", default="info")
    parser.add_argument('--added-help', action='store_true', help='Show help message and exit')
    parser.add_argument('--version', action='store_true', help='Show version and exit')

    args = parser.parse_args()

    if args.added_help:
        show_help()
        sys.exit(0)

    if args.version:
        print(f"{SCRIPTNAME} {about.__version__}")
        print(f"Source code is here: https://github.com/per2jensen/dar-backup")
        print('''Licensed under GNU GENERAL PUBLIC LICENSE v3, see the supplied file "LICENSE" for details.
THERE IS NO WARRANTY FOR THE PROGRAM, TO THE EXTENT PERMITTED BY APPLICABLE LAW, not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
See section 15 and section 16 in the supplied "LICENSE" file.''')
        sys.exit(0)


    args.config_file = os.path.expanduser(args.config_file)
    config_settings = ConfigSettings(args.config_file)
    if not config_settings.logfile_location or not os.path.dirname(config_settings.logfile_location):
        print(f"Log file '{config_settings.logfile_location}' does not exist, exiting")
        sys.exit(1) 
    logger = setup_logging(config_settings.logfile_location, args.log_level)

    start_time=int(time())
    logger.info(f"=====================================")
    logger.info(f"{SCRIPTNAME} started, version: {about.__version__}")
    logger.info(f"START TIME: {start_time}")
    logger.debug(f"`args`:\n{args}")
    logger.debug(f"`config_settings`:\n{config_settings}")


    # Sanity checks before starting
    if args.add_dir and not args.add_dir.strip():
        log_error("archive dir not given, exiting")
        sys.exit(1)

    if args.add_specific_archive and not args.add_specific_archive.strip():
        log_error("specific archive to add not given, exiting")
        sys.exit(1)

    if args.remove_specific_archive and not args.remove_specific_archive.strip():
        log_error("specific archive to remove not given, exiting")
        sys.exit(1)

    if args.add_specific_archive and args.remove_specific_archive:
        log_error("you can't add and remove archives in the same operation, exiting")
        sys.exit(1)

    if args.backup_def:
        backup_def_path = os.path.join(config_settings.backup_d_dir, args.backup_def)
        if not os.path.exists(backup_def_path):
            log_error(f"Backup definition {args.backup_def} does not exist, exiting")
            sys.exit(1)


    # Modify config settings based on the arguments
    if args.alternate_archive_dir:
        if not os.path.exists(args.alternate_archive_dir):
            log_error(f"Alternate archive dir '{args.alternate_archive_dir}' does not exist, exiting")
            sys.exit(1)
        config_settings.backup_dir = args.alternate_archive_dir



    # Implement the logic for the operations based on the arguments
    if args.create_db:
        if args.backup_def:
            create_db(args.backup_def, config_settings)
        else:
            for root, dirs, files in os.walk(config_settings.backup_d_dir):
                for file in files:
                    current_backupdef = os.path.basename(file)
                    create_db(current_backupdef, config_settings)
        sys.exit(0)

    if args.add_specific_archive:
        # Implement add specific archive logic
        pass

    if args.add_dir:
        # Implement add directory logic
        pass

    if args.remove_specific_archive:
        # Implement remove specific archive logic
        pass

    if args.list_catalog:
        # Implement list catalog logic
        pass

if __name__ == "__main__":
    main()
