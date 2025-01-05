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

logger = None

def show_more_help():
    help_text = f"""
NAME
    {SCRIPTNAME} - creates/maintains `dar` databases with catalogs for backup definitions
"""
    print(help_text)


def create_db(backup_def: str, config_settings: ConfigSettings):
    database = f"{backup_def}{DB_SUFFIX}"
    
    database_path = os.path.join(config_settings.backup_dir, database)
    
    logger.debug(f"BACKUP_DIR: {config_settings.backup_dir}")

    if os.path.exists(database_path):
        logger.warning(f'"{database_path}" already exists, skipping creation')
    else:
        logger.info(f'Create catalog database: "{database_path}"')
        command = ['dar_manager', '--create' , database_path]
        process = run_command(command)
        logger.debug(f"return code from 'db created': {process.returncode}")
        if process.returncode == 0:
            logger.info(f'Database created: "{database_path}"')
        else:
            logger.error(f'Something went wrong creating the database: "{database_path}"')
            stdout, stderr = process.stdout, process.stderr 
            logger.error(f"stderr: {stderr}")
            logger.error(f"stdout: {stdout}")



def list_db(backup_def: str, config_settings: ConfigSettings):
    database = f"{backup_def}{DB_SUFFIX}"
    database_path = os.path.join(config_settings.backup_dir, database)
    if not os.path.exists(database_path):
        logger.error(f'Database not found: "{database_path}"')
        return 1
    command = ['dar_manager', '--base', database_path, '--list']
    process = run_command(command)
    stdout, stderr = process.stdout, process.stderr 
    if process.returncode != 0:
        logger.error(f'Error listing catalogs for: "{database_path}"')
        logger.error(f"stderr: {stderr}")  
        logger.error(f"stdout: {stdout}")
    else:
        print(stdout)
    sys.exit(process.returncode)


def add_specific_archive(archive: str, config_settings: ConfigSettings):    
    # sanity check - does dar backup exist?
    archive = os.path.basename(archive)  # remove path if it was given
    archive_path = os.path.join(config_settings.backup_dir, f'{archive}.1.dar')
    if not os.path.exists(archive_path):
        logger.error(f'dar backup: "{archive_path}" not found, exiting')
        sys.exit(1)
        
    # sanity check - does backup definition exist?
    backup_definition = archive.split('_')[0]
    backup_def_path = os.path.join(config_settings.backup_d_dir, backup_definition)
    if not os.path.exists(backup_def_path):
        logger.error(f'backup definition "{backup_definition}" not found (--add-specific-archive option probably not correct), exiting')
        sys.exit(1)
    
    database = f"{backup_definition}{DB_SUFFIX}"
    database_path = os.path.realpath(os.path.join(config_settings.backup_dir, database))
    logger.info(f'Add "{archive_path}" to catalog "{database}"')
    
    command = ['dar_manager', '--base', database_path, "--add", archive_path, "-ai", "-Q"]
    process = run_command(command)
    stdout, stderr = process.stdout, process.stderr

    if process.returncode == 0:
        logger.info(f'"{archive_path}" added to it\'s catalog')
    elif process.returncode == 5:
        logger.warning(f'Something did not go completely right adding "{archive_path}" to it\'s catalog, dar_manager error: "{process.returncode}"')
    else: 
        logger.error(f'something went wrong adding "{archive_path}" to it\'s catalog, dar_manager error: "{process.returncode}"')
        logger.error(f"stderr: {stderr}")
        logger.error(f"stdout: {stdout}")
     
    sys.exit(process.returncode)



def main():
    global logger 

    MIN_PYTHON_VERSION = (3, 9)
    if sys.version_info < MIN_PYTHON_VERSION:
        sys.stderr.write(f"Error: This script requires Python {'.'.join(map(str, MIN_PYTHON_VERSION))} or higher.\n")
        sys.exit(1)

    parser = argparse.ArgumentParser(description="Creates/maintains `dar` database catalogs")
    parser.add_argument('-c', '--config-file', type=str, help="Path to 'dar-backup.conf'", default='~/.config/dar-backup/dar-backup.conf')
    parser.add_argument('--create-db', action='store_true', help='Create missing databases for all backup definitions')
    parser.add_argument('--alternate-archive-dir', type=str, help='Use this directory instead of BACKUP_DIR in config file')
    parser.add_argument('--add-dir', type=str, help='Add all archive catalogs in this directory to databases')
    parser.add_argument('-d', '--backup-def', type=str, help='Restrict to work only on this backup definition')
    parser.add_argument('--add-specific-archive', type=str, help='Add this archive to catalog database')
    parser.add_argument('--remove-specific-archive', type=str, help='Remove this archive from catalog database')
    parser.add_argument('--list-db', action='store_true', help='List catalogs in databases')
    parser.add_argument('--verbose', action='store_true', help='Be more verbose')
    parser.add_argument('--log-level', type=str, help="`debug` or `trace`, default is `info`", default="info")
    parser.add_argument('--log-stdout', action='store_true', help='also print log messages to stdout')
    parser.add_argument('--more-help', action='store_true', help='Show extended help message')
    parser.add_argument('--version', action='store_true', help='Show version & license')

    args = parser.parse_args()

    if args.more_help:
        show_more_help()
        sys.exit(0)

    if args.version:
        print(f"{SCRIPTNAME} {about.__version__}")
        print(f"Source code is here: https://github.com/per2jensen/dar-backup")
        print('''Licensed under GNU GENERAL PUBLIC LICENSE v3, see the supplied file "LICENSE" for details.
THERE IS NO WARRANTY FOR THE PROGRAM, TO THE EXTENT PERMITTED BY APPLICABLE LAW, not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
See section 15 and section 16 in the supplied "LICENSE" file.''')
        sys.exit(0)

    # setup logging
    args.config_file = os.path.expanduser(args.config_file)
    config_settings = ConfigSettings(args.config_file)
    if not os.path.dirname(config_settings.logfile_location):
        print(f"Directory for log file '{config_settings.logfile_location}' does not exist, exiting")
        sys.exit(1) 
    logger = setup_logging(config_settings.logfile_location, args.log_level, args.log_stdout)

    start_time=int(time())
    logger.info(f"=====================================")
    logger.info(f"{SCRIPTNAME} started, version: {about.__version__}")
    logger.info(f"START TIME: {start_time}")
    logger.debug(f"`args`:\n{args}")
    logger.debug(f"`config_settings`:\n{config_settings}")


    # Sanity checks before starting
    if args.add_dir and not args.add_dir.strip():
        logger.error("archive dir not given, exiting")
        sys.exit(1)

    if args.add_specific_archive and not args.add_specific_archive.strip():
        logger.error("specific archive to add not given, exiting")
        sys.exit(1)

    if args.remove_specific_archive and not args.remove_specific_archive.strip():
        logger.error("specific archive to remove not given, exiting")
        sys.exit(1)

    if args.add_specific_archive and args.remove_specific_archive:
        logger.error("you can't add and remove archives in the same operation, exiting")
        sys.exit(1)

    if args.backup_def:
        backup_def_path = os.path.join(config_settings.backup_d_dir, args.backup_def)
        if not os.path.exists(backup_def_path):
            logger.error(f"Backup definition {args.backup_def} does not exist, exiting")
            sys.exit(1)


    # Modify config settings based on the arguments
    if args.alternate_archive_dir:
        if not os.path.exists(args.alternate_archive_dir):
            logger.error(f"Alternate archive dir '{args.alternate_archive_dir}' does not exist, exiting")
            sys.exit(1)
        config_settings.backup_dir = args.alternate_archive_dir


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
        add_specific_archive(args.add_specific_archive, config_settings)

    if args.add_dir:
        # Implement add directory logic
        pass

    if args.remove_specific_archive:
        # Implement remove specific archive logic
        pass


    if args.list_db:
        if args.backup_def:
            list_db(args.backup_def, config_settings)
        else:
            for root, dirs, files in os.walk(config_settings.backup_d_dir):
                for file in files:
                    current_backupdef = os.path.basename(file)
                    list_db(current_backupdef, config_settings)
        sys.exit(0)

if __name__ == "__main__":
    main()
