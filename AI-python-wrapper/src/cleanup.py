#!/usr/bin/env python3

import argparse
import configparser
import logging
import os
import re
import sys

from datetime import datetime, timedelta

VERSION = "aplha-0.2"

# Define TRACE level
TRACE_LEVEL_NUM = 5
logging.addLevelName(TRACE_LEVEL_NUM, "TRACE")

def trace(self, message, *args, **kws):
    if self.isEnabledFor(TRACE_LEVEL_NUM):
        self._log(TRACE_LEVEL_NUM, message, args, **kws)
logging.Logger.trace = trace

# Create a custom logger at the module level
logger = logging.getLogger(__name__)


def setup_logging(log_file, log_level="info"):
    try:
        level_used = logging.INFO
        logger.setLevel(logging.INFO)
        if log_level == "debug":
            level_used = logging.DEBUG
            logger.setLevel(logging.DEBUG)
        elif log_level == "trace":
            level_used = TRACE_LEVEL_NUM
            logger.setLevel(TRACE_LEVEL_NUM)

        logging.basicConfig(filename=log_file, level=level_used,
                            format='%(asctime)s - %(levelname)s - %(message)s')

        logger.info("====================")
        logger.info("`cleanup.py` started")
    except Exception:
        print("cleanup.py logging not initialized, exiting.")
        sys.exit(1)


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
    now = datetime.now()
    cutoff_date = now - timedelta(days=age)

    for filename in os.listdir(backup_dir):
        if backup_definition and not filename.startswith(backup_definition):
            continue

        if backup_type in filename:
            try:
                date_str = filename.split(f"_{backup_type}_")[1].split('.')[0]
                file_date = datetime.strptime(date_str, '%Y-%m-%d')
            except Exception as e:
                logger.error(f"Error parsing date from filename {filename}: {e}")
                continue

            if file_date < cutoff_date:
                file_path = os.path.join(backup_dir, filename)
                try:
                    os.remove(file_path)
                    logger.info(f"Deleted {backup_type} backup: {file_path}")
                except Exception as e:
                    logger.error(f"Error deleting file {file_path}: {e}")

# Assuming logger and other necessary imports and initial setup are done above

def delete_archives(backup_dir, archive_name):
    # Regex to match the archive files according to the naming convention
    archive_regex = re.compile(rf"^{re.escape(archive_name)}\.[0-9]+\.dar$")
    
    # Delete the specified .dar files according to the naming convention
    for filename in os.listdir(backup_dir):
        if archive_regex.match(filename):
            file_path = os.path.join(backup_dir, filename)
            try:
                os.remove(file_path)
                logger.info(f"Deleted archive slice: {file_path}")
            except Exception as e:
                logger.error(f"Error deleting archive slice {file_path}: {e}")

    # Delete associated .par2 files
    par2_regex = re.compile(rf"^{re.escape(archive_name)}\.[0-9]+\.dar\..*\.par2$")
    for filename in os.listdir(backup_dir):
        if par2_regex.match(filename):
            file_path = os.path.join(backup_dir, filename)
            try:
                os.remove(file_path)
                logger.info(f"Deleted PAR2 file: {file_path}")
            except Exception as e:
                logger.error(f"Error deleting PAR2 file {file_path}: {e}")



def show_version():
    script_name = os.path.basename(sys.argv[0])
    print(f"{script_name} {VERSION}")
    print('''Licensed under GNU GENERAL PUBLIC LICENSE v3, see the supplied file "LICENSE" for details.
THERE IS NO WARRANTY FOR THE PROGRAM, TO THE EXTENT PERMITTED BY APPLICABLE LAW, not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
See section 15 and section 16 in the supplied "LICENSE" file.''')

def main():
    parser = argparse.ArgumentParser(description="Cleanup old backup files.")
    parser.add_argument('--backup-definition', '-d', help="Specific backup definition to clean.")
    parser.add_argument('--config-file', '-c', type=str, help="Path to 'dar-backup.conf'", default=os.path.join(os.path.dirname(__file__), '../conf/dar-backup.conf'))
    parser.add_argument('--version', '-v', action='store_true', help="Show version information.")
    parser.add_argument('--delete-archive', type=str, help="Delete all .dar and .par2 files in the backup directory for given archive name.")
    args = parser.parse_args()

    if args.version:
        show_version()
        sys.exit(0)

    logfile_location, backup_dir, backup_d, diff_age, incr_age = read_config(args.config_file)
    setup_logging(logfile_location)

    if args.delete_archive:
        delete_archives(backup_dir, args.delete_archive)
        sys.exit(0)
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
