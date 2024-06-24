#!/usr/bin/env python3

import argparse
import os
import sys
import configparser
import logging
from datetime import datetime, timedelta

VERSION = "0.1"

def setup_logging(log_file):
    logging.basicConfig(filename=log_file, level=logging.DEBUG,
                        format='%(asctime)s - %(levelname)s - %(message)s')
    console = logging.StreamHandler()
    console.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    console.setFormatter(formatter)
    logging.getLogger().addHandler(console)

def read_config():
    config = configparser.ConfigParser()
    config_file = os.path.join(os.path.dirname(__file__), '../conf/backup_script.conf')
    try:
        config.read(config_file)
        logfile_location = config['DEFAULT']['LOGFILE_LOCATION']
        backup_dir = config['DEFAULT']['BACKUP_DIR']
        backup_d = config['DEFAULT']['BACKUP.D']
        diff_age = int(config['DEFAULT']['DIFF_AGE'])
        incr_age = int(config['DEFAULT']['INCR_AGE'])
    except Exception as e:
        logging.error(f"Error reading config file {config_file}: {e}")
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
                logging.error(f"Error parsing date from filename {filename}: {e}")
                continue

            if file_date < cutoff_date:
                file_path = os.path.join(backup_dir, filename)
                try:
                    os.remove(file_path)
                    logging.info(f"Deleted old {backup_type} backup: {file_path}")
                except Exception as e:
                    logging.error(f"Error deleting file {file_path}: {e}")

def show_version():
    script_name = os.path.basename(sys.argv[0])
    print(f"{script_name} {VERSION}")
    print('''Licensed under GNU GENERAL PUBLIC LICENSE v3, see the supplied file "LICENSE" for details.
THERE IS NO WARRANTY FOR THE PROGRAM, TO THE EXTENT PERMITTED BY APPLICABLE LAW, not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
See section 15 and section 16 in the supplied "LICENSE" file.''')

def main():
    parser = argparse.ArgumentParser(description="Cleanup old backup files.")
    parser.add_argument('--backup-definition', '-d', help="Specific backup definition to clean.")
    parser.add_argument('--version', '-v', action='store_true', help="Show version information.")
    args = parser.parse_args()

    if args.version:
        show_version()
        sys.exit(0)

    logfile_location, backup_dir, backup_d, diff_age, incr_age = read_config()
    setup_logging(logfile_location)

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
