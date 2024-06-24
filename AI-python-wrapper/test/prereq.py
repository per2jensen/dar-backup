#!/usr/bin/env python3

import os
import shutil
import logging
import glob
import argparse
import sys

UNIT_TEST_DIR = '/tmp/unit-test/'
VERSION = "0.1"

def setup_logging():
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

def cleanup_test_env(base_dir=UNIT_TEST_DIR):
    for item in os.listdir(base_dir):
        item_path = os.path.join(base_dir, item)
        if os.path.isdir(item_path):
            try:
                logging.info(f"Cleaning up test environment: {item_path}")
                shutil.rmtree(item_path)
            except Exception as e:
                logging.error(f"Error cleaning up test environment {item_path}: {e}")

def cleanup_dar_files(base_dir=UNIT_TEST_DIR):
    dar_files = glob.glob(os.path.join(base_dir, '*.dar*'))
    for dar_file in dar_files:
        try:
            logging.info(f"Removing dar file: {dar_file}")
            os.remove(dar_file)
        except Exception as e:
            logging.error(f"Error removing dar file {dar_file}: {e}")

def setup_test_env(test_name):
    test_dir = os.path.join(UNIT_TEST_DIR, test_name)
    logging.info(f"Setting up test environment in {test_dir}")

    if os.path.exists(test_dir):
        shutil.rmtree(test_dir)
    os.makedirs(test_dir)

    # Create necessary directories
    os.makedirs(os.path.join(test_dir, 'backup.d'))
    os.makedirs(os.path.join(test_dir, 'conf'))
    os.makedirs(os.path.join(test_dir, 'logs'))
    os.makedirs(os.path.join(test_dir, 'backups'))
    os.makedirs(os.path.join(test_dir, 'restore'))

    # Create backup.d/example_config_snippet
    config_snippet_path = os.path.join(test_dir, 'backup.d', 'example_config_snippet')
    with open(config_snippet_path, 'w') as f:
        f.write(f'-R {test_dir}\n-g data\n')

    # Create conf/backup_script.conf
    config_file_path = os.path.join(test_dir, 'conf', 'backup_script.conf')
    with open(config_file_path, 'w') as f:
        f.write(
            "[DEFAULT]\n"
            "LOGFILE_LOCATION = /tmp/unit-test/test_create_full_and_diff_backup/logs/backup_script.log\n"
            "BACKUP_DIR = /tmp/unit-test/test_create_full_and_diff_backup/backups/\n"
            "TEST_RESTORE_DIR = /tmp/unit-test/test_create_full_and_diff_backup/restore/\n"
            "BACKUP.D = /tmp/unit-test/test_create_full_and_diff_backup/backup.d/\n"
        )

    return test_dir, config_snippet_path, config_file_path

def show_version():
    script_name = os.path.basename(sys.argv[0])
    print(f"{script_name} {VERSION}")
    print('''Licensed under GNU GENERAL PUBLIC LICENSE v3, see the supplied file "LICENSE" for details.
THERE IS NO WARRANTY FOR THE PROGRAM, TO THE EXTENT PERMITTED BY APPLICABLE LAW, not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
See section 15 and section 16 in the supplied "LICENSE" file.''')

def main():
    parser = argparse.ArgumentParser(description="Setup and clean test environment.")
    parser.add_argument('--version', '-v', action='store_true', help="Show version information.")
    args = parser.parse_args()

    if args.version:
        show_version()
        sys.exit(0)

    setup_logging()
    os.makedirs(UNIT_TEST_DIR, exist_ok=True)
    cleanup_test_env()
    cleanup_dar_files()
    setup_test_env('example_test')

if __name__ == "__main__":
    main()
