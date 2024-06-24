#!/usr/bin/env python3

import os
import subprocess
import logging
import prereq
import glob
import re

UNIT_TEST_DIR = '/tmp/unit-test/'

def setup_logging():
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

def run_command(command):
    result = subprocess.run(command, capture_output=True, text=True)
    logging.info(result.stdout)
    if result.returncode != 0:
        logging.error(result.stderr)
    return result.returncode

def create_test_files(test_dir):
    logging.info("Creating test files...")
    os.makedirs(os.path.join(test_dir, 'data'), exist_ok=True)
    with open(os.path.join(test_dir, 'data', 'file1.txt'), 'w') as f:
        f.write('This is file 1.')
    with open(os.path.join(test_dir, 'data', 'file2.txt'), 'w') as f:
        f.write('This is file 2.')
    with open(os.path.join(test_dir, 'data', 'file3.txt'), 'w') as f:
        f.write('This is file 3.')

def verify_backup_contents(backup_file_base, expected_files, check_saved=False):
    command = ['dar', '-l', backup_file_base, '-Q']
    result = subprocess.run(command, capture_output=True, text=True)
    logging.info(result.stdout)
    if result.returncode != 0:
        logging.error(result.stderr)
        return False

    for expected_file in expected_files:
        if check_saved:
            pattern = re.compile(rf'\[Saved\].*{re.escape(expected_file)}')
            if not pattern.search(result.stdout):
                logging.error(f"Expected file {expected_file} not found with [Saved] marker in backup {backup_file_base}")
                return False
        else:
            if expected_file not in result.stdout:
                logging.error(f"Expected file {expected_file} not found in backup {backup_file_base}")
                return False

    return True

def main():
    setup_logging()
    prereq.cleanup_test_env()  # Clean up any existing test environments
    prereq.cleanup_dar_files()  # Clean up any existing .dar files
    test_dir, config_snippet_path, config_file_path = prereq.setup_test_env('test_create_full_and_diff_backup')

    # Setup test environment
    create_test_files(test_dir)

    # Create FULL backup
    full_backup_file_base = os.path.join(test_dir, 'backups', 'example_config_snippet_FULL_2024-06-24')
    logging.info("Creating FULL backup...")
    full_backup_command = ['dar', '-c', full_backup_file_base, '-B', config_snippet_path, '-Q']
    logging.info(f"Running command: {' '.join(full_backup_command)}")
    if run_command(full_backup_command) != 0:
        logging.error("Failed to create full backup")
        return

    # Verify FULL backup contents
    expected_files = ['data/file1.txt', 'data/file2.txt', 'data/file3.txt']
    if not verify_backup_contents(full_backup_file_base, expected_files):
        logging.error("Full backup verification failed")
        return
    else:
        logging.info("FULL backup verification succeeded")

    # Modify one file for differential backup
    with open(os.path.join(test_dir, 'data', 'file2.txt'), 'a') as f:
        f.write(' This is an additional line.')

    # Create DIFF backup
    diff_backup_file_base = os.path.join(test_dir, 'backups', 'example_config_snippet_DIFF_2024-06-24')
    logging.info("Creating DIFF backup...")
    diff_backup_command = ['dar', '-c', diff_backup_file_base, '-B', config_snippet_path, '-A', full_backup_file_base, '-Q']
    logging.info(f"Running command: {' '.join(diff_backup_command)}")
    if run_command(diff_backup_command) != 0:
        logging.error("Failed to create differential backup")
        return

    # Verify DIFF backup contents
    if not verify_backup_contents(diff_backup_file_base, ['data/file2.txt'], check_saved=True):
        logging.error("Differential backup verification failed")
    else:
        logging.info("Differential backup verification succeeded")

    logging.info("Test create full and diff backup passed successfully")

if __name__ == "__main__":
    main()
