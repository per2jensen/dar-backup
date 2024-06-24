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
    test_files = {
        'file1.txt': 'This is file 1.',
        'file2.txt': 'This is file 2.',
        'file3.txt': 'This is file 3.',
        'file with spaces.txt': 'This is file with spaces.',
        'file_with_danish_chars_æøå.txt': 'This is file with danish chars æøå.',
        'file_with_DANISH_CHARS_ÆØÅ.txt': 'This is file with DANISH CHARS ÆØÅ.',
        'file_with_colon:.txt': 'This is file with colon :.',
        'file_with_hash#.txt': 'This is file with hash #.',
        'file_with_currency¤.txt': 'This is file with currency ¤.'
    }
    for filename, content in test_files.items():
        with open(os.path.join(test_dir, 'data', filename), 'w') as f:
            f.write(content)

def verify_backup_contents(backup_file_base, expected_files, check_saved=False):
    command = ['dar', '-l', backup_file_base, '-Q']
    result = subprocess.run(command, capture_output=True, text=True)
    logging.info(result.stdout)
    if result.returncode != 0:
        logging.error(result.stderr)
        return False

    backup_contents = result.stdout
    for expected_file in expected_files:
        if check_saved:
            pattern = re.compile(rf'\[Saved\].*{re.escape(expected_file)}')
            if not pattern.search(backup_contents):
                logging.error(f"Expected file {expected_file} not found with [Saved] marker in backup {backup_file_base}")
                return False
        else:
            if expected_file not in backup_contents:
                logging.error(f"Expected file {expected_file} not found in backup {backup_file_base}")
                return False

    return True

def main():
    setup_logging()
    prereq.cleanup_test_env()  # Clean up any existing test environments
    prereq.cleanup_dar_files()  # Clean up any existing .dar files
    test_dir, config_snippet_path, config_file_path = prereq.setup_test_env('test_create_full_diff_incr_backup')

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
    expected_files = [
        'data/file1.txt', 'data/file2.txt', 'data/file3.txt',
        'data/file with spaces.txt', 'data/file_with_danish_chars_æøå.txt',
        'data/file_with_DANISH_CHARS_ÆØÅ.txt', 'data/file_with_colon:.txt',
        'data/file_with_hash#.txt', 'data/file_with_currency¤.txt'
    ]
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
        return
    else:
        logging.info("Differential backup verification succeeded")

    # Modify another file for incremental backup
    with open(os.path.join(test_dir, 'data', 'file3.txt'), 'a') as f:
        f.write(' This is an additional line for incremental backup.')

    # Create INCR backup
    incr_backup_file_base = os.path.join(test_dir, 'backups', 'example_config_snippet_INCR_2024-06-24')
    logging.info("Creating INCR backup...")
    incr_backup_command = ['dar', '-c', incr_backup_file_base, '-B', config_snippet_path, '-A', diff_backup_file_base, '-Q']
    logging.info(f"Running command: {' '.join(incr_backup_command)}")
    if run_command(incr_backup_command) != 0:
        logging.error("Failed to create incremental backup")
        return

    # Verify INCR backup contents
    if not verify_backup_contents(incr_backup_file_base, ['data/file3.txt'], check_saved=True):
        logging.error("Incremental backup verification failed")
    else:
        logging.info("Incremental backup verification succeeded")

    logging.info("Test create full, diff, and incr backup passed successfully")

if __name__ == "__main__":
    main()


