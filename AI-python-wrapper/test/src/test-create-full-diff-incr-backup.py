#!/usr/bin/env python3

import unittest
from base_test_case import BaseTestCase

import os
import subprocess
import logging
import re
import shutil
import glob  # Added import statement

class Test_Create_Full_Diff_Incr_Backup(BaseTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()

        cls.create_test_files()

        # setup backup definitions
        cls.logger.info("generatge backup definition")
        cls.create_backup_definitions()
        cls.logger.info("backupdef created")
 
    
    def test_backup_functionality(self):
        try:
            # Add specific tests for backup functionality here
            # Placeholder for actual tests
            if self.run_backup_script() != 0:
                logging.error("Failed to create full backup")
                raise "TET"
        except Exception as e:
            self.logger.exception("Backup functionality test failed")
            

    def test_backup_functionality2(cls):
        try:
            # Add specific tests for backup functionality here
            # Placeholder for actual tests
            pass
        except Exception as e:
            cls.logger.exception("Backup functionality test failed")
            raise

    @classmethod
    def create_test_files(cls):
        logging.info("Creating test files...")
        os.makedirs(os.path.join(cls.test_dir, 'data'), exist_ok=True)
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
            with open(os.path.join(cls.test_dir, 'data', filename), 'w') as f:
                f.write(content)


    @classmethod
    def create_backup_definitions(cls):
        logging.info("Generating backup definition")
        backup_definitions = {
            "example" : f"""
-Q 
-B {cls.dar_rc}
-R /
-s 10G
-z6
-am
-g {os.path.join(cls.test_dir, 'data')}
""".replace("-g /tmp/", "-g tmp/")  # because dar does not allow first "/"
        }

        for filename, content in backup_definitions.items():
            with open(os.path.join(cls.test_dir, 'backup.d', filename), 'w') as f:
                f.write(content)


    
    def run_backup_script(self):
        command = ['python3',  os.path.join(self.test_dir, "bin", "backup_script.py"), '-d', "example", '--config-file', self.config_file]
        logging.info(command)
        result = subprocess.run(command, capture_output=True, text=True)
        logging.info(result.stdout)
        if result.returncode != 0:
            logging.error(result.stderr)
        return result.returncode

    def verify_backup_contents(cls, backup_file_base, expected_files, check_saved=False):
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

    @classmethod
    def cleanup_test_env(cls):
        if os.path.exists(UNIT_TEST_DIR):
            shutil.rmtree(UNIT_TEST_DIR)
        os.makedirs(UNIT_TEST_DIR)


    @classmethod
    def setup_test_env(cls, test_name):
        test_dir = os.path.join(UNIT_TEST_DIR, test_name)
        os.makedirs(test_dir, exist_ok=True)
        backup_definition_path = os.path.join(test_dir, 'backup.d')
        cls.logger.info("HEJ")
        return test_dir, backup_definition_path, config_file_path

    
    @classmethod
    def main(cls):
        cls.cleanup_test_env()  # Clean up any existing test environments
        cls.cleanup_dar_files()  # Clean up any existing .dar files

        test_dir, backup_definition_path, config_file_path =cls.setup_test_env('test_create_full_diff_incr_backup')


        # Create FULL backup
        full_backup_file_base = os.path.join(test_dir, 'backups', 'example_backup_definition_FULL_2024-06-24')
        logging.info("Creating FULL backup...")
        full_backup_arguments = ['-d', backup_definition_path, '--config-file', config_file]
        if run_backup_script(full_backup_arguments) != 0:
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
        diff_backup_file_base = os.path.join(test_dir, 'backups', 'example_backup_definition_DIFF_2024-06-24')
        logging.info("Creating DIFF backup...")
        diff_backup_arguments = ['--differential-backup', '-d', backup_definition_path, '--config-file', config_file_path]
        if run_backup_script(diff_backup_arguments) != 0:
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
        incr_backup_file_base = os.path.join(test_dir, 'backups', 'example_backup_definition_INCR_2024-06-24')
        logging.info("Creating INCR backup...")
        incr_backup_arguments = ['--incremental-backup', '-d', backup_definition_path, '--config-file', config_file_path]
        if run_backup_script(incr_backup_arguments) != 0:
            logging.error("Failed to create incremental backup")
            return

        # Verify INCR backup contents
        if not verify_backup_contents(incr_backup_file_base, ['data/file3.txt'], check_saved=True):
            logging.error("Incremental backup verification failed")
        else:
            logging.info("Incremental backup verification succeeded")


if __name__ == "__main__":
    unittest.main()
    