import unittest
import os
from base_test_case import BaseTestCase
import subprocess
import logging
import re

class Test_Backup_Script(BaseTestCase):
    
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.create_test_files()

    @classmethod
    def create_test_files(cls):
        cls.logger.info("Creating test files...")
        data_dir = os.path.join(cls.test_dir, 'data')
        os.makedirs(data_dir, exist_ok=True)
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
            with open(os.path.join(data_dir, filename), 'w') as f:
                f.write(content)

    def run_command(self, command):
        result = subprocess.run(command, capture_output=True, text=True)
        self.logger.info(result.stdout)
        if result.returncode != 0:
            self.logger.error(result.stderr)
        return result.returncode

    def verify_backup_contents(self, backup_file_base, expected_files, check_saved=False):
        command = ['dar', '-l', backup_file_base, '-Q']
        result = subprocess.run(command, capture_output=True, text=True)
        self.logger.info(result.stdout)
        if result.returncode != 0:
            self.logger.error(result.stderr)
            return False

        backup_contents = result.stdout
        for expected_file in expected_files:
            if check_saved:
                pattern = re.compile(rf'\[Saved\].*{re.escape(expected_file)}')
                if not pattern.search(backup_contents):
                    self.logger.error(f"Expected file {expected_file} not found with [Saved] marker in backup {backup_file_base}")
                    return False
            else:
                if expected_file not in backup_contents:
                    self.logger.error(f"Expected file {expected_file} not found in backup {backup_file_base}")
                    return False

        return True

    def test_create_full_diff_incr_backup(self):
        self.logger.info("Starting test_create_full_diff_incr_backup")

        # Create FULL backup
        full_backup_file_base = os.path.join(self.test_dir, 'backups', 'example_config_snippet_FULL_2024-06-24')
        self.logger.info("Creating FULL backup...")
        full_backup_command = ['dar', '-c', full_backup_file_base, '-B', self.config_file, '-Q']
        self.logger.info(f"Running command: {' '.join(full_backup_command)}")
        self.assertEqual(self.run_command(full_backup_command), 0, "Failed to create full backup")

        # Verify FULL backup contents
        expected_files = [
            'data/file1.txt', 'data/file2.txt', 'data/file3.txt',
            'data/file with spaces.txt', 'data/file_with_danish_chars_æøå.txt',
            'data/file_with_DANISH_CHARS_ÆØÅ.txt', 'data/file_with_colon:.txt',
            'data/file_with_hash#.txt', 'data/file_with_currency¤.txt'
        ]
        self.assertTrue(self.verify_backup_contents(full_backup_file_base, expected_files), "Full backup verification failed")

        # Modify one file for differential backup
        with open(os.path.join(self.test_dir, 'data', 'file2.txt'), 'a') as f:
            f.write(' This is an additional line.')

        # Create DIFF backup
        diff_backup_file_base = os.path.join(self.test_dir, 'backups', 'example_config_snippet_DIFF_2024-06-24')
        self.logger.info("Creating DIFF backup...")
        diff_backup_command = ['dar', '-c', diff_backup_file_base, '-B', self.config_file, '-A', full_backup_file_base, '-Q']
        self.logger.info(f"Running command: {' '.join(diff_backup_command)}")
        self.assertEqual(self.run_command(diff_backup_command), 0, "Failed to create differential backup")

        # Verify DIFF backup contents
        self.assertTrue(self.verify_backup_contents(diff_backup_file_base, ['data/file2.txt'], check_saved=True), "Differential backup verification failed")

        # Modify another file for incremental backup
        with open(os.path.join(self.test_dir, 'data', 'file3.txt'), 'a') as f:
            f.write(' This is an additional line for incremental backup.')

        # Create INCR backup
        incr_backup_file_base = os.path.join(self.test_dir, 'backups', 'example_config_snippet_INCR_2024-06-24')
        self.logger.info("Creating INCR backup...")
        incr_backup_command = ['dar', '-c', incr_backup_file_base, '-B', self.config_file, '-A', diff_backup_file_base, '-Q']
        self.logger.info(f"Running command: {' '.join(incr_backup_command)}")
        self.assertEqual(self.run_command(incr_backup_command), 0, "Failed to create incremental backup")

        # Verify INCR backup contents
        self.assertTrue(self.verify_backup_contents(incr_backup_file_base, ['data/file3.txt'], check_saved=True), "Incremental backup verification failed")

        self.logger.info("Test create full, diff, and incr backup passed successfully")


if __name__ == '__main__':
    unittest.main()
