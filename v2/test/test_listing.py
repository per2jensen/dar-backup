
import unittest
import subprocess
import logging
import random
import shutil
import sys
import os

from base_test_case import BaseTestCase
from datetime import datetime
from subprocess import CompletedProcess

from dar_backup.util import run_command

class Test_Listing(BaseTestCase):
    """
    A test case class for the --list option.
    """


    @classmethod
    def setUpClass(cls):
        """
        Set up the necessary environment for running the tests.

        This method is called before any test methods in the class are executed.
        It initializes the test_files dictionary, generates the data files, and creates the backup definitions.
        """
        super().setUpClass()

        cls.test_files = {}
        cls.create_test_files()

    @classmethod
    def create_test_files(cls):
        logging.info("Creating test dummy archive files...")
        cls.test_files = {
            f'example_FULL_.1.dar': 'dummy',
            f'example.1.dar': 'dummy',
            f'example_DIFF_199_01-01.1.dar': 'dummy',
            f'example.txt': 'dummy',
            f'example_FULL_2024-07-25.1.dar': 'dummy',
            f'example_DIFF_2024-07-25.1.dar': 'dummy',
            f'example_INCR_2024-07-25.1.dar': 'dummy',

        }
        for filename, content in cls.test_files.items():
            with open(os.path.join(cls.test_dir, 'backups', filename), 'w') as f:
                f.write(content)

    def tearDown(self) -> None:
        """
        Clean up after each test method is executed.
        """
        return super().tearDown()
        
    def test_list_dar_archives(self):
        """
        Expects to be run in a virtal environment with dar-backup installed.
        """
        logging.info(f"--> Start running test: {sys._getframe().f_code.co_name}")
        command = ['dar-backup', '--list', '--config-file', self.config_file]
        process = run_command(command)
        stdout, stderr = process.communicate()

        # Check for all expected files using regex
        expected_patterns = [
            r'example_FULL_\d{4}-\d{2}-\d{2}',
            r'example_DIFF_\d{4}-\d{2}-\d{2}',
            r'example_INCR_\d{4}-\d{2}-\d{2}']

        for pattern in expected_patterns:
            self.assertRegex(stdout, pattern)

        # Ensure specific files are not listed
        unexpected_patterns = [
            r'example(?!_FULL_\d{4}-\d{2}-\d{2})(?!_DIFF_\d{4}-\d{2}-\d{2})(?!_INCR_\d{4}-\d{2}-\d{2})',
            r'example_DIFF_199_01-01',
            r'example.txt']

        for pattern in unexpected_patterns:
            self.assertNotRegex(stdout, pattern)

        logging.info(f"<-- Finished running test: {sys._getframe().f_code.co_name}")

if __name__ == '__main__':
    unittest.main()
    
