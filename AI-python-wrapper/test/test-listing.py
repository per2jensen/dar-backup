
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
        

    def run_command(self, command: list[str]) -> CompletedProcess:
        """
        Run a command and return the exit code.

        Args:
            command (list): The command to be executed.

        Returns:
            int: The exit code of the command.

        Raises:
            RuntimeError: If the command fails.
        """
        logging.info(command)
        result = subprocess.run(command, capture_output=True, text=True)
        logging.info(result.stdout)
        if result.returncode != 0:
            logging.error(result.stderr)
            raise RuntimeError(f"Command failed with return code {result.returncode}")
        return result


    def test_list_dar_archives(self):
        """
        """
        logging.info(f"--> Start running test: {sys._getframe().f_code.co_name}")
        command = ['python3',  os.path.join(self.test_dir, "bin", "dar-backup.py"), '--list', '--config-file', self.config_file]
        result = self.run_command(command)
        self.assertIn('example_FULL_2024-07-25', result.stdout)
        self.assertIn('example_DIFF_2024-07-25', result.stdout)
        self.assertIn('example_INCR_2024-07-25', result.stdout)
        self.assertNotIn('example_DIFF_199_01-01', result.stdout) 
        self.assertNotIn('example.txt', result.stdout)
        logging.info(f"<-- Finished running test: {sys._getframe().f_code.co_name}")

if __name__ == '__main__':
    unittest.main()
    
