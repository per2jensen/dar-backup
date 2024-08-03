
import unittest
import subprocess
import logging
import random
import shutil
import sys
import os

from base_test_case import BaseTestCase
from datetime import datetime

from dar_backup.util import run_command

class Test_Space_In_Definition(BaseTestCase):
    """
    A test case class for testing backup definitions with spaces in their names.
    """

    file_sizes = {
        '100kB': 100 * 1024,
        '1MB': 1024 * 1024,
        '10MB': 10 * 1024 * 1024
    }

    @classmethod
    def setUpClass(cls):
        """
        Set up the necessary environment for running the tests.

        This method is called before any test methods in the class are executed.
        It initializes the test_files dictionary, generates the data files, and creates the backup definitions.
        """
        super().setUpClass()

        cls.test_files = {}
        cls.generate_datafiles()

        # setup backup definitions
        cls.create_backup_definitions()

    @classmethod
    def create_random_data_file(cls, name, size):
        """
        Create a file with random data of a specific size.

        Args:
            name (str): The name of the file.
            size (int): The size of the file in bytes.
        """
        filename = f"random-{name}.dat"
        with open(os.path.join(cls.test_dir, "data", filename), 'wb') as f:
            f.write(os.urandom(size))
            cls.logger.info(f'Created {os.path.join(cls.test_dir, "data", filename)} of size {name}')

    @classmethod
    def generate_datafiles(cls):
        """
        Generate the data files for testing.

        This method creates files of different sizes using the create_random_data_file method.
        """
        try:
            # Create files
            for name, size in cls.file_sizes.items():
                cls.create_random_data_file(name, size)
        except Exception as e:
            cls.logger.exception("data file generation failed")
            raise


    @classmethod
    def create_backup_definitions(cls):
        """
        Generate the backup definitions for testing.

        This method creates the backup definition files using the backup_definitions dictionary.
        """
        logging.info("Generating backup definition")
        backup_definitions = {
            "example 2" : f"""
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

    
    def tearDown(self) -> None:
        """
        Clean up after each test method is executed.
        """
        return super().tearDown()
        

    def test_backup_definition_with_space(self):
        """
        Verify that the backups are correct when a backup
        definition name contains space(s)

        Expects to be run in a virtal environment with dar-backup installed.
        """
        logging.info(f"--> Start running test: {sys._getframe().f_code.co_name}")
        self.generate_datafiles()
        command = ['dar-backup', '--full-backup' ,'-d', "example 2", '--config-file', self.config_file]
        process = run_command(command)

if __name__ == '__main__':
    unittest.main()
    
