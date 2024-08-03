
import unittest
import subprocess
import logging
import random
import shutil
import sys
import os

from dar_backup.util import run_command

from base_test_case import BaseTestCase
from datetime import datetime

class Test_BitRot(BaseTestCase):
    """
    This module contains unit tests for detecting bitrot and fixing it in dar archives.

    The Test_BitRot class inherits from the BaseTestCase class and defines various test methods
    to verify the behavior of the bitrot recovery process.

    Attributes:
        file_sizes (dict): A dictionary mapping file sizes to their corresponding values in bytes.

    Methods:
        setUpClass(cls): A class method that sets up the necessary environment for running the tests.
        create_random_data_file(cls, name, size): A class method that creates a file with random data of a specific size.
        generate_datafiles(cls): A class method that generates the data files for testing.
        simulate_bitrot(cls, bitrot): A class method that simulates bitrot in a dar archive by replacing a percentage of the file with random data.
        create_backup_definitions(cls): A class method that generates the backup definitions for testing.
        run_command(self, command): A method that runs a command and returns the exit code.
        test_bitrot_recovery(self): A test method that verifies the bitrot recovery process.
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
        cls.logger.info("generate backup definition")
        cls.create_backup_definitions()
        cls.logger.info("backupdef created")

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
    def simulate_bitrot(cls, bitrot: int = 5):
        """
        Simulate bitrot in a dar archive by replacing a percentage of the file with random data.

        Args:
            bitrot (int): The percentage of the file to be affected by bitrot.
        """
        date = datetime.now().strftime('%Y-%m-%d')
        archive = f'example_FULL_{date}.1.dar'
        archive_path = os.path.join(cls.test_dir, "backups", archive)

        # Check if the file exists
        if os.path.exists(archive_path):
            archive_size = os.path.getsize(archive_path)
            logging.info(f"Size of archive: {archive_path} is {archive_size} bytes")
            # Generate random bytes
            random_bytes = bytearray(random.getrandbits(8) for _ in range(int(archive_size*(bitrot/100)*0.98))) 
            # Open the file in write mode
            with open(archive_path, "r+b") as file:
                # Seek to random position between 0 - 70% of file size
                random_position = random.randint(0, int(archive_size * 0.7))
                file.seek(random_position)
                # Write the random bytes
                file.write(random_bytes)
            cls.logger.info(f"{bitrot}% bitrot created in {archive_path}")
        else:
            cls.logger.error(f"File {archive_path} does not exist.")
            sys.exit(1)

    @classmethod
    def create_backup_definitions(cls):
        """
        Generate the backup definitions for testing.

        This method creates the backup definition files using the backup_definitions dictionary.
        """
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

    
    @classmethod
    def modify_par2_redundancy(cls, redundancy: int) -> None:
        """
        Modify the redundancy level of the par2 files by patching the dar-backup.conf file

        Args:
            redundancy (int): The redundancy level to be set.

        Raises:
            RuntimeError: If the command fails.
        """
        with open(cls.config_file, 'r') as f:
            lines = f.readlines()
        with open(cls.config_file, 'w') as f:
            for line in lines:
                if line.startswith('ERROR_CORRECTION_PERCENT'):
                    f.write(f'ERROR_CORRECTION_PERCENT = {redundancy}\n')
                else:
                    f.write(line)


    def tearDown(self) -> None:
        return super().cleanup_before_test()
    

    def check_bitrot_recovery(self):
        """
        Verify the bitrot recovery process.

        This test method performs the following steps:
        1. Simulates bitrot in the backup archive.
        2. Verifies that dar detects the bitrot and raises an exception.
        3. Uses parchive2 to repair the bitrot.
        4. Verifies that the archive is successfully repaired.
        """
        date = datetime.now().strftime('%Y-%m-%d')
        basename_path = os.path.join(self.test_dir, "backups", f"example_FULL_{date}")
        archive_path = os.path.join(self.test_dir, "backups", f"example_FULL_{date}.1.dar")
        try:
            command = ['dar', '-t', basename_path]
            run_command(command)
            logging.error(f"dar does not detect a bad archive: {basename_path} ")
            sys.exit(1)
        except Exception as e:
            logging.info(f"Expected exception due to bitrot")
        
        try:
            # fix bitrot with parchive2
            command = ["par2", "repair", "-q", archive_path]
            run_command(command)

            # test archive once more
            command = ['dar', '-t', basename_path]
            run_command(command)
            logging.info(f"Archive: {archive_path}  successfully repaired")
        except Exception as e:
            logging.exception(f"Expected no errors after parchive repair")
            sys.exit(1)


    def test_5percent_bitrot_recovery(self):
        """
        Verify the bitrot recovery process with 5% bitrot.
        Expects to run in a virtual environment with dar-backup installed
        """
        logging.info(f"--> Start running test: {sys._getframe().f_code.co_name}")
        self.generate_datafiles()
        self.modify_par2_redundancy(5)
        command = ['dar-backup', '--full-backup' ,'-d', "example", '--config-file', self.config_file]
        run_command(command)
        self.simulate_bitrot(5)
        self.check_bitrot_recovery()


    def test_25percent_bitrot_recovery(self):
        """
        Verify the bitrot recovery process with 25% bitrot.
        Expects to run in a virtual environment with dar-backup installed
        """
        logging.info(f"--> Start running test: {sys._getframe().f_code.co_name}")
        self.generate_datafiles()
        self.modify_par2_redundancy(25)
        command = ['dar-backup', '--full-backup' ,'-d', "example", '--config-file', self.config_file]
        run_command(command)
        self.simulate_bitrot(25)
        self.check_bitrot_recovery()



if __name__ == '__main__':
    unittest.main()
    
