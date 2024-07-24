import unittest
import subprocess
import logging
import random
import shutil
import sys
import os

from base_test_case import BaseTestCase
from datetime import datetime

class Test_BitRot(BaseTestCase):

    file_sizes = {
    '100kB': 100 * 1024,
    '1MB': 1024 * 1024,
    '10MB': 10 * 1024 * 1024}

    @classmethod
    def setUpClass(cls):
        super().setUpClass()

        cls.test_files = {}
        cls.generate_datafiles()

        # setup backup definitions
        cls.logger.info("generate backup definition")
        cls.create_backup_definitions()
        cls.logger.info("backupdef created")

    @classmethod
    def create_random_data_file(cls, name, size):
        """Create a file with random data of a specific size."""
        filename=f"random-{name}.dat"
        with open(os.path.join(cls.test_dir, "data", filename), 'wb') as f:
            f.write(os.urandom(size))
            cls.logger.info(f'Created {os.path.join(cls.test_dir, "data", filename)} of size {name}')

    @classmethod
    def generate_datafiles(cls):
        try:
            # Create files
            for name, size in cls.file_sizes.items():
                cls.create_random_data_file(name, size)
        except Exception as e:
            cls.logger.exception("data file generation failed")
            raise


    @classmethod
    def simulate_bitrot(cls):
        """Simulate bitrot in dar archive by replacing 5% with random data"""
        date = datetime.now().strftime('%Y-%m-%d')
        archive = f'example_FULL_{date}.1.dar'
        archive_path = os.path.join(cls.test_dir, "backups", archive)

        # Check if the file exists
        if os.path.exists(archive_path):
            archive_size = os.path.getsize(archive_path)
            logging.info(f"Size of archive: {archive_path} is {archive_size} bytes")
            # Generate 5% random bytes
            random_bytes = bytearray(random.getrandbits(8) for _ in range(int(archive_size*0.049)))  # 4,9% bitrot
            # Open the file in write mode
            with open(archive_path, "r+b") as file:
                # Seek to position 40% into the file
                file.seek(int(archive_size*0.4))
                # Write the random bytes
                file.write(random_bytes)
            cls.logger.info(f"5% bitrot created in {archive_path}")
        else:
            cls.logger.error(f"File {archive_path} does not exist.")


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



    def run_command(self, command: list[str]) -> int:
        logging.info(command)
        result = subprocess.run(command, capture_output=True, text=True)
        logging.info(result.stdout)
        if result.returncode != 0:
            logging.error(result.stderr)
            raise RuntimeError(f"Command failed with return code {result.returncode}")
        return result.returncode


    def test_bitrot_recovery(self):
        logging.info(f"--> Start running test: {sys._getframe().f_code.co_name}")
        self.generate_datafiles()
        command = ['python3',  os.path.join(self.test_dir, "bin", "dar-backup.py"), '--full-backup' ,'-d', "example", '--config-file', self.config_file]
        self.run_command(command)
        self.simulate_bitrot()
        
        date = datetime.now().strftime('%Y-%m-%d')
        basename_path = os.path.join(self.test_dir, "backups", f"example_FULL_{date}")
        archive_path = os.path.join(self.test_dir, "backups", f"example_FULL_{date}.1.dar")
        try:
            command = ['dar', '-t', basename_path]
            self.run_command(command)
            logging.error(f"dar does not detect a bad archive: {basename_path} ")
            sys.exit(1)
        except RuntimeError as e:
            logging.info(f"Expected exception due to bitrot")
        
        # fix bitrot with parchive2
        command = ["par2", "repair", "-q", archive_path]
        self.run_command(command)

        # test archive once more
        try:
            command = ['dar', '-t', basename_path]
            self.run_command(command)
        except RuntimeError as e:
            logging.exception(f"Expected no errors after parchive repair")
            sys.exit(1)


if __name__ == '__main__':
    unittest.main()
    
