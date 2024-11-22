import logging
import random
import sys
import os

from dar_backup.util import run_command
from datetime import datetime
from tests.envdata import EnvData

"""
This module contains unit tests for detecting bitrot and fixing it in dar archives.
"""


def create_random_data_file(env: EnvData, name, size):
    """
    Create a file with random data of a specific size.

    Args:
        name (str): The name of the file.
        size (int): The size of the file in bytes.
    """
    filename = f"random-{name}.dat"
    with open(os.path.join(env.test_dir, "data", filename), 'wb') as f:
        f.write(os.urandom(size))
        env.logger.info(f'Created {os.path.join(env.test_dir, "data", filename)} of size {name}')



def generate_datafiles(env: EnvData, file_sizes: dict) -> None:
    """
    Generate the data files for testing.

    This method creates files of different sizes using the create_random_data_file method.
    """
    try:
        # Create files
        for name, size in file_sizes.items():
            create_random_data_file(env, name, size)
    except Exception as e:
        env.logger.exception("data file generation failed")
        raise



def simulate_bitrot(env: EnvData, bitrot: int = 5):
    """
    Simulate bitrot in a dar archive by replacing a percentage of the file with random data.

    Args:
        bitrot (int): The percentage of the file to be affected by bitrot.
    """
    date = datetime.now().strftime('%Y-%m-%d')
    archive = f'example_FULL_{date}.1.dar'
    archive_path = os.path.join(env.test_dir, "backups", archive)

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
        env.logger.info(f"{bitrot}% bitrot created in {archive_path}")
    else:
        env.logger.error(f"File {archive_path} does not exist.")
        sys.exit(1)


def modify_par2_redundancy(env: EnvData, redundancy: int) -> None:
    """
    Modify the redundancy level of the par2 files by patching the dar-backup.conf file

    Args:
        redundancy (int): The redundancy level to be set.

    Raises:
        RuntimeError: If the command fails.
    """
    with open(env.config_file, 'r') as f:
        lines = f.readlines()
    with open(env.config_file, 'w') as f:
        for line in lines:
            if line.startswith('ERROR_CORRECTION_PERCENT'):
                f.write(f'ERROR_CORRECTION_PERCENT = {redundancy}\n')
            else:
                f.write(line)



def check_bitrot_recovery(env: EnvData):
    """
    Verify the bitrot recovery process.

    This test method performs the following steps:
    1. Simulates bitrot in the backup archive.
    2. Verifies that dar detects the bitrot and raises an exception.
    3. Uses parchive2 to repair the bitrot.
    4. Verifies that the archive is successfully repaired.
    """
    date = datetime.now().strftime('%Y-%m-%d')
    basename_path = os.path.join(env.test_dir, "backups", f"example_FULL_{date}")
    archive_path = os.path.join(env.test_dir, "backups", f"example_FULL_{date}.1.dar")
    try:
        command = ['dar', '-t', basename_path]
        process = run_command(command)
        if process.returncode != 0:
            raise RuntimeError(f"dar detected a bad archive: {basename_path}")
        else:
            logging.error(f"dar does not detect a bad archive: {basename_path} ")
            sys.exit(1)
    except Exception as e:
        logging.info(f"Expected exception due to bitrot")
    
    try:
        # fix bitrot with parchive2
        command = ["par2", "repair", "-q", archive_path]
        process = run_command(command)
        if process.returncode != 0:
            raise RuntimeError(f"parchive2 failed to repair the archive: {archive_path}")
        
        # test archive once more
        command = ['dar', '-t', basename_path]
        process = run_command(command)
        if process.returncode != 0:
            raise RuntimeError(f"dar archive test failed: {basename_path}")
        
        logging.info(f"Archive: {archive_path}  successfully repaired")
    except Exception as e:
        logging.exception(f"Expected no errors after parchive repair")
        sys.exit(1)


def test_5_bitrot_recovery(setup_environment, env: EnvData):
    """
    Verify the bitrot recovery process with 5% bitrot.
    Expects to run in a virtual environment with dar-backup installed
    """
    redundancy = 5  # redundancy in percent
    run_bitrot_recovery(env, redundancy)


def test_25_bitrot_recovery(setup_environment, env: EnvData):
    """
    Verify the bitrot recovery process with 5% bitrot.
    Expects to run in a virtual environment with dar-backup installed
    """

    redundancy = 25  # redundancy in percent
    run_bitrot_recovery(env, redundancy)



def run_bitrot_recovery(env: EnvData, redundancy_percentage: int):
    """
    Verify the bitrot recovery process with 25% bitrot.
    Expects to run in a virtual environment with dar-backup installed
    """
    file_sizes = {
        '100kB': 100 * 1024,
        '1MB': 1024 * 1024,
        '10MB': 10 * 1024 * 1024
    }
    generate_datafiles(env, file_sizes)
    modify_par2_redundancy(env, redundancy_percentage)
    print(f"env: {env}")
    command = ['dar-backup', '--full-backup' ,'-d', "example", '--config-file', env.config_file]
    process = run_command(command)
    stdout,stderr = process.communicate()
    if process.returncode != 0:
        logging.error(f"dar stdout: {stdout}")
        logging.error(f"dar stderr: {stderr}")
        raise RuntimeError(f"dar-backup failed to create a full backup")
    simulate_bitrot(env, redundancy_percentage)
    check_bitrot_recovery(env)

