import logging
import random
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from dar_backup.command_runner import CommandRunner
from dar_backup.config_settings import ConfigSettings
from datetime import datetime
from tests.envdata import EnvData
from dar_backup.util import CommandResult

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
    except Exception:
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


def check_bitrot_recovery(env: EnvData, command_timeout: int):
    """
    Verify the bitrot recovery process.
    This test method performs the following steps:
    1. Simulates bitrot in the backup archive.
    2. Verifies that dar detects the bitrot and raises an exception.
    3. Uses parchive2 to repair the bitrot.
    4. Verifies that the archive is successfully repaired.
    """
    runner = CommandRunner(
        logger=env.logger,
        command_logger=env.command_logger,
        default_timeout=command_timeout
    )
    date = datetime.now().strftime('%Y-%m-%d')
    basename_path = os.path.join(env.test_dir, "backups", f"example_FULL_{date}")
    backup_dir = os.path.join(env.test_dir, "backups")
    archive_path = os.path.join(backup_dir, f"example_FULL_{date}.1.dar")
    par2_path = os.path.join(backup_dir, f"example_FULL_{date}.par2")
    
    # Step 1: dar should detect corruption
    try:
        command = ['dar', '-t', basename_path]
        result: CommandResult = runner.run(command)
        logging.info(f"stdout:\n{result.stdout}")
        logging.info(f"stderr:\n{result.stderr}")
        # Assert bitrot is detected from stderr or non-zero return
        assert result.returncode != 0, "dar returned success on corrupted archive!"
        assert any(
            keyword in result.stderr.lower()
            for keyword in ("crc", "error", "corrupt", "checksum")
        ), "Expected bitrot error not found in stderr"
        logging.info("dar detected archive corruption as expected.")
    except AssertionError:
        logging.exception("Bitrot was not detected as expected")
        sys.exit(1)

    # Step 2: Repair
    try:
        command = ["par2", "repair", "-B", backup_dir, "-q", par2_path]
        result: CommandResult = runner.run(command)
        logging.info(f"stdout:\n{result.stdout}")
        logging.info(f"stderr:\n{result.stderr}")
        assert result.returncode == 0, "par2 failed to repair the archive"

        # Step 3: dar test should now pass
        command = ['dar', '-t', basename_path]
        result: CommandResult = runner.run(command)
        logging.info(f"stdout:\n{result.stdout}")
        logging.info(f"stderr:\n{result.stderr}")
        assert result.returncode == 0, "dar test failed after par2 repair"
        logging.info(f"Archive successfully repaired and verified: {archive_path}")
    except Exception:
        logging.exception("Unexpected error during recovery or verification")
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
    Verify the bitrot recovery process with 25% bitrot.
    Expects to run in a virtual environment with dar-backup installed
    """

    redundancy = 25  # redundancy in percent
    run_bitrot_recovery(env, redundancy)



def run_bitrot_recovery(env: EnvData, redundancy_percentage: int):
    """
    Verify the bitrot recovery process with `redundancy_percentage` bitrot.
    Expects to run in a virtual environment with dar-backup installed
    """
    config_settings = ConfigSettings(env.config_file)
    command_timeout = config_settings.command_timeout_secs
    runner = CommandRunner(
        logger=env.logger,
        command_logger=env.command_logger,
        default_timeout=command_timeout
    )
    file_sizes = {
        '100kB': 100 * 1024,
        '1MB': 1024 * 1024,
        '10MB': 10 * 1024 * 1024
    }
    generate_datafiles(env, file_sizes)
    modify_par2_redundancy(env, redundancy_percentage)
    print(f"env: {env}")
    command = ['dar-backup', '--full-backup' ,'-d', "example", '--config-file', env.config_file, '--log-level', 'debug', '--log-stdout']
    process: CommandResult  = runner.run(command)
    logging.info(f"stdout:\n{process.stdout}")
    logging.info(f"stderr:\n{process.stderr}")
    stdout,stderr = process.stdout, process.stderr
    if process.returncode != 0:
        raise RuntimeError("dar-backup failed to create a full backup")
    
    command = ['ls', '-hl', os.path.join(env.test_dir, 'backups')]
    stdout,stderr = process.stdout, process.stderr
    process: CommandResult  = runner.run(command)
    logging.info(f"stdout:\n{process.stdout}")
    logging.info(f"stderr:\n{process.stderr}")
    if process.returncode != 0:
        raise RuntimeError("dar-backup failed to create a full backup")

    simulate_bitrot(env, redundancy_percentage)
    check_bitrot_recovery(env, command_timeout)
