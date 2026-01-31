import os
import re
import sys
import pytest

pytestmark = pytest.mark.integration

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from datetime import datetime
from tests.envdata import EnvData
from dar_backup.command_runner import CommandRunner







"""
This module tests the par2 file creation and repair functionality of dar-backup.
Also see the test_bitrot.py module for more tests on the par2 functionality.
"""


def create_random_data_file(env: EnvData, name, size):
    """
    Create a file with random data of a specific size.

    Args:
        name (str): The name of the file.
        size (int): The size of the file in bytes.
    """
    filename = f"random-{name}"
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


def modify_slice_size(env: EnvData, definition: str, slice_size: str) -> None:
    """
    Modify the redundancy level of the par2 files by patching the dar-backup.conf file

    Args:
        env (EnvData): The environment data object.
        definition (str): The backup definition file to modify. Fx `example`
        slice_size (str): fx `1k`
    Raises:
        RuntimeError: If the command fails.
    """
    print("Definition", definition)
    print("test_dir", env.test_dir) 
    definition_path = os.path.join(env.test_dir, 'backup.d', definition)
    print("Definition path ", definition_path)

    with open(definition_path, 'r') as f:
        lines = f.readlines()
    with open(definition_path, 'w') as f:
        for line in lines:
            if line.startswith('-s '):
                f.write(f'-s {slice_size}\n')
            else:
                f.write(line)


def test_ordered_by_slicenumber(setup_environment, env):
    date = datetime.now().strftime('%Y-%m-%d')
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)


    dummy_dar_files = {f'{date}-1' : 1024,
                        f'{date}-2': 2048,
                        f'{date}-3': 4096,}
    generate_datafiles(env, dummy_dar_files)
    
    modify_slice_size(env, 'example', '1k')    

    command = ['dar-backup', '-F', '-d', "example", '--verbose', '--log-stdout', '--config-file', env.config_file, '--log-level', 'debug', '--log-stdout']
    process = runner.run(command)
    stdout,stderr = process.stdout, process.stderr
    env.logger.info(stdout)
    if process.returncode != 0:
        env.logger.error(f"Error running backup command: {command}")
        env.logger.error(f"stderr: {stderr}")
        raise Exception(f"Error running backup command: {command}")

    # Extract slice numbers from the par2 create command logged to stdout
    par2_command_lines = [
        line for line in stdout.splitlines()
        if "Executing command:" in line and "par2 create" in line
    ]
    assert par2_command_lines, f"No par2 create command found in stdout: {stdout}"
    slice_pattern = re.compile(r'\.(\d+)\.dar(?:\s|$)')
    slice_numbers = [int(num) for num in slice_pattern.findall(par2_command_lines[0])]
    assert slice_numbers, f"No slice numbers found in par2 command: {par2_command_lines[0]}"
    assert len(slice_numbers) > 0, "There must at least be 1 dar slice, got 0"

    # Verify that slice numbers are in increasing order
    assert slice_numbers == sorted(slice_numbers), f"Slices are not processed in order: {slice_numbers}"

    env.logger.info(f"OK: slices processed in order: {slice_numbers}")

    assert True, "OK: Slices are processed in the correct order" 

    
