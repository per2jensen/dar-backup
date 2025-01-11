import os

from dar_backup.util import run_command
from dar_backup.config_settings import ConfigSettings
from datetime import datetime
from tests.envdata import EnvData

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
    except Exception as e:
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
    dummy_dar_files = {f'{date}-1' : 1024,
                        f'{date}-2': 2048,
                        f'{date}-3': 4096,}
    generate_datafiles(env, dummy_dar_files)
    
    modify_slice_size(env, 'example', '1k')    

    command = ['dar-backup', '-F', '-d', "example", '--verbose', '--log-stdout', '--config-file', env.config_file]
    process = run_command(command)
    stdout,stderr = process.stdout, process.stderr
    env.logger.info(stdout)
    if process.returncode != 0:
        env.logger.error(f"Error running backup command: {command}")
        env.logger.error(f"stderr: {stderr}")
        raise Exception(f"Error running backup command: {command}")


    assert True, "some tests to verify the order of the slices are processed in the correct order should be implemented here" 

    