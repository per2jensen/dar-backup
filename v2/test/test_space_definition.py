
import logging
import sys
import os

# Ensure the test directory is in the Python path
sys.path.append(os.path.abspath(os.path.dirname(__file__)))
from v2.test.envdata import EnvData
from datetime import datetime
from dar_backup.util import run_command


def create_random_data_file(env: EnvData, name: str, size: int) -> None:
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


def generate_datafiles(env: EnvData) -> None:
    """
    Generate the data files for testing.

    This method creates files of different sizes using the create_random_data_file method.
    """
    try:
        # Create files
        for name, size in env.file_sizes.items():
            create_random_data_file(env, name, size)
    except Exception as e:
        env.logger.exception("data file generation failed")
        raise


def create_backup_definitions(env: EnvData) -> None:
    """
    Generate the backup definitions for testing.

    This method creates the backup definition files using the backup_definitions dictionary.
    """
    logging.info("Generating backup definition")
    backup_definitions = {
        "example 2" : f"""
        -Q 
        -B {env.dar_rc}
        -R /
        -s 10G
        -z6
        -am
        -g {os.path.join(env.test_dir, 'data')}
        """.replace("-g /tmp/", "-g tmp/")  # because dar does not allow first "/"
    }

    for filename, content in backup_definitions.items():
        with open(os.path.join(env.test_dir, 'backup.d', filename), 'w') as f:
            f.write(content)

    
def test_backup_definition_with_space(setup_environment, env):
    """
    Verify that the backups are correct when a backup
    definition name contains space(s)

    Expects to be run in a virtal environment with dar-backup installed.
    """
    env.file_sizes = {
        '100kB': 100 * 1024,
        '1MB': 1024 * 1024,
        '10MB': 10 * 1024 * 1024
    }

    generate_datafiles(env)

    create_backup_definitions(env)

    command = ['dar-backup', '--full-backup' ,'-d', "example 2", '--config-file', env.config_file]
    process = run_command(command)

    
