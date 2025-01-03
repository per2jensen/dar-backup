# modified: 2021-07-25 to be a pytest test
import importlib
import re
import sys
import os

from tests.envdata import EnvData


from dar_backup.util import run_command

def create_test_files(env: EnvData) -> dict:
    env.logger.info("Creating test dummy archive files...")
    test_files = {
        f'dummy_FULL_.1.dar': 'dummy',
    }
    for filename, content in test_files.items():
        with open(os.path.join(env.test_dir, 'backups', filename), 'w') as f:
            f.write(content)

    return test_files

def test_dar_backup_definition_with_underscore(setup_environment, env):
    command = ['dar-backup', '--full-backup', '--config-file', env.config_file, '-d', 'example_2']
    process = run_command(command)
    if process.returncode == 0:
        raise Exception(f'dar-backup must fail on a backup definition with an underscore in the name')

def test_dar_backup_nonexistent_definition_(setup_environment, env):
    command = ['dar-backup', '--full-backup', '--config-file', env.config_file, '-d', 'nonexistent_definition']
    process = run_command(command)
    if process.returncode == 0:
        raise Exception(f'dar-backup must fail if backup definition is not found')
                        