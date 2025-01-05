# modified: 2021-07-25 to be a pytest test
import importlib
import re
import sys
import os

# Ensure the test directory is in the Python path
#sys.path.append(os.path.abspath(os.path.dirname(__file__)))

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

def test_verbose(setup_environment, env):
    test_files = create_test_files(env)   

    env.logger.info(f"--> Start running test: {sys._getframe().f_code.co_name}")
    command = ['dar-backup', '--list', '--config-file', env.config_file, '--verbose']
    process = run_command(command)
    stdout, stderr = process.stdout, process.stderr
    if process.returncode != 0:
        env.logger.error(f"Command failed: {command}")
        env.logger.error(f"stderr: {stderr}")
        raise Exception(f"Command failed: {command}")

    env.logger.info("dar-backup --verbose output:\n" + stdout)


    # Find directory of dar_backup.py
    dar_backup = importlib.import_module('dar_backup.dar_backup')
    dar_backup_path = dar_backup.__file__
    dar_backup_dir = os.path.dirname(dar_backup_path)

    darrc_path = os.path.join(dar_backup_dir, '.darrc')

    expected_patterns = [
        f'{darrc_path}'
        ]

    for pattern in expected_patterns:
        assert re.search(pattern, stdout), f".darrc not found alongside dar_backup.py"