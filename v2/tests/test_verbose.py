# modified: 2021-07-25 to be a pytest test
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
        f'example_FULL_.1.dar': 'dummy',
        f'example.1.dar': 'dummy',
        f'example_DIFF_199_01-01.1.dar': 'dummy',
        f'example.txt': 'dummy',
        f'example_FULL_2024-07-25.1.dar': 'dummy',
        f'example_DIFF_2024-07-25.1.dar': 'dummy',
        f'example_INCR_2024-07-25.1.dar': 'dummy',

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
    stdout, stderr = process.communicate()
    env.logger.info("dar-backup --verbose output:\n" + stdout)

