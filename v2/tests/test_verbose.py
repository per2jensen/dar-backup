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
    stdout, stderr = process.communicate()
    env.logger.info("dar-backup --verbose output:\n" + stdout)

    expected_patterns = [
        'Current directory:',
        'Backup.d dir:',
        'Backup dir:',
        'Test restore dir:',
        'Logfile location:',
        '--do-not-compare:'
        ]

    for pattern in expected_patterns:
        assert re.search(pattern, stdout), f"Pattern {pattern} not found in output"