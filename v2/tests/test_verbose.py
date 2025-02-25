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

def test_verbose(setup_environment, env):
    test_files = create_test_files(env)   

    command = ['dar-backup', '--list', '--config-file', env.config_file, '--verbose']
    process = run_command(command)
    if process.returncode != 0:
        raise Exception(f"Command failed {command}")

    expected_patterns = [
        'Script directory:',
        'Backup.d dir:',
        'Backup dir:',
        'Restore dir:',
        'Logfile location:',
        '--do-not-compare:'
        ]

    for pattern in expected_patterns:
        assert re.search(pattern, process.stdout), f"Pattern `{pattern}` not found in output"


def test_verbose_cleanup(setup_environment, env):
    test_files = create_test_files(env)   

    command = ['cleanup', '--list', '--config-file', env.config_file, '--verbose']
    process = run_command(command)
    if process.returncode != 0:
        raise Exception(f"Command failed {command}")
    stdout, stderr = process.stdout, process.stderr

    expected_patterns = [
        'Script directory:',
        'Config file:',
        'Backup dir:',
        'Logfile location:',
        '--cleanup-specific-archive',
        '--alternate-archive-dir:'
        ]

    for pattern in expected_patterns:
        assert re.search(pattern, stdout), f"Pattern {pattern} not found in output"
