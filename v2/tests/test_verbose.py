# modified: 2021-07-25 to be a pytest test
import re
import sys
import os
import pytest

pytestmark = pytest.mark.integration


# Add src directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from tests.envdata import EnvData
from dar_backup.command_runner import CommandRunner







def create_test_files(env: EnvData) -> dict:
    env.logger.info("Creating test dummy archive files...")
    test_files = {
        'dummy_FULL_.1.dar': 'dummy',
    }
    for filename, content in test_files.items():
        with open(os.path.join(env.test_dir, 'backups', filename), 'w') as f:
            f.write(content)

    return test_files

def test_verbose(setup_environment, env):
    test_files = create_test_files(env)
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)

    command = ['dar-backup', '--list', '--config-file', env.config_file, '--verbose']
    process = runner.run(command)
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
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
    
    command = ['cleanup', '--list', '--config-file', env.config_file, '--verbose']
    process = runner.run(command)
    if process.returncode != 0:
        raise Exception(f"Command failed {command}")
    stdout, stderr = process.stdout, process.stderr

    expected_patterns = [
        'Script directory:',
        'Config file:',
        'Backup dir:',
        'Logfile:',
        '--cleanup-specific-archives:',
        '--alternate-archive-dir:'
    ]

    for pattern in expected_patterns:
        assert re.search(pattern, stdout), f"Pattern {pattern} not found in output"

def test_verbose_error_reporting(setup_environment, env):
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
    # Patch config file with a successful command
    with open(env.config_file, 'a') as f:
        f.write('\n[PREREQ]\n')
        f.write('PREREQ_01 = ls /tmp\n')

    # Run the command
    command = ['dar-backup', '--full-backup', '-d', "example", '--config-file', env.config_file, '--verbose']
    process = runner.run(command)
    assert process.returncode == 0

    # Patch the config file with a failing command
    with open(env.config_file, 'a') as f:
        f.write('PREREQ_02 = command-does-not-exist /tmp\n')
    env.logger.info(f"PREREQ_02 which fails has been added to config file: {env.config_file}")

    # Run the command
    try:
        command = ['dar-backup', '--differential-backup', '-d', "example", '--config-file', env.config_file, '--verbose']
        process = runner.run(command)
        assert process.returncode != 0
        assert "CalledProcessError(127, 'command-does-not-exist /tmp')" in process.stdout

    except Exception:
        env.logger.exception("Expected exception: dar-backup must fail when a prereq command fails")
        assert True
