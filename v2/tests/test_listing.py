# modified: 2021-07-25 to be a pytest test
import re
import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

# Ensure the test directory is in the Python path
#sys.path.append(os.path.abspath(os.path.dirname(__file__)))

from tests.envdata import EnvData
from dar_backup.command_runner import CommandRunner

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

def test_list_dar_archives(setup_environment, env):
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
    test_files = create_test_files(env)   

    env.logger.info(f"--> Start running test: {sys._getframe().f_code.co_name}")
    command = ['dar-backup', '--list', '--config-file', env.config_file]
    process = runner.run(command)
    stdout, stderr = process.stdout, process.stderr
    if process.returncode != 0:
        env.logger.error(f"Command failed: {command}")
        env.logger.error(f"stderr: {stderr}")
        raise Exception(f"Command failed: {command}")   
    stdout, stderr = process.stdout, process.stderr
    env.logger.debug("dar-backup --list output:\n" + stdout)

    # Check for all expected files using regex
    expected_patterns = [
        r'example_FULL_\d{4}-\d{2}-\d{2}',
        r'example_DIFF_\d{4}-\d{2}-\d{2}',
        r'example_INCR_\d{4}-\d{2}-\d{2}']

    for pattern in expected_patterns:
        assert re.search(pattern, stdout), f"Pattern {pattern} not found in output"

    # Ensure specific files are not listed
    unexpected_patterns = [
        r'example(?!_FULL_\d{4}-\d{2}-\d{2})(?!_DIFF_\d{4}-\d{2}-\d{2})(?!_INCR_\d{4}-\d{2}-\d{2})',
        r'example_DIFF_199_01-01',
        r'example.txt']

    for pattern in unexpected_patterns:
        assert not re.search(pattern, stdout), f"Unexpected pattern {pattern} found in output"


def test_list_dar_archives_short_options(setup_environment, env):
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
    test_files = create_test_files(env)   

    env.logger.info(f"--> Start running test: {sys._getframe().f_code.co_name}")
    command = ['dar-backup', '-l', '-c', env.config_file]
    process = runner.run(command)
    stdout, stderr = process.stdout, process.stderr
    if process.returncode != 0:
        env.logger.error(f"Command failed: {command}")
        env.logger.error(f"stderr: {stderr}")
        raise Exception(f"Command failed: {command}")   
    stdout, stderr = process.stdout, process.stderr

    env.logger.debug("dar-backup -l output:\n" + stdout)

    # Check for all expected files using regex
    expected_patterns = [
        r'example_FULL_\d{4}-\d{2}-\d{2}',
        r'example_DIFF_\d{4}-\d{2}-\d{2}',
        r'example_INCR_\d{4}-\d{2}-\d{2}']

    for pattern in expected_patterns:
        assert re.search(pattern, stdout), f"Pattern {pattern} not found in output"

    # Ensure specific files are not listed
    unexpected_patterns = [
        r'example(?!_FULL_\d{4}-\d{2}-\d{2})(?!_DIFF_\d{4}-\d{2}-\d{2})(?!_INCR_\d{4}-\d{2}-\d{2})',
        r'example_DIFF_199_01-01',
        r'example.txt']

    for pattern in unexpected_patterns:
        assert not re.search(pattern, stdout), f"Unexpected pattern {pattern} found in output"


