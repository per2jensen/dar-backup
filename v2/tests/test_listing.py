# modified: 2021-07-25 to be a pytest test
import re
import os
import sys
import pytest

pytestmark = pytest.mark.integration

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

# Ensure the test directory is in the Python path
#sys.path.append(os.path.abspath(os.path.dirname(__file__)))

from tests.envdata import EnvData
from dar_backup.command_runner import CommandRunner







def create_test_files(env: EnvData) -> dict:
    env.logger.info("Creating test dummy archive files...")
    test_files = {
        'example_FULL_.1.dar': 'dummy',
        'example.1.dar': 'dummy',
        'example_DIFF_199_01-01.1.dar': 'dummy',
        'example.txt': 'dummy',
        'example_FULL_2024-07-25.1.dar': 'dummy',
        'example_DIFF_2024-07-25.1.dar': 'dummy',
        'example_INCR_2024-07-25.1.dar': 'dummy',

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


def _create_unicode_files(env: EnvData) -> list[str]:
    filenames = [
        "dansk_æøå.txt",
        "DANSK_ÆØÅ.txt",
        "spansk_ñ.txt",
        "japanese_日本語.txt",
        "space name_æøå.txt",
        "dir with spaces/ø/fil_æøå.txt",
        "deep/日本語/emoji-🙂.txt",
    ]
    for name in filenames:
        path = os.path.join(env.data_dir, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            f.write("unicode test")
    return filenames


def test_list_contents_unicode_filenames(setup_environment, env):
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
    filenames = _create_unicode_files(env)

    command = [
        'dar-backup',
        '--full-backup',
        '-d', 'example',
        '--config-file', env.config_file,
        '--log-level', 'debug',
    ]
    result = runner.run(command)
    assert result.returncode == 0

    archive_base = f"example_FULL_{env.datestamp}"
    list_result = runner.run([
        'dar-backup',
        '--list-contents',
        archive_base,
        '--config-file', env.config_file
    ])
    assert list_result.returncode == 0
    stdout = list_result.stdout
    for name in filenames:
        assert name in stdout
