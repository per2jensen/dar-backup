""
import pytest

pytestmark = [pytest.mark.integration, pytest.mark.smoke]

"""
modified: 2021-07-25 to be a pytest test

see more restore tests/verifications in v2/tests/test_create_full_diff_incr_backup.py
"""

import re
import tempfile

from tests.conftest import test_files
from dar_backup.command_runner import CommandRunner
from dar_backup.command_runner import CommandResult
from testdata_verification import run_backup_script
from testdata_verification import verify_restored_matches_source







def test_restoredir_requires_value(setup_environment, env):
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
    command = ['dar-backup', '--restore', 'dummy_FULL_1970-01-01', '--restore-dir', '--log-stdout', '--log-level', 'debug', '--config-file', env.config_file]
    process = runner.run(command)
    env.logger.info(f"process.returncode={process.returncode}")
    if process.returncode == 0:
        raise Exception('dar-backup must fail because value to --restore-dir is not given')
    else:
        stdout, stderr = process.stdout, process.stderr
        if not re.search('usage: dar-backup', stderr):
            raise Exception(f"Expected error message not found in stderr: {stderr}")
        env.logger.info(f"process.returncode={process.returncode} which is expected")

def test_restore_requires_value(setup_environment, env):
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
    command = ['dar-backup', '--restore', '--restore-dir', env.test_dir , '--log-stdout', '--log-level', 'debug', '--config-file', env.config_file]
    process = runner.run(command)
    env.logger.info(f"process.returncode={process.returncode}")
    if process.returncode == 0:
        raise Exception('dar-backup must fail because a value to --restore is not given')
    else:
        stdout, stderr = process.stdout, process.stderr
        if not re.search('usage: dar-backup', stderr):
            raise Exception(f"Expected error message not found in stderr: {stderr}")
        env.logger.info(f"process.returncode={process.returncode} which is expected")

def test_restore_with_restoredir(setup_environment, env):
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
    with tempfile.TemporaryDirectory(dir="/tmp") as unique_dir:
        run_backup_script("--full-backup", env)
        env.logger.info(f"unique_dir={unique_dir}")
        command = ['dar-backup', '--restore', f'example_FULL_{env.datestamp}', '--restore-dir', unique_dir , '--log-stdout', '--log-level', 'debug', '--config-file', env.config_file]
        process = runner.run(command)
        env.logger.info(f"process.returncode={process.returncode}")
        if process.returncode != 0:
            stdout, stderr = process.stdout, process.stderr
            env.logger.error(f"command failed: \nstdout:{stdout}\nstderr:{stderr}")
            raise RuntimeError(f"Expected error message not found in stderr: {stderr}")
        verify_restored_matches_source(list(test_files), env, unique_dir)

def test_restore_validatation(setup_environment, env):
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
    try:
        result: CommandResult = run_backup_script("--full-backup", env)
        if "Restoring file: '" not in result.stdout or "' for file comparing" not in result.stdout:
            assert False, f"Expected message not found in stdout: {result.stdout}"
    finally:
        pass
