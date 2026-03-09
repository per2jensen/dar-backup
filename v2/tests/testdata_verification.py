"""
This module produces test data to be used in the tests.

Verification functions used to verify expected files exist in the backup and when restore has been performed.
"""

import filecmp
import os
import re
import sys
from typing import Dict, List


# Add src directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from envdata import EnvData
from dar_backup.command_runner import CommandRunner, CommandResult


def run_backup_script(type: str, env: EnvData) -> CommandResult:
    command = ['dar-backup', type, '-d', "example", '--verbose', '--log-level', 'debug', '--log-stdout', '--config-file', env.config_file]
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
    result: CommandResult = runner.run(command, timeout=300)
    stdout, stderr = result.stdout, result.stderr
    if result.returncode != 0:
        env.logger.error(f"Error running backup command: {command}")
        env.logger.error(f"stderr: {stderr}")
        raise Exception(f"Error running backup command: {command}")
    return result


def verify_backup_contents(expected_files: Dict[str, str], archive: str, env: EnvData):
    """
    Loop through the expected files and verify they exist in the backup archive.

    args:
        expected_files (Dict[str, str]): Dict of <filename>:<file content> of expected files to verify.
        archive (str): The basenase of archive to verify.
        env (EnvData): The environment data object.

    raises:
        RuntimeError: If expected file is not found in the backup archive.

    """
    env.logger.info(f"Verifying archive '{archive}' contains expected files")
    command = ['dar-backup', '--list-contents', archive, '--config-file', env.config_file, '--verbose', '--log-stdout', '--log-level', 'debug']
    env.logger.info(command)
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
    process = runner.run(command)
    stdout, stderr = process.stdout, process.stderr
    env.logger.info(stdout)
    if process.returncode != 0:
        env.logger.error(f"command failed: {stderr}")
        raise RuntimeError(f"Error running command: {command}, stderr: {stderr}")

    for expected_file in expected_files:
        env.logger.info(f"Checking for '{expected_file}' in backup '{archive}'")
        pattern = re.compile(rf'\[Saved\].*{re.escape(expected_file)}')
        if not pattern.search(stdout):
            env.logger.error(f"Expected file '{expected_file}' not found with [Saved] marker in backup")
            raise RuntimeError(f"Expected file '{expected_file}' not found with [Saved] marker in backup")

    env.logger.info(f"Archive '{archive}' contains expected files")


def verify_restore_contents(expected_files: Dict[str, str], archive: str, env: EnvData, restore_dir: str = None):
    """
    Loop through the list of files to verify they are restored and contains expected content.

    args:
        expected_files (Dict[str, str]): Dict of <filename>:<file content> of expected files to verify.
        archive (str): The basenase of archive to verify.
        env (EnvData): The environment data object.
        restore_dir (str): Optional directory to restore to. Default is env.restore_dir.

    raises:
        RuntimeError: If expected content is not found in expected restored files.

    """
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
    env.logger.info(f"Restore and verify archive '{archive}', check for expected files and content")
    command = ['dar-backup', '--restore', archive, '--config-file', env.config_file, '--verbose', '--log-stdout', '--log-level', 'debug']
    if restore_dir:
        command.extend(['--restore-dir', restore_dir])
    else:
        restore_dir = env.restore_dir
    env.logger.info(command)
    process = runner.run(command)
    stdout, stderr = process.stdout, process.stderr
    env.logger.info(stdout)
    if process.returncode != 0:
        env.logger.error(f"command failed: {stderr}")
        raise RuntimeError(f"Error running command: {command}, stderr: {stderr}")

    for expected_file in expected_files:
        expected_dir_path = os.path.join(restore_dir, env.data_dir[1:])
        expected_file_path = os.path.join(expected_dir_path, expected_file)
        with open(expected_file_path, 'r') as f:
            content = f.read()
            if content == expected_files[expected_file]:
                env.logger.info(f"OK: expected content found for file '{expected_file}' in dir: '{expected_dir_path}'")
            else:
                env.logger.error(f"Error: expected content in file '{expected_file}' not found")
                raise RuntimeError(f"Expected content in file '{expected_file}' not found")

    env.logger.info(f"Restored files from archive '{archive}' contains expected content")


def verify_restored_matches_source(filenames: List[str], env: EnvData, restore_dir: str = None) -> None:
    """
    Byte-for-byte compare each file in data_dir with its counterpart under restore_dir.

    dar preserves the full absolute path when restoring, so a file that lived at
    /a/b/data/foo.txt is restored to <restore_dir>/a/b/data/foo.txt.  This
    function reconstructs that path using env.data_dir and compares every byte.

    args:
        filenames: list of filenames (relative to env.data_dir) to compare.
        env:       EnvData instance providing data_dir and restore_dir.
        restore_dir: optional override; defaults to env.restore_dir.

    raises:
        RuntimeError: if a file is missing from the restore tree or its content
                      differs from the source.
    """
    if restore_dir is None:
        restore_dir = env.restore_dir

    for filename in filenames:
        source_path = os.path.join(env.data_dir, filename)
        restored_path = os.path.join(restore_dir, env.data_dir.lstrip("/"), filename)

        if not os.path.exists(restored_path):
            env.logger.error(f"Restored file missing: '{restored_path}'")
            raise RuntimeError(f"Restored file missing: '{restored_path}'")

        if not filecmp.cmp(source_path, restored_path, shallow=False):
            env.logger.error(
                f"Content mismatch after restore: source='{source_path}' restored='{restored_path}'"
            )
            raise RuntimeError(
                f"Content mismatch after restore: '{filename}' differs from source"
            )

        env.logger.info(f"OK byte-for-byte match: '{filename}'")
