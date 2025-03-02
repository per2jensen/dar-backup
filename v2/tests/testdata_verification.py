"""
This module produces test data to be used in the tests.

Verification functions used to verify expected files exist in the backup and when restore has been performed.
"""


import os
import re
from envdata import EnvData
from dar_backup.util import run_command
from dar_backup.util import CommandResult
from typing import Dict
from tests.conftest import test_files


def run_backup_script(type: str, env: EnvData) -> CommandResult:
    command = ['dar-backup', type, '-d', "example", '--verbose', '--log-level', 'debug','--log-stdout' ,'--config-file', env.config_file]
    result: CommandResult = run_command(command)
    stdout,stderr = result.stdout, result.stderr
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
    process = run_command(command)
    stdout,stderr = process.stdout, process.stderr
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



def verify_restore_contents(expected_files: Dict[str, str], archive: str, env: EnvData, restore_dir: str=None):
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
    env.logger.info(f"Restore and verify archive '{archive}', check for expected files and content")
    command = ['dar-backup', '--restore', archive, '--config-file', env.config_file, '--verbose', '--log-stdout', '--log-level', 'debug'] 
    if restore_dir:
        command.extend(['--restore-dir', restore_dir])
    else:
        restore_dir = env.restore_dir
    env.logger.info(command) 
    process = run_command(command)
    stdout,stderr = process.stdout, process.stderr
    env.logger.info(stdout)
    if process.returncode != 0:
        env.logger.error(f"command failed: {stderr}")
        raise  RuntimeError(f"Error running command: {command}, stderr: {stderr}")

    for expected_file in expected_files:
        # expected_file is located in the `data` directory of a unit test
        # after restore a file is located in the join of `restore dir` + `data dir`
        expected_dir_path = os.path.join(restore_dir, env.data_dir[1:])
        expected_file_path = os.path.join(restore_dir, env.data_dir[1:], expected_file)
        with open(expected_file_path, 'r') as f:
            content = f.read()
            if content == expected_files[expected_file]:
                env.logger.info(f"OK: expected content found for file '{expected_file}' in dir: '{expected_dir_path}'")
            else:
                env.logger.error(f"Error: expected content in file '{expected_file}' not found")
                raise RuntimeError(f"Expected content in file '{expected_file}' not found")

    env.logger.info(f"Restored files from archive '{archive}' contains expected content")        


