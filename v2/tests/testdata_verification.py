"""
This module produces test data to be used in the tests.

Verification functions used to verify expected files exist in the backup and when restore has been performed.
"""


import os
import re
from envdata import EnvData
from dar_backup.util import run_command
from typing import Dict

test_files = {
        'file1.txt': 'This is file 1.',
        'file2.txt': 'This is file 2.',
        'file3.txt': 'This is file 3.',
        'file with spaces.txt': 'This is file with spaces.',
        'file_with_danish_chars_æøå.txt': 'This is file with danish chars æøå.',
        'file_with_DANISH_CHARS_ÆØÅ.txt': 'This is file with DANISH CHARS ÆØÅ.',
        'file_with_colon:.txt': 'This is file with colon :.',
        'file_with_hash#.txt': 'This is file with hash #.',
        'file_with_currency$.txt': 'This is file with currency $ ¤.',
        'file with spaces.txt': 'This is file with spaces.',
 }


def create_test_files(env):
    env.logger.info("Creating test files...")
    for filename, content in test_files.items():
        env.logger.info(f"Creating {filename} with content: {content} in {env.test_dir}")
        with open(os.path.join(env.test_dir, 'data', filename), 'w') as f:
            f.write(content)




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



def verify_restore_contents(expected_files: Dict[str, str], archive: str, env: EnvData):
    """
    Loop through the list of files to verify they are restored and contains expected content.

    args:
        expected_files (Dict[str, str]): Dict of <filename>:<file content> of expected files to verify.
        archive (str): The basenase of archive to verify.
        env (EnvData): The environment data object.

    raises:
        RuntimeError: If expected content is not found in expected restored files.

    """
    env.logger.info(f"Restore and verify archive '{archive}', check for expected files and content")
    command = ['dar-backup', '--restore', archive, '--config-file', env.config_file, '--verbose', '--log-stdout', '--log-level', 'debug'] 
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
        env.logger.info(f"Checking for '{expected_file}' in backup '{archive}'")
        expected_file_path = os.path.join(env.restore_dir, env.data_dir, expected_file)
        env.logger.info(f"Checking for '{expected_file_path}' below restore dir")
        with open(expected_file_path, 'r') as f:
            content = f.read()
            if content == expected_files[expected_file]:
                env.logger.info(f"Expected content in file '{expected_file}' found")
            else:
                env.logger.error(f"Expected content in file '{expected_file}' not found")
                raise RuntimeError(f"Expected content in file '{expected_file}' not found")

    env.logger.info(f"Restored files from archive '{archive}' contains expected content")        


