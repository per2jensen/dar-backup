#!/usr/bin/env python3

import os
import logging
import re
import shutil
import sys

from pathlib import Path

from dar_backup.util import run_command
from tests.envdata import EnvData

test_files = {
        'file1.txt': 'This is file 1.',
        'file2.txt': 'This is file 2.',
        'file3.txt': 'This is file 3.',
        'file with spaces.txt': 'This is file with spaces.',
        'file_with_danish_chars_æøå.txt': 'This is file with danish chars æøå.',
        'file_with_DANISH_CHARS_ÆØÅ.txt': 'This is file with DANISH CHARS ÆØÅ.',
        'file_with_colon:.txt': 'This is file with colon :.',
        'file_with_hash#.txt': 'This is file with hash #.',
        'file_with_currency¤.txt': 'This is file with currency ¤.'
 }


def create_test_files(env):
    env.logger.info("Creating test files...")
    for filename, content in test_files.items():
        env.logger.info(f"Creating {filename} with content: {content} in {env.test_dir}")
        with open(os.path.join(env.test_dir, 'data', filename), 'w') as f:
            f.write(content)



def test_backup_functionality(setup_environment, env):
    check_saved=True
    try:
        create_test_files(env)

        # full backup
        run_backup_script("--full-backup", env)

        # Verify FULL backup contents
        check_saved=True
        verify_backup_contents(test_files, f"example_FULL_{env.datestamp}", check_saved, env)
        env.logger.info("FULL backup verification succeeded")

        # cleanup restore directory
        shutil.rmtree(os.path.join(env.test_dir, 'restore'))
        Path(os.path.join(env.test_dir, 'restore')).mkdir(parents=True, exist_ok=True)

        # Differential backup
        # Modify one file for differential backup
        with open(os.path.join(env.test_dir, 'data', 'file2.txt'), 'a') as f:
            f.write('This is an additional line.')

        run_backup_script("--differential-backup", env)

        # Verify DIFF backup contents
        verify_backup_contents(['data/file2.txt'], f"example_DIFF_{env.datestamp}", check_saved, env)
        env.logger.info("Differential backup verification succeeded")

        # cleanup restore directory
        shutil.rmtree(os.path.join(env.test_dir, 'restore'))
        Path(os.path.join(env.test_dir, 'restore')).mkdir(parents=True, exist_ok=True)

        # Incremental backup
        # Modify one file for incremental backup
        with open(os.path.join(env.test_dir, 'data', 'file3.txt'), 'a') as f:
            f.write('This is an additional line.')

        run_backup_script("--incremental-backup", env)
        # Verify INCR backup contents
        
        verify_backup_contents(['data/file3.txt'], f"example_INCR_{env.datestamp}", check_saved, env)
        env.logger.info("Incremental backup verification succeeded")
    except Exception as e:
        env.logger.exception("Backup functionality test failed")
        sys.exit(1)
    env.logger.info("test_backup_functionality() finished successfully")


def test_backup_functionality_short_options(setup_environment, env):
    check_saved=True
    try:
        create_test_files(env)

        # full backup
        run_backup_script("-F", env)

        # Verify FULL backup contents
        check_saved=True
        verify_backup_contents(test_files, f"example_FULL_{env.datestamp}", check_saved, env)
        env.logger.info("FULL backup verification succeeded")

        # cleanup restore directory
        shutil.rmtree(os.path.join(env.test_dir, 'restore'))
        Path(os.path.join(env.test_dir, 'restore')).mkdir(parents=True, exist_ok=True)

        # Differential backup
        # Modify one file for differential backup
        with open(os.path.join(env.test_dir, 'data', 'file2.txt'), 'a') as f:
            f.write('This is an additional line.')

        run_backup_script("-D", env)

        # Verify DIFF backup contents
        verify_backup_contents(['data/file2.txt'], f"example_DIFF_{env.datestamp}", check_saved, env)
        env.logger.info("Differential backup verification succeeded")

        # cleanup restore directory
        shutil.rmtree(os.path.join(env.test_dir, 'restore'))
        Path(os.path.join(env.test_dir, 'restore')).mkdir(parents=True, exist_ok=True)

        # Incremental backup
        # Modify one file for incremental backup
        with open(os.path.join(env.test_dir, 'data', 'file3.txt'), 'a') as f:
            f.write('This is an additional line.')

        run_backup_script("-I", env)
        # Verify INCR backup contents
        
        env.logger.debug("Incremental backup verification staring......")
        verify_backup_contents(['data/file3.txt'], f"example_INCR_{env.datestamp}", check_saved, env)
        env.logger.info("Incremental backup verification succeeded")
    except Exception as e:
        env.logger.exception("Backup functionality test failed")
        sys.exit(1)
    env.logger.info("test_backup_functionality() finished successfully")



def run_backup_script(type: str, env: EnvData):
    """
    Expects to run in a virtual environment with dar-backup installed
    """
    command = ['dar-backup', type, '-d', "example", '--verbose', '--log-level', 'debug', '--config-file', env.config_file]
    process = run_command(command)
    stdout,stderr = process.stdout, process.stderr
    env.logger.info(stdout)
    if process.returncode != 0:
        env.logger.error(f"Error running backup command: {command}")
        env.logger.error(f"stderr: {stderr}")
        raise Exception(f"Error running backup command: {command}")
    return True


def verify_backup_contents(expected_files, archive, check_saved, env: EnvData):
    """
    Expects to run in a virtual environment with dar-backup installed
    """
    env.logger.info(f"Verifying archive {archive} contains expected files")
    command = ['dar-backup', '--list-contents', archive, '--config-file', env.config_file]
    env.logger.info(command) 
    process = run_command(command)
    stdout,stderr = process.stdout, process.stderr
    env.logger.info(stdout)
    if process.returncode != 0:
        env.logger.error(f"command failed: {stderr}")
        raise Exception(f"Error running command: {command}, stderr: {stderr}")


    for expected_file in expected_files:
        env.logger.info(f"Checking for {expected_file} in backup {archive}")    
        if check_saved:
            pattern = re.compile(rf'\[Saved\].*{re.escape(expected_file)}')
            if not pattern.search(stdout):
                env.logger.error(f"Expected file {expected_file} not found with [Saved] marker in backup")
                raise Exception(f"Expected file {expected_file} not found with [Saved] marker in backup")

    env.logger.info(f"Archive {archive} contains expected files")        
