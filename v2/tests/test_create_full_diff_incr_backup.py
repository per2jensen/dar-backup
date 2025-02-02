#!/usr/bin/env python3

import os
import logging
import re
import shutil
import sys

from pathlib import Path

from dar_backup.util import run_command
from tests.envdata import EnvData
from testdata_verification import create_test_files, verify_backup_contents, verify_restore_contents,test_files, run_backup_script



def list_catalog_db(env):    
    command = ['manager', '--list-catalog' ,'--config-file', env.config_file, '--log-level', 'debug', '--log-stdout']
    process = run_command(command)
    if process.returncode != 0:
        stdout, stderr = process.stdout, process.stderr
        print(f"stdout: {stdout}")  
        print(f"stderr: {stderr}")  
        raise Exception(f"Command failed: {command}")
    print(process.stdout)
    return process.stdout




def test_backup_functionality(setup_environment, env):
    try:
        create_test_files(env)

        # full backup
        run_backup_script("--full-backup", env)

        # Verify FULL backup contents
        verify_backup_contents(test_files, f"example_FULL_{env.datestamp}",env)
        env.logger.info("FULL backup verification succeeded")

        verify_restore_contents(test_files, f"example_FULL_{env.datestamp}", env )

        # cleanup restore directory
        shutil.rmtree(os.path.join(env.test_dir, 'restore'))
        Path(os.path.join(env.test_dir, 'restore')).mkdir(parents=True, exist_ok=True)

        # Differential backup
        # Modify one file for differential backup
        test_files_diff = {'file2.txt' : 'This is file 2.\nThis is an additional line.'}
        with open(os.path.join(env.test_dir, 'data', 'file2.txt'), 'w') as f:
            f.write(test_files_diff['file2.txt'])

        run_backup_script("--differential-backup", env)

        # Verify DIFF backup contents
        verify_backup_contents(test_files_diff, f"example_DIFF_{env.datestamp}", env)
        verify_restore_contents(test_files_diff, f"example_DIFF_{env.datestamp}", env )
        env.logger.info("Differential backup verification succeeded")
        

        # cleanup restore directory
        shutil.rmtree(os.path.join(env.test_dir, 'restore'))
        Path(os.path.join(env.test_dir, 'restore')).mkdir(parents=True, exist_ok=True)

        # Incremental backup
        # Modify one file for incremental backup
        test_files_inc = {'file3.txt' : 'This is file 3.\nThis is an additional line.',
                          'file2.txt' : 'This is file 2.\nThis is another line.'}

        for file, content in test_files_inc.items():
            with open(os.path.join(env.test_dir, 'data', file), 'w') as f:
                f.write(content)

        run_backup_script("--incremental-backup", env)
        
        verify_backup_contents(test_files_inc, f"example_INCR_{env.datestamp}", env)
        verify_restore_contents(test_files_inc, f"example_INCR_{env.datestamp}", env )

        env.logger.info("Incremental backup verification succeeded")

        list_catalog_db(env)


    except Exception as e:
        env.logger.exception("Backup functionality test failed")
        sys.exit(1)
    env.logger.info("test_backup_functionality() finished successfully")


def test_backup_functionality_short_options(setup_environment, env):
    try:
        create_test_files(env)

        # full backup
        run_backup_script("-F", env)

        # Verify FULL backup contents
        verify_backup_contents(test_files, f"example_FULL_{env.datestamp}", env)
        env.logger.info("FULL backup verification succeeded")

        verify_restore_contents(test_files, f"example_FULL_{env.datestamp}", env )

        # cleanup restore directory
        shutil.rmtree(os.path.join(env.test_dir, 'restore'))
        Path(os.path.join(env.test_dir, 'restore')).mkdir(parents=True, exist_ok=True)

        # Differential backup
        # Modify one file for differential backup
        test_files_diff = {'file2.txt' : 'This is file 2.\nThis is an additional line.'}
        with open(os.path.join(env.test_dir, 'data', 'file2.txt'), 'w') as f:
            f.write(test_files_diff['file2.txt'])


        run_backup_script("-D", env)

        # Verify DIFF backup contents
        verify_backup_contents(['data/file2.txt'], f"example_DIFF_{env.datestamp}", env)
        verify_restore_contents(test_files_diff, f"example_DIFF_{env.datestamp}", env )

        env.logger.info("Differential backup verification succeeded")

        # cleanup restore directory
        shutil.rmtree(os.path.join(env.test_dir, 'restore'))
        Path(os.path.join(env.test_dir, 'restore')).mkdir(parents=True, exist_ok=True)



        # Incremental backup
        # Modify one file for incremental backup
        test_files_inc = {'file3.txt' : 'This is file 3.\nThis is an additional line.',
                          'file2.txt' : 'This is file 2.\nThis is another line.'}

        for file, content in test_files_inc.items():
            with open(os.path.join(env.test_dir, 'data', file), 'w') as f:
                f.write(content)

        run_backup_script("-I", env)
        # Verify INCR backup contents
        
        verify_backup_contents(test_files_inc, f"example_INCR_{env.datestamp}", env)
        verify_restore_contents(test_files_inc, f"example_INCR_{env.datestamp}", env )
        env.logger.info("Incremental backup verification succeeded")

        list_catalog_db(env)

    except Exception as e:
        env.logger.exception("Backup functionality test failed")
        sys.exit(1)
    env.logger.info("test_backup_functionality() finished successfully")


