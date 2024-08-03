#!/usr/bin/env python3

import unittest
from base_test_case import BaseTestCase

import datetime
import os
import subprocess
import logging
import re
import shutil
import sys
import glob  # Added import statement

from pathlib import Path

from dar_backup.util import run_command

class Test_Create_Full_Diff_Incr_Backup(BaseTestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()

        cls.test_files = {}
        cls.create_test_files()

        # setup backup definitions
        cls.logger.info("generate backup definition")
        cls.create_backup_definitions()
        cls.logger.info("backupdef created")


    @classmethod
    def create_test_files(cls):
        logging.info("Creating test files...")
        cls.test_files = {
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
        for filename, content in cls.test_files.items():
            with open(os.path.join(cls.test_dir, 'data', filename), 'w') as f:
                f.write(content)


    @classmethod
    def create_backup_definitions(cls):
        logging.info("Generating backup definition")
        backup_definitions = {
            "example" : f"""
-Q 
-B {cls.dar_rc}
-R /
-s 10G
-z6
-am
-g {os.path.join(cls.test_dir, 'data')}
""".replace("-g /tmp/", "-g tmp/")  # because dar does not allow first "/"
        }

        for filename, content in backup_definitions.items():
            with open(os.path.join(cls.test_dir, 'backup.d', filename), 'w') as f:
                f.write(content)


    def test_backup_functionality(self):
        try:
            # full backup
            self.run_backup_script("--full-backup")

            # Verify FULL backup contents
            check_saved=True
            self.verify_backup_contents(self.test_files, f"example_FULL_{self.datestamp}", check_saved)
            logging.info("FULL backup verification succeeded")

            # cleanup restore directory
            shutil.rmtree(os.path.join(self.test_dir, 'restore'))
            Path(os.path.join(self.test_dir, 'restore')).mkdir(parents=True, exist_ok=True)

            # Differential backup
            # Modify one file for differential backup
            with open(os.path.join(self.test_dir, 'data', 'file2.txt'), 'a') as f:
                f.write('This is an additional line.')

            self.run_backup_script("--differential-backup")

            # Verify DIFF backup contents
            self.verify_backup_contents(['data/file2.txt'], f"example_DIFF_{self.datestamp}", check_saved=True)
            logging.info("Differential backup verification succeeded")

            # cleanup restore directory
            shutil.rmtree(os.path.join(self.test_dir, 'restore'))
            Path(os.path.join(self.test_dir, 'restore')).mkdir(parents=True, exist_ok=True)

            # Incremental backup
            # Modify one file for incremental backup
            with open(os.path.join(self.test_dir, 'data', 'file3.txt'), 'a') as f:
                f.write('This is an additional line.')

            self.run_backup_script("--incremental-backup")
            # Verify INCR backup contents
            self.verify_backup_contents(['data/file3.txt'], f"example_INCR_{self.datestamp}", check_saved=True)
            logging.info("Incremental backup verification succeeded")
        except Exception as e:
            self.logger.exception("Backup functionality test failed")
            sys.exit(1)
        self.logger.info("test_backup_functionality() finished successfully")



    def run_backup_script(self, type=""):
        """
        Expects to run in a virtual environment with dar-backup installed
        """
        command = ['dar-backup', type, '-d', "example", '--verbose', '--log-level', 'debug', '--config-file', self.config_file]
        process = run_command(command)
        stdout,stderr = process.communicate()
        logging.info(stdout)
        return True

    
    def verify_backup_contents(self, expected_files, archive, check_saved=False):
        """
        Expects to run in a virtual environment with dar-backup installed
        """
        command = ['dar-backup', '--list-contents', archive, '--config-file', self.config_file]
        logging.info(command)
        
        process = run_command(command)
        stdout,stderr = process.communicate()
        logging.info(stdout)


        for expected_file in expected_files:
            if check_saved:
                pattern = re.compile(rf'\[Saved\].*{re.escape(expected_file)}')
                if not pattern.search(stdout):
                    logging.error(f"Expected file {expected_file} not found with [Saved] marker in backup")
                    raise Exception(f"Expected file {expected_file} not found with [Saved] marker in backup")
                


if __name__ == "__main__":
    unittest.main()
    