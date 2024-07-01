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
            if self.run_backup_script() != 0:
                logging.error("Failed to create FULL backup")
                raise ValueError("FULL backup failed")

            # Verify FULL backup contents
            check_saved=True
            if not self.verify_backup_contents(self.test_files, f"example_FULL_{self.datestamp}", check_saved):
                logging.error("Full backup verification failed")
                raise RuntimeError("FULL backup verification failed")
            else:
                logging.info("FULL backup verification succeeded")

            # Differential backup
            # Modify one file for differential backup
            with open(os.path.join(self.test_dir, 'data', 'file2.txt'), 'a') as f:
                f.write('This is an additional line.')

            if self.run_backup_script("--differential-backup") != 0:
                logging.error("Failed to create DIFF backup")
                raise ValueError("DIFF backup failed")

            # Verify DIFF backup contents
            if not self.verify_backup_contents(['data/file2.txt'], f"example_DIFF_{self.datestamp}", check_saved=True):
                logging.error("Differential backup verification failed")
                raise ValueError("DIFF verify failed")
            else:
                logging.info("Differential backup verification succeeded")


            # Incremental backup
            # Modify one file for incremental backup
            with open(os.path.join(self.test_dir, 'data', 'file3.txt'), 'a') as f:
                f.write('This is an additional line.')

            if self.run_backup_script("--incremental-backup") != 0:
                logging.error("Failed to create INCR backup")
                raise ValueError("INCR backup failed")

            # Verify INCR backup contents
            if not self.verify_backup_contents(['data/file3.txt'], f"example_INCR_{self.datestamp}", check_saved=True):
                logging.error("Incremental backup verification failed")
                raise ValueError("INCR verify failed")
            else:
                logging.info("Incremental backup verification succeeded")
        except Exception as e:
            self.logger.exception("Backup functionality test failed")
            sys.exit(1)
            
    def run_backup_script(self, type=""):
        if type == "":
            command = ['python3',  os.path.join(self.test_dir, "bin", "dar-backup.py"), '-d', "example", '--config-file', self.config_file]
        else:
            command = ['python3',  os.path.join(self.test_dir, "bin", "dar-backup.py"), type, '-d', "example", '--config-file', self.config_file]
        logging.info(command)
        result = subprocess.run(command, capture_output=True, text=True)
        logging.info(result.stdout)
        if result.returncode != 0:
            logging.error(result.stderr)
        return result.returncode

    def verify_backup_contents(self, expected_files, archive, check_saved=False):
        command = ['python3',  os.path.join(self.test_dir, "bin", "dar-backup.py"), '--list-contents', archive, '--config-file', self.config_file]
        result = subprocess.run(command, capture_output=True, text=True)
        logging.info(result.stdout)
        if result.returncode != 0:
            logging.error(result.stderr)
            return False

        backup_contents = result.stdout
        for expected_file in expected_files:
            if check_saved:
                pattern = re.compile(rf'\[Saved\].*{re.escape(expected_file)}')
                if not pattern.search(result.stdout):
                    logging.error(f"Expected file {expected_file} not found with [Saved] marker in backup")
                    return False

        return True

if __name__ == "__main__":
    unittest.main()
    