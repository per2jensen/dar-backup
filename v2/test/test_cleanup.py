import unittest

#import datetime
import os
import subprocess
import logging
import re
import shutil
import sys
import glob  # Added import statement

from base_test_case import BaseTestCase
from pathlib import Path
from datetime import timedelta
from datetime import datetime

from dar_backup.util import run_command

today = datetime.now().strftime('%Y-%m-%d')
date_10_days_ago = (datetime.now() - timedelta(days=10)).strftime('%Y-%m-%d')
date_19_days_ago  = (datetime.now() - timedelta(days=19)).strftime('%Y-%m-%d')
date_20_days_ago  = (datetime.now() - timedelta(days=20)).strftime('%Y-%m-%d')
date_40_days_ago  = (datetime.now() - timedelta(days=40)).strftime('%Y-%m-%d')
date_100_days_ago = (datetime.now() - timedelta(days=100)).strftime('%Y-%m-%d')

class Test_Cleanup_Script(BaseTestCase):
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


    @classmethod
    def create_test_files(cls):
        logging.info("Creating test dummy archive files...")
        cls.test_files = {
            f'example_FULL_{date_100_days_ago}.1.dar': 'dummy',
            f'example_DIFF_{date_40_days_ago}.1.dar': 'dummy',
            f'example_DIFF_{date_20_days_ago}.1.dar': 'dummy',
            f'example_INCR_{date_19_days_ago}.1.dar': 'dummy',
            f'example_INCR_{date_10_days_ago}.1.dar': 'dummy',

        }
        for filename, content in cls.test_files.items():
            with open(os.path.join(cls.test_dir, 'backups', filename), 'w') as f:
                f.write(content)

    def run_cleanup_script(self):

        current_pythonpath = os.environ.get('PYTHONPATH', '')
        new_pythonpath = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        os.environ['PYTHONPATH'] = f"{new_pythonpath}:{current_pythonpath}"

        print(f"PYTHONPATH: {os.environ['PYTHONPATH']}")
        logging.info(f"PYTHONPATH: {os.environ['PYTHONPATH']}")

        command = ['python3', "-m",  "dar_backup.cleanup", '-d', "example", '--config-file', self.config_file]
        logging.info(command)
        result = subprocess.run(command, capture_output=True, text=True)
        logging.info(result.stdout)

        os.environ['PYTHONPATH'] = current_pythonpath   

        if result.returncode != 0:
            logging.error(result.stderr)
            raise RuntimeError(f"Cleanup script failed with return code {result.returncode}")
        return result.returncode

    def test_cleanup_functionality(self):
        logging.info(f"--> Start running test: {sys._getframe().f_code.co_name}")
        
        self.create_test_files()
        try:
            self.run_cleanup_script()

            self.logger.info(f"Assert 'example_DIFF_{date_40_days_ago}.1.dar' was deleted")
            self.assertTrue(not os.path.exists(os.path.join(self.test_dir, 'backups', f'example_DIFF_{date_40_days_ago}.1.dar')))
            
            self.logger.info(f"Assert 'example_INCR_{date_19_days_ago}.1.dar' was deleted")
            self.assertTrue(not os.path.exists(os.path.join(self.test_dir, 'backups', f'example_INCR_{date_19_days_ago}.1.dar')))


            self.logger.info(f"Assert 'example_FULL_{date_100_days_ago}.1.dar' exists")
            self.assertTrue(os.path.exists(os.path.join(self.test_dir, 'backups', f'example_FULL_{date_100_days_ago}.1.dar')))
            
            self.logger.info(f"Assert 'example_DIFF_{date_20_days_ago}.1.dar' exists")
            self.assertTrue(os.path.exists(os.path.join(self.test_dir, 'backups', f'example_DIFF_{date_20_days_ago}.1.dar')))
            
            self.logger.info(f"Assert 'example_INCR_{date_10_days_ago}.1.dar' exists")
            self.assertTrue(os.path.exists(os.path.join(self.test_dir, 'backups', f'example_INCR_{date_10_days_ago}.1.dar')))
        except Exception as e:
            self.logger.exception("Cleanup functionality test failed")
            raise e


    def test_cleanup_specific_archive(self):
        """
        Expects to run in a virtual environment with dar-backup installed
        """    
        logging.info(f"--> Start running test: {sys._getframe().f_code.co_name}")
        logging.info("Creating specific dummy archive files...")
        test_files = {
            f'specific_FULL_{date_100_days_ago}.1.dar': 'dummy',
            f'specific_FULL_{date_100_days_ago}.1.dar.vol001.par2': 'dummy',
            f'specific_FULL_{date_100_days_ago}.1.dar.par2': 'dummy',
            f'specific_FULL_{date_100_days_ago}.2.dar': 'dummy',
            f'specific_FULL_{date_100_days_ago}.2.dar.vol666.par2': 'dummy',
            f'specific_FULL_{date_100_days_ago}.2.dar.par2': 'dummy',
        }
        for filename, content in test_files.items():
            with open(os.path.join(self.test_dir, 'backups', filename), 'w') as f:
                f.write(content)

        command = ['cleanup', '--cleanup-specific-archive', f'specific_FULL_{date_100_days_ago}'  , '--config-file', self.config_file]
        logging.info(command)
        result = subprocess.run(command, capture_output=True, text=True)
        logging.info(result.stdout)
        if result.returncode != 0:
            logging.error(result.stderr)
            raise RuntimeError(f"Cleanup script failed with return code {result.returncode}")

        self.assertTrue(not os.path.exists(os.path.join(self.test_dir, 'backups', f'specific_FULL_{date_100_days_ago}.1.dar')))
        self.assertTrue(not os.path.exists(os.path.join(self.test_dir, 'backups', f'specific_FULL_{date_100_days_ago}.1.dar.vol001.par2')))
        self.assertTrue(not os.path.exists(os.path.join(self.test_dir, 'backups', f'specific_FULL_{date_100_days_ago}.1.dar.par2')))

        self.assertTrue(not os.path.exists(os.path.join(self.test_dir, 'backups', f'specific_FULL_{date_100_days_ago}.2.dar')))
        self.assertTrue(not os.path.exists(os.path.join(self.test_dir, 'backups', f'specific_FULL_{date_100_days_ago}.2.dar.vol666.par2')))
        self.assertTrue(not os.path.exists(os.path.join(self.test_dir, 'backups', f'specific_FULL_{date_100_days_ago}.2.dar.par2')))


    def test_cleanup_alternate_dir(self):
        """
        Expects to run in a virtual environment with dar-backup installed
        """
        logging.info(f"--> Start running test: {sys._getframe().f_code.co_name}")

        alternate_dir = os.path.join(self.test_dir, 'backups-alternate')
        if not alternate_dir.startswith('/tmp/unit-test'):
            raise RuntimeError("Alternate directory is not a temporary directory")

        self.cleanup_before_test([alternate_dir])
        os.makedirs(alternate_dir, exist_ok=True)

        for filename, content in self.test_files.items():
            with open(os.path.join(self.test_dir, 'backups', filename), 'w') as f:
                f.write(content)

        for filename, content in self.test_files.items():
            with open(os.path.join(alternate_dir, filename), 'w') as f:
                f.write(content)


        command = ['cleanup', '--alternate-archive-dir', alternate_dir, '--config-file', self.config_file]
        logging.info(command)
        result = subprocess.run(command, capture_output=True, text=True)
        logging.info(result.stdout)
        if result.returncode != 0:
            logging.error(result.stderr)
            raise RuntimeError(f"Cleanup script failed with return code {result.returncode}")

        self.assertTrue(not os.path.exists(os.path.join(self.test_dir, 'alternate_dir', f'example_DIFF_{date_20_days_ago}.1.dar')))
        self.assertTrue(not os.path.exists(os.path.join(self.test_dir, 'alternate_dir', f'example_INCR_{date_10_days_ago}.1.dar')))

        self.assertTrue(os.path.exists(os.path.join(self.test_dir, 'backups', f'example_DIFF_{date_20_days_ago}.1.dar')))
        self.assertTrue(os.path.exists(os.path.join(self.test_dir, 'backups', f'example_INCR_{date_10_days_ago}.1.dar')))


if __name__ == '__main__':
    unittest.main()
    
