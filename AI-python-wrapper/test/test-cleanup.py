import unittest
from base_test_case import BaseTestCase

#import datetime
import os
import subprocess
import logging
import re
import shutil
import sys
import glob  # Added import statement


from pathlib import Path
from datetime import timedelta
from datetime import datetime

today = datetime.now().strftime('%Y-%m-%d')
days_ago_10  = (datetime.now() - timedelta(days=10)).strftime('%Y-%m-%d')
days_ago_19  = (datetime.now() - timedelta(days=19)).strftime('%Y-%m-%d')
days_ago_20  = (datetime.now() - timedelta(days=20)).strftime('%Y-%m-%d')
days_ago_40  = (datetime.now() - timedelta(days=40)).strftime('%Y-%m-%d')
days_ago_100 = (datetime.now() - timedelta(days=100)).strftime('%Y-%m-%d')

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
            f'example_FULL_{days_ago_100}.1.dar': 'dummy',
            f'example_DIFF_{days_ago_40}.1.dar': 'dummy',
            f'example_DIFF_{days_ago_20}.1.dar': 'dummy',
            f'example_INCR_{days_ago_19}.1.dar': 'dummy',
            f'example_INCR_{days_ago_10}.1.dar': 'dummy',

        }
        for filename, content in cls.test_files.items():
            with open(os.path.join(cls.test_dir, 'backups', filename), 'w') as f:
                f.write(content)

    def run_cleanup_script(self):
        command = ['python3',  os.path.join(self.test_dir, "bin", "cleanup.py"), '-d', "example", '--config-file', self.config_file]
        logging.info(command)
        result = subprocess.run(command, capture_output=True, text=True)
        logging.info(result.stdout)
        if result.returncode != 0:
            logging.error(result.stderr)
            raise RuntimeError(f"Cleanup script failed with return code {result.returncode}")
        return result.returncode



    def test_cleanup_functionality(self):
        try:
            self.run_cleanup_script()

            self.logger.info(f"Assert 'example_DIFF_{days_ago_40}.1.dar' was deleted")
            self.assertTrue(not os.path.exists(os.path.join(self.test_dir, 'backups', f'example_DIFF_{days_ago_40}.1.dar')))
            
            self.logger.info(f"Assert 'example_INCR_{days_ago_19}.1.dar' was deleted")
            self.assertTrue(not os.path.exists(os.path.join(self.test_dir, 'backups', f'example_INCR_{days_ago_19}.1.dar')))


            self.logger.info(f"Assert 'example_FULL_{days_ago_100}.1.dar' exists")
            self.assertTrue(os.path.exists(os.path.join(self.test_dir, 'backups', f'example_FULL_{days_ago_100}.1.dar')))
            
            self.logger.info(f"Assert 'example_DIFF_{days_ago_20}.1.dar' exists")
            self.assertTrue(os.path.exists(os.path.join(self.test_dir, 'backups', f'example_DIFF_{days_ago_20}.1.dar')))
            
            self.logger.info(f"Assert 'example_INCR_{days_ago_10}.1.dar' exists")
            self.assertTrue(os.path.exists(os.path.join(self.test_dir, 'backups', f'example_INCR_{days_ago_10}.1.dar')))


        except Exception as e:
            self.logger.exception("Cleanup functionality test failed")
            raise


if __name__ == '__main__':
    unittest.main()
    
