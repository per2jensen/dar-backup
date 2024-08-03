import os
from datetime import datetime
import shutil
import unittest
import logging
import sys
from configparser import ConfigParser, NoSectionError

from dar_backup.util import setup_logging

class BaseTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        #if cls is BaseTestCase:
        #    raise unittest.SkipTest("Skip BaseTestCase tests, it's a base class.")

        sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), 'dar_backup')))

        # Use the name of the inheriting class to determine the test case name, preserving underscores
        cls.test_case_name = cls.__name__
        cls.test_dir = f"/tmp/unit-test/{cls.test_case_name.lower()}"
        cls.template_config_file = "template/dar-backup.conf.template"
        cls.config_file = os.path.join(cls.test_dir, "dar-backup.conf")
        cls.template_dar_rc = "template/.darrc"
        cls.dar_rc = os.path.join(cls.test_dir, ".darrc")
        #cls.bin_dir = "dar_backup"
        cls.log_file = "/tmp/unit-test/test.log"
        cls.datestamp = datetime.now().strftime('%Y-%m-%d')

        if os.path.exists(cls.test_dir) and not cls.test_dir.endswith("unit-test/"):
            shutil.rmtree(cls.test_dir)

        # Create the unit test directory
        if not os.path.exists(cls.test_dir):
            os.makedirs(cls.test_dir)

        # Setup logging
        cls.logger = setup_logging(cls.log_file, logging.DEBUG)
        cls.logger.info("setUpClass(): initialized logger")

        # Create the directories as described in the template config file
        try:
            cls.create_directories_from_template()
        except Exception as e:
            cls.logger.exception("Failed to create directories from template")
            raise

        # Put .darrc in test directory
        try:
            cls.copy_dar_rc()
        except Exception as e:
            cls.logger.exception("Failed to copy .darrc to test directory")
            raise
        
        #cls.copy_scripts()
        
        # Print variables to console
        cls.print_variables()


    @classmethod
    def tearDownClass(cls):
        # Clean up after tests - Comment out this block to preserve directories
        #cls.logger.info("No operations in tearDownClass")
        # Uncomment the following lines to enable cleanup
        if os.path.exists(cls.test_dir):
           shutil.rmtree(cls.test_dir)
        
    @classmethod
    def copy_dar_rc(cls):
        try:
            shutil.copy(cls.template_dar_rc, os.path.join(cls.test_dir, cls.dar_rc))
        except:
            cls.logger.exception("Failed to copy {cls.template_dar_rc} to " + os.path.join(cls.test_dir, cls.dar_rc))
            raise

 
    # @classmethod
    # def copy_scripts(cls):
    #     try:
    #         for script in os.listdir(cls.bin_dir):
    #             if os.path.isfile(os.path.join(cls.bin_dir, script)):
    #                 shutil.copy(os.path.join(cls.bin_dir, script), os.path.join(cls.test_dir, "bin"))
    #     except:
    #         cls.logger.exception("Failed to copy script to " + os.path.join(cls.test_dir, "bin"))
    #         raise
    
    @classmethod
    def create_directories_from_template(cls):
        try:
            with open(cls.template_config_file, 'r') as template_file:
                config_content = template_file.read().replace('@@test-case-name@@', cls.test_case_name.lower())
        except FileNotFoundError:
            cls.logger.exception("Template config file not found")
            raise RuntimeError(f"Template config file {cls.template_config_file} not found")

        with open(cls.config_file, 'w') as config_file:
            config_file.write(config_content)

        config = ConfigParser()
        config.read_string(config_content)

        # Log the content to verify it is correctly read
        cls.logger.info(f"Configuration content:\n{config_content}")

        try:
            for key in config["DIRECTORIES"]:
                dir_path = config["DIRECTORIES"][key]
                if not os.path.exists(dir_path):
                    os.makedirs(dir_path, exist_ok=True)
                    cls.logger.info(f"Created directory: {dir_path}")
                else:
                    cls.logger.info(f"Directory already exists: {dir_path}")
        except NoSectionError:
            cls.logger.exception("Section 'DIRECTORIES' not found in the config file")
            raise RuntimeError(f"Section 'DIRECTORIES' not found in the config file {cls.config_file}")

    @classmethod
    def print_variables(cls):
        print(f"Test case name: {cls.test_case_name}")
        print(f"Test directory: {cls.test_dir}")
        print(f"Template config file: {cls.template_config_file}")
        print(f"Config file: {cls.config_file}")
        print(f"Log file: {cls.log_file}")
        print(f".darrc file: {cls.dar_rc}")
 
        cls.logger.info(f"Test case name: {cls.test_case_name}")
        cls.logger.info(f"Test directory: {cls.test_dir}")
        cls.logger.info(f"Template config file: {cls.template_config_file}")
        cls.logger.info(f"Config file: {cls.config_file}")
        cls.logger.info(f"Log file: {cls.log_file}")
        cls.logger.info(f".darrc file: {cls.dar_rc}")

    def tearDown(self):
        # Clean up state that was set up for each test
        self.cleanup_before_test()
        self.logger.info("tearDown(): cleaned up before test")
    
    
    def test_setup(self):
        try:
            # Test to ensure the setup is correct
            # self.assertTrue(os.path.exists(self.test_dir))
            # self.assertTrue(os.path.exists(os.path.join(self.test_dir, 'backups')))
            # self.assertTrue(os.path.exists(os.path.join(self.test_dir, 'data')))
            # self.assertTrue(os.path.exists(os.path.join(self.test_dir, 'restore')))
            # self.assertTrue(os.path.exists(os.path.join(self.test_dir, 'bin')))
            # self.assertTrue(os.path.exists(os.path.join(self.test_dir, 'backup.d')))
            # self.assertTrue(os.path.exists(self.config_file))
            # self.assertTrue(os.path.exists(self.dar_rc))
            pass
        except AssertionError as e:
            self.logger.exception("Setup test failed")
            raise
        
    @classmethod
    def cleanup_before_test(cls, directory_path: list[str] = None):
        if not directory_path:
            directory_path = [os.path.join(cls.test_dir,   "backups"),
                                os.path.join(cls.test_dir, "data"),
                                os.path.join(cls.test_dir, "restore"),
                              ]
        for dir in directory_path:
            if not dir.startswith("/tmp/unit-test"):
                logging.error(f"Only files/directories in /tmp/unit-test can be cleaned up: {dir}")
                raise ValueError(f"Only files/directories in /tmp/unit-test can be cleaned up: {dir}")
            if not os.path.exists(dir):
                return
            for filename in os.listdir(dir):
                file_path = os.path.join(dir, filename)
                try:
                    if os.path.isfile(file_path) or os.path.islink(file_path):
                        os.unlink(file_path)
                    elif os.path.isdir(file_path):
                        shutil.rmtree(file_path)
                except Exception as e:
                    logging.error(f'Failed to delete {file_path}. Reason: {e}')
                    raise e
                
