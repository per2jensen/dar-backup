import os
import shutil
import unittest
from configparser import ConfigParser, NoSectionError

class BaseTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        script_name = os.path.basename(__file__)
        cls.test_case_name = os.path.splitext(script_name)[0]  # Remove .py extension
        cls.test_dir = f"/tmp/unit-test/{cls.test_case_name}"
        cls.template_config_file = "../template/backup_script.conf.template"
        cls.config_file = os.path.join(cls.test_dir, "backup_script.conf")

        # Create the unit test directory
        if not os.path.exists(cls.test_dir):
            os.makedirs(cls.test_dir)

        # Create the directories as described in the template config file
        cls.create_directories_from_template()

        # Print variables to console
        cls.print_variables()

    @classmethod
    def tearDownClass(cls):
        # Clean up after tests - Comment out this block to preserve directories
        # if os.path.exists(cls.test_dir):
        #     shutil.rmtree(cls.test_dir)
        pass

    @classmethod
    def create_directories_from_template(cls):
        try:
            with open(cls.template_config_file, 'r') as template_file:
                config_content = template_file.read().replace('@@test-case-name@@', cls.test_case_name)
        except FileNotFoundError:
            raise RuntimeError(f"Template config file {cls.template_config_file} not found")

        with open(cls.config_file, 'w') as config_file:
            config_file.write(config_content)

        config = ConfigParser()
        config.read_string(config_content)

        # Log the content to verify it is correctly read
        print(f"Configuration content:\n{config_content}")

        try:
            for key, value in config.items('DIRECTORIES'):
                dir_path = value
                os.makedirs(dir_path, exist_ok=True)
        except NoSectionError:
            raise RuntimeError(f"Section 'DIRECTORIES' not found in the config file {cls.config_file}")

    @classmethod
    def print_variables(cls):
        print(f"Test case name: {cls.test_case_name}")
        print(f"Test directory: {cls.test_dir}")
        print(f"Template config file: {cls.template_config_file}")
        print(f"Config file: {cls.config_file}")

    def test_setup(self):
        # Test to ensure the setup is correct
        self.assertTrue(os.path.exists(self.test_dir))
        self.assertTrue(os.path.exists(os.path.join(self.test_dir, 'backups')))
        self.assertTrue(os.path.exists(os.path.join(self.test_dir, 'restore')))
        self.assertTrue(os.path.exists(os.path.join(self.test_dir, 'backup.d')))
        self.assertTrue(os.path.exists(self.config_file))


class TestBackupScript(BaseTestCase):
    def test_backup_functionality(self):
        # Add specific tests for backup functionality here
        # Placeholder for actual tests
        self.assertTrue(True)


if __name__ == '__main__':
    unittest.main()
