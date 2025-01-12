import pytest

import logging
import os
import shutil
import sys

# Ensure the test directory is in the Python path
sys.path.append(os.path.abspath(os.path.dirname(__file__)))

from configparser import ConfigParser, NoSectionError
from dar_backup.util import setup_logging
from datetime import datetime
from tests.envdata import EnvData
from dar_backup.util import setup_logging


# Session-scoped fixture for the logger
@pytest.fixture(scope='session')
def logger():
    os.path.exists("/tmp/unit-test") or os.makedirs("/tmp/unit-test")
    logger = setup_logging("/tmp/unit-test/test.log", "debug", False, "test_logger")
    return logger




@pytest.fixture(scope='function')
def env(request, logger):
    """
    Setup the EnvData dataclass for each test case before the "yield" statement.
    """
    sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../dar_backup')))

    print(f"Logger: {logger}")  

    env = EnvData(request.node.name, logger) # name of test case
    env.datestamp = datetime.now().strftime('%Y-%m-%d')

    yield env

    try:
        pass
    except Exception as e:
        env.logger.exception("Failed to tear down environment")
        

@pytest.fixture(scope='function')
def setup_environment(request, logger):
    """
    Setup the environment for each test case before the "yield" statement.
    Tear down the environment after the "yield" statement.
    """

    print("current os.path.dirname: " + os.path.join(os.path.dirname(__file__)))
    sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../dar_backup')))

    env = EnvData(request.node.name, logger) # name of test case

    env.logger.info("================================================================")
    env.logger.info("               Configure test environment")
    env.logger.info("================================================================")


    env.datestamp = datetime.now().strftime('%Y-%m-%d')

    if env.test_dir.startswith("/tmp") and os.path.exists(env.test_dir) and not env.test_dir.endswith("unit-test/"):
        shutil.rmtree(env.test_dir)

    # Create the unit test directory
    if not os.path.exists(env.test_dir):
        os.makedirs(env.test_dir)


    # Create the directories as described in the template config file
    try:
        create_directories_from_template(env)
    except Exception as e:
        env.logger.exception("Failed to create directories from template")
        raise

    create_backup_definitions(env)

    # Put .darrc in test directory
    try:
        copy_dar_rc(env)
    except Exception as e:
        env.logger.exception("Failed to copy .darrc to test directory")
        raise
    
    # Print variables to console
    print_variables(env)

    env.logger.info("Environment setup completed")
    env.logger.info("================================================================")
    env.logger.info(f"===> Now running test case: {env.test_case_name}")
    env.logger.info("================================================================")


    yield
    
    # Tear down the environment after the test case
    # in the code below.
    # Tear down the environment after the test case
    try:
        teardown_environment(env)
        pass
    except Exception as e:
        env.logger.exception("Failed to tear down environment")




def create_backup_definitions(env : EnvData) -> None:
    logging.info("Generating backup definition")
    backup_definitions = {
        "example" : f"""
-Q 
-B {env.dar_rc}
-R /
-s 10G
-z6
-am
-g {os.path.join(env.test_dir, 'data')}
""".replace("-g /tmp/", "-g tmp/")  # because dar does not allow first "/"
    }

    for filename, content in backup_definitions.items():
        with open(os.path.join(env.test_dir, 'backup.d', filename), 'w') as f:
            f.write(content)




def create_directories_from_template(env : EnvData):
    try:
        with open(env.template_config_file, 'r') as template_file:
            config_content = template_file.read().replace('@@test-case-name@@', env.test_case_name.lower())
    except FileNotFoundError:
        env.logger.exception("Template config file not found")
        raise RuntimeError(f"Template config file { env.template_config_file} not found")

    with open(env.config_file, 'w') as config_file:
        config_file.write(config_content)

    config = ConfigParser()
    config.read_string(config_content)

    # Log the content to verify it is correctly read
    env.logger.info(f"Configuration content:\n{config_content}")

    try:
        for key in config["DIRECTORIES"]:
            dir_path = config["DIRECTORIES"][key]
            if not os.path.exists(dir_path):
                os.makedirs(dir_path, exist_ok=True)
                env.logger.info(f"Created directory: {dir_path}")
            else:
                env.logger.info(f"Directory already exists: {dir_path}")
    except NoSectionError:
        env.logger.exception("Section 'DIRECTORIES' not found in the config file")
        raise RuntimeError(f"Section 'DIRECTORIES' not found in the config file {config_file}")


def teardown_environment(env: EnvData):
    """
    Safely clean up the test environment directory.
    
    This function ensures that only safe directories are deleted by validating
    `env.test_dir` against critical paths like `/` or `/home/<user>`.

    Args:
        env (EnvData): Environment data containing the `test_dir` to clean up.

    Raises:
        RuntimeError: If the directory is deemed unsafe for deletion.
    """
    try:
        # Perform checks to prevent accidental deletion of critical directories
        if not env.test_dir:
            raise RuntimeError("Environment test directory is not defined!")

        # Normalize the path for safety
        normalized_path = os.path.normpath(env.test_dir)
        
        # List of critical paths that should never be deleted
        try:
            env_var = "HOME"
            home = os.environ[env_var]  # Raises KeyError if the variable does not exist
            env.logger.debug(f"${env_var}: {home}")
        except KeyError:
            home = "/tmp"

        critical_paths = ["/", "/home", home, "/root", "/usr", "/var", "/etc"]
        
        # Check if the path is critical
        if normalized_path in critical_paths or normalized_path in map(os.path.abspath, critical_paths):
            raise RuntimeError(f"Attempt to delete a critical directory: {normalized_path}")

        # Check for other unsafe paths (e.g., parent of the home directory)
        if not normalized_path.startswith("/tmp/unit-test/"):
            raise RuntimeError(f"Refusing to delete an unsafe directory: {normalized_path}")

        # Only delete the directory if all checks are passed
        if os.path.exists(normalized_path):
            shutil.rmtree(normalized_path)

    except Exception as e:
        env.logger.exception("Failed to clean up environment")
        raise


def copy_dar_rc(env : EnvData):
    try:
        shutil.copy(env.template_dar_rc, os.path.join(env.test_dir, env.dar_rc))
    except:
        env.logger.exception("Failed to copy {env.template_dar_rc} to " + os.path.join(env.test_dir, env.dar_rc))
        raise



def print_variables(env : EnvData):
    print(f"Test case name: {env.test_case_name}")
    print(f"Test directory: {env.test_dir}")
    print(f"Template config file: {env.template_config_file}")
    print(f"Config file: {env.config_file}")
    print(f"Log file: {env.log_file}")
    print(f".darrc file: {env.dar_rc}")

    env.logger.info(f"Test case name: {env.test_case_name}")
    env.logger.info(f"Test directory: {env.test_dir}")
    env.logger.info(f"Template config file: {env.template_config_file}")
    env.logger.info(f"Config file: {env.config_file}")
    env.logger.info(f"Log file: {env.log_file}")
    env.logger.info(f".darrc file: {env.dar_rc}")
