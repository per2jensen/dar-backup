import pytest

import logging
import os
import shutil
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

# Ensure the test directory is in the Python path
sys.path.append(os.path.abspath(os.path.dirname(__file__)))

from configparser import ConfigParser, NoSectionError
from dar_backup.util import setup_logging
from datetime import datetime
from tests.envdata import EnvData
from dar_backup.util import setup_logging
from dar_backup.command_runner import CommandRunner
from dar_backup.util import get_logger as get_command_logger

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


# Session-scoped fixture for the logger
@pytest.fixture(scope='session')
def logger():
    os.path.exists("/tmp/unit-test") or os.makedirs("/tmp/unit-test")

    test_log =                "/tmp/unit-test/test.log"
    test_command_output_log = "/tmp/unit-test/test_command_output.log"

    logger = setup_logging(test_log, test_command_output_log, "debug", False)
    command_logger = get_command_logger(command_output_logger=True) 
    return {"logger" : logger,
            "command_logger" : command_logger}




@pytest.fixture(scope='function')
def env(request, logger):
    """
    Setup the EnvData dataclass for each test case before the "yield" statement.
    """
    env = EnvData(request.node.name, logger["logger"], logger["command_logger"]) # name of test case
    env.datestamp = datetime.now().strftime('%Y-%m-%d')

    yield env


@pytest.fixture(scope='function')
def setup_environment(request, logger):
    """
    Setup the environment for each test case before the "yield" statement.
    Tear down the environment after the "yield" statement.
    """
    env = EnvData(request.node.name,  logger["logger"], logger["command_logger"]) # name of test case

    env.logger.info("================================================================")
    env.logger.info("               Configure test environment")
    env.logger.info("================================================================")


    env.datestamp = datetime.now().strftime('%Y-%m-%d')

    if env.test_dir.startswith("/tmp/") and os.path.exists(env.test_dir) and not env.test_dir.endswith("unit-test/"):
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
    
    
    create_catalog_db(env)  

    create_a_bit_of_testdata(env)

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
-R /
-s 10G
-z6
-am
--cache-directory-tagging
-g {env.data_dir}
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




def create_catalog_db(env):
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)

    command = ['manager', '--create-db' ,'--config-file', env.config_file, '--log-level', 'debug', '--log-stdout']
    process = runner.run(command)
    if process.returncode != 0:
        stdout, stderr = process.stdout, process.stderr
        print(f"stdout: {stdout}")  
        print(f"stderr: {stderr}")  
        raise Exception(f"Command failed: {command}")



def create_a_bit_of_testdata(env: EnvData):
    global test_files
    env.logger.info("Creating test data files...")
    for filename, content in test_files.items():
        env.logger.info(f"Creating '{filename}' in '{env.data_dir}'")
        with open(os.path.join(env.data_dir, filename), 'w') as f:
            f.write(content)


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
    env.logger.info(f"Test case name: {env.test_case_name}")
    env.logger.info(f"Test directory: {env.test_dir}")
    env.logger.info(f"Template config file: {env.template_config_file}")
    env.logger.info(f"Config file: {env.config_file}")
    env.logger.info(f"Log file: {env.log_file}")
    env.logger.info(f".darrc file: {env.dar_rc}")
