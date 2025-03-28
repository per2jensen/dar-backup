# modified: 2021-07-25 to be a pytest test
import importlib
import re
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from dar_backup.command_runner import CommandRunner
from dar_backup.dar_backup import filter_darrc_file
from tests.envdata import EnvData
from tests.test_bitrot import generate_datafiles


def create_test_files(env: EnvData) -> dict:
    env.logger.info("Creating test dummy archive files...")
    test_files = {
        f'dummy_FULL_.1.dar': 'dummy',
    }
    for filename, content in test_files.items():
        with open(os.path.join(env.test_dir, 'backups', filename), 'w') as f:
            f.write(content)

    return test_files


def xtest_verbose(setup_environment, env):

    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
    test_files = create_test_files(env)   

    env.logger.info(f"--> Start running test: {sys._getframe().f_code.co_name}")
    command = ['dar-backup', '--list', '--config-file', env.config_file, '--verbose']
    process = runner.run(command)
    stdout, stderr = process.stdout, process.stderr
    if process.returncode != 0:
        env.logger.error(f"Command failed: {command}")
        env.logger.error(f"stderr: {stderr}")
        raise Exception(f"Command failed: {command}")

    env.logger.info("dar-backup --verbose output:\n" + stdout)


    # Find directory of dar_backup.py
    dar_backup = importlib.import_module('dar_backup.dar_backup')
    dar_backup_path = dar_backup.__file__
    dar_backup_dir = os.path.dirname(dar_backup_path)

    darrc_path = os.path.join(dar_backup_dir, '.darrc')

    expected_patterns = [
        f'{darrc_path}'
        ]

    for pattern in expected_patterns:
        assert re.search(pattern, stdout), f".darrc expected here: {darrc_path}"


def test_verify_filtering(setup_environment, env):
    """
    Verify that the filtering options from .darrc works as expected
    """
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
    # Define options to filter out
    options_to_remove = {"-vt", "-vs", "-vd", "-vf", "-va"}

    found_options_in_darrc = []

    try:
        with open(env.dar_rc, "r") as infile:
            for line in infile:
                # Check if any unwanted option is in the line
                if any(option in line for option in options_to_remove):
                    found_options_in_darrc.append(line)
        for option in found_options_in_darrc:
            env.logger.info(f"Option {option} found in .darrc")

        if len(found_options_in_darrc) == 0:
            assert False, "No options to filter out found in .darrc  ==> the test is not valid"

       
        # Filter out options from .darrc
        path_filtered_darrc = filter_darrc_file(env.dar_rc)
        env.logger.info(f"Filtered .darrc saved to {path_filtered_darrc}")
        env.logger.info(f"Verify options have been filtered out: {options_to_remove}")  
        with open(path_filtered_darrc, "r") as infile:
            for line in infile:
                # Check if any unwanted option is in the line
                if any(option in line for option in options_to_remove):
                    assert False, f"'{line}' filtered option found in filtered .darrc '{path_filtered_darrc}'"

    except:
        env.logger.error(f"Failed to filter out options", exc_info=True)
        assert False
    finally:
        # Clean up
        if os.path.exists(path_filtered_darrc):
            os.remove(path_filtered_darrc)


def test_backup_with_filtered_darrc(setup_environment, env):
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
    file_sizes = {
        '10B': 10,
        '100B': 100,        
        '100kB': 100 * 1024,
        '1MB': 1024 * 1024
    }
    generate_datafiles(env, file_sizes)

    command = ['dar-backup', '-F', '--config-file', env.config_file, '--verbose', '--log-level', 'debug', '--log-stdout', '--suppress-dar-msg']
    process = runner.run(command)
    stdout, stderr = process.stdout, process.stderr
    
    # verify the temporary filtered darrc is removed
    darrc_location = None
    for line in stdout.split("\n"):
        if ".darrc location: " in line:
            darrc_location = line.split(".darrc location: ")[1].strip()
            env.logger.info(f"Extracted .darrc location: {darrc_location}")
            break

    if not darrc_location:
        assert False, "Failed to find '.darrc location' in stdout"

    assert not os.path.exists(darrc_location), f"The filtered darrc file '{darrc_location}' should have been removed"


    # verify dar output is not as verbose as the default configures
    for line in stdout.split("\n"):
        if "-Txml" in line:
            env.logger.info(f"dar list contents in xml found, stop here: {line}")
            break
        if "<File" in line or "<Directory" in line:
            assert False, f"dar verbose message found in output: {line}"
    
    if process.returncode != 0:
        env.logger.error(f"Command failed: {command}")
        env.logger.error(f"stderr: {stderr}")
        raise Exception(f"Command failed: {command}")

