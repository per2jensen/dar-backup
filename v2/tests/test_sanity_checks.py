# modified: 2021-07-25 to be a pytest test
import importlib
import os
import re
import sys
import tempfile

from tests.envdata import EnvData
from time import time
from dar_backup.util import run_command



def modify_config_file_tilde(env: EnvData) -> dict:
    """
    Modify the LOG_DIR in the config file to include "~"

    Args:
        env (EnvData): The environment data object.
    
    Returns:
        dict: { "LOGFILE_LOCATION" : "<path to log file>" }
    
    Raises:
        RuntimeError: If the command fails.
    """

    unix_time = int(time())

    LOGFILE_LOCATION = f"~/.test_{unix_time}_dar-backup.log"
    env.logger.info(f"LOGFILE_LOCATION: {LOGFILE_LOCATION}")

    config_path = os.path.join(env.test_dir, env.config_file)
    env.logger.info(f"config file path: {config_path}")

    with open(config_path, 'r') as f:
        lines = f.readlines()
    with open(config_path, 'w') as f:
        for line in lines:
            if line.startswith('LOGFILE_LOCATION = '):
                f.write(f'LOGFILE_LOCATION = {LOGFILE_LOCATION}\n')
            else:
                f.write(line)

    env.logger.info("Patched config file:")
    with open(config_path, 'r') as f:
        lines = f.readlines()
        for line in lines:
            env.logger.info(line)

    return { 'LOGFILE_LOCATION': LOGFILE_LOCATION }   




def modify_config_file_env_vars(env: EnvData) -> dict:
    """
    Modify the BACKUP_DIR and LOG_DIR in the config file to include environtment variables

    Args:
        env (EnvData): The environment data object.
    
    Returns:
        dict: with the keys BACKUP_DIR and LOG_DIR
    
    Raises:
        RuntimeError: If the command fails.
    """

    BACKUP_DIR = tempfile.mkdtemp(dir="/tmp")
    env.logger.info(f"BACKUP_DIR: {BACKUP_DIR}")

    LOG_DIR    = tempfile.mkdtemp(dir="/tmp")  
    env.logger.info(f"LOG_DIR: {LOG_DIR}")

    config_path = os.path.join(env.test_dir, env.config_file)
    env.logger.info(f"Resulting config file path: {config_path}")

    with open(config_path, 'r') as f:
        lines = f.readlines()
    with open(config_path, 'w') as f:
        for line in lines:
            if line.startswith('BACKUP_DIR = '):
                f.write('BACKUP_DIR = ${BACKUP_DIR}\n')
            elif line.startswith('LOGFILE_LOCATION = '):
                f.write('LOGFILE_LOCATION = ${LOG_DIR}/dar-backup.log\n')
            else:
                f.write(line)

    env.logger.info("Patched config file:")
    with open(config_path, 'r') as f:
        lines = f.readlines()
        for line in lines:
            env.logger.info(line)

    return {'BACKUP_DIR': BACKUP_DIR, 'LOG_DIR': LOG_DIR}   



def test_env_vars_in_config_file(setup_environment, env: EnvData):
    """
    Test that environment variables in the config file are correctly expanded.
    """

    # Create temporary config file with environment variables
    env_vars = modify_config_file_env_vars(env)

    # Set environment variables
    os.environ['BACKUP_DIR'] = env_vars['BACKUP_DIR']
    env.logger.info(f"env var $BACKUP_DIR: {os.environ['BACKUP_DIR']}")

    os.environ['LOG_DIR']    = env_vars['LOG_DIR']
    env.logger.info(f"env var $LOG_DIR: {os.environ['LOG_DIR']}")

    try:
        #run manager --create again, since the BACKUP_DIR was changed after the environment was set up
        command = ['manager', '--create', '--config-file', env.config_file]
        process = run_command(command)
        assert process.returncode == 0, f'manager command failed with return code {process.returncode}'

        # Run the dar-backup command with the temporary config file
        command = ['dar-backup', '--full-backup', '--config-file', env.config_file, '-d', 'example', '--log-level', 'debug', '--log-stdout']
        process = run_command(command)

        # Check that the command executed successfully
        assert process.returncode == 0, f'dar-backup command failed with return code {process.returncode}'

        # Verify that the backup and log directories were used correctly
        assert os.path.exists(os.path.join(os.environ['BACKUP_DIR'], f'example_FULL_{env.datestamp}.1.dar')), f'Archive f"example_FULL_{env.datestamp}.1.dar" not found in Backup directory'
        assert os.path.exists(os.path.join(os.environ['LOG_DIR'], 'dar-backup.log')), 'Log directory was not used correctly'
    finally:
        # Clean up temporary config file and directories
        if os.environ['BACKUP_DIR'].startswith('/tmp/'):
            command = ['rm', '-rf', f"/tmp/{env_vars['BACKUP_DIR'][5:]}"]

        if os.environ['LOG_DIR'].startswith('/tmp/'):
            command = ['rm', '-rf', f"/tmp/{env_vars['LOG_DIR'][5:]}"]


def test_tilde_in_config_file(setup_environment, env: EnvData):
    """
    Test that "~" in the config file is correctly expanded.
    """

    # Create temporary config file with environment variables
    dict = modify_config_file_tilde(env)

    try:
        # Run the dar-backup command with the temporary config file
        command = ['dar-backup', '--full-backup', '--config-file', env.config_file, '-d', 'example', '--log-level', 'debug', '--log-stdout']
        process = run_command(command)

        # Check that the command executed successfully
        assert process.returncode == 0, f'dar-backup command failed with return code {process.returncode}'

        # Verify that logfile exists
        logfile = os.path.expanduser(dict['LOGFILE_LOCATION'])  
        assert os.path.exists(logfile), f'Logfile: {logfile} not found in home directory'
        assert os.path.getsize(logfile) > 0, f'Logfile: {logfile} is empty'

        env.logger.info(f"Contents of logfile '{logfile}'\n==================")
        with open(logfile, 'r') as f:
            for line in f:
                env.logger.info(line.strip())  # Removes unnecessary newlines
        
    finally:
        # Clean up temporary config file and directories
        if os.path.exists(logfile):
            os.remove(logfile)
            env.logger.info(f"Removed logfile: {logfile}")


def test_dar_backup_definition_with_underscore(setup_environment, env):
    command = ['dar-backup', '--full-backup', '--config-file', env.config_file, '-d', 'example_2']
    process = run_command(command)
    if process.returncode == 0:
        raise Exception(f'dar-backup must fail on a backup definition with an underscore in the name')

def test_dar_backup_nonexistent_definition_(setup_environment, env):
    command = ['dar-backup', '--full-backup', '--config-file', env.config_file, '-d', 'nonexistent_definition']
    process = run_command(command)
    assert process.returncode == 127, f'dar-backup must fail if backup definition is not found, using -d option'


def test_dar_backup_nonexistent_config_file(setup_environment, env):
    command = ['dar-backup', '--full-backup', '--config-file', 'non-existent-config-file', '-d', 'example']
    process = run_command(command)
    assert process.returncode == 127, f'dar-backup must fail and return code must be 127 if config file is not found'


