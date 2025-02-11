import os
import subprocess
import logging
import sys

from pathlib import Path
from datetime import timedelta
from datetime import datetime

from dar_backup.util import run_command

# Ensure the test directory is in the Python path
#sys.path.append(os.path.abspath(os.path.dirname(__file__)))
from tests.envdata import EnvData

today = datetime.now().strftime('%Y-%m-%d')
date_10_days_ago = (datetime.now() - timedelta(days=10)).strftime('%Y-%m-%d')
date_19_days_ago  = (datetime.now() - timedelta(days=19)).strftime('%Y-%m-%d')
date_20_days_ago  = (datetime.now() - timedelta(days=20)).strftime('%Y-%m-%d')
date_40_days_ago  = (datetime.now() - timedelta(days=40)).strftime('%Y-%m-%d')
date_100_days_ago = (datetime.now() - timedelta(days=100)).strftime('%Y-%m-%d')


def create_test_files(env):
    env.logger.info("Creating test dummy archive files...")
    test_files = {
        f'example_FULL_{date_100_days_ago}.1.dar': 'dummy',
        f'example_DIFF_{date_40_days_ago}.1.dar': 'dummy',
        f'example_DIFF_{date_20_days_ago}.1.dar': 'dummy',
        f'example_INCR_{date_19_days_ago}.1.dar': 'dummy',
        f'example_INCR_{date_10_days_ago}.1.dar': 'dummy',

    }
    for filename, content in test_files.items():
        with open(os.path.join(env.test_dir, 'backups', filename), 'w') as f:
            f.write(content)


def run_cleanup_script(env):
#    current_pythonpath = os.environ.get('PYTHONPATH', '')
#    new_pythonpath = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
#    os.environ['PYTHONPATH'] = f"{new_pythonpath}:{current_pythonpath}"

#    print(f"PYTHONPATH: {os.environ['PYTHONPATH']}")
#    env.logger.info(f"PYTHONPATH: {os.environ['PYTHONPATH']}")

    command = ['cleanup', '-d', 'example', '--config-file', env.config_file, '--log-level', 'debug', '--log-stdout']
    env.logger.info(command)
    result = subprocess.run(command, capture_output=True, text=True)
    env.logger.info(result.stdout)

#    os.environ['PYTHONPATH'] = current_pythonpath   

    if result.returncode != 0:
        env.logger.error(result.stderr)
        raise RuntimeError(f"Cleanup script failed with return code {result.returncode}")
    return result.returncode


def test_cleanup_functionality(setup_environment, env):
    env.logger.info(f"--> Start running test: {sys._getframe().f_code.co_name}")
    
    create_test_files(env)
    run_cleanup_script(env)


    env.logger.info(f"Assert 'example_DIFF_{date_40_days_ago}.1.dar' was deleted")
    assert (not os.path.exists(os.path.join(env.test_dir, 'backups', f'example_DIFF_{date_40_days_ago}.1.dar'))), f"File {os.path.join(env.test_dir, 'backups', f'example_DIFF_{date_40_days_ago}.1.dar')} still exists"
    
    env.logger.info(f"Assert 'example_INCR_{date_19_days_ago}.1.dar' was deleted")
    assert (not os.path.exists(os.path.join(env.test_dir, 'backups', f'example_INCR_{date_19_days_ago}.1.dar'))), f"File {os.path.join(env.test_dir, 'backups', f'example_INCR_{date_19_days_ago}.1.dar')} still exists"


    env.logger.info(f"Assert 'example_FULL_{date_100_days_ago}.1.dar' exists")
    assert (os.path.exists(os.path.join(env.test_dir, 'backups', f'example_FULL_{date_100_days_ago}.1.dar'))), f"File {os.path.join(env.test_dir, 'backups', f'example_FULL_{date_100_days_ago}.1.dar')} does not exist"
    
    env.logger.info(f"Assert 'example_DIFF_{date_20_days_ago}.1.dar' exists")
    assert (os.path.exists(os.path.join(env.test_dir, 'backups', f'example_DIFF_{date_20_days_ago}.1.dar'))), f"File {os.path.join(env.test_dir, 'backups', f'example_DIFF_{date_20_days_ago}.1.dar')} does not exist"
    
    env.logger.info(f"Assert 'example_INCR_{date_10_days_ago}.1.dar' exists")
    assert (os.path.exists(os.path.join(env.test_dir, 'backups', f'example_INCR_{date_10_days_ago}.1.dar'))), f"File {os.path.join(env.test_dir, 'backups', f'example_INCR_{date_10_days_ago}.1.dar')} does not exist"


def test_cleanup_specific_archives(setup_environment, env):
    """
    Verify that the cleanup script can delete multiple specific archives
    """

    filename = "specific"
    with open(os.path.join(env.test_dir, 'backup.d', filename), 'w') as f:
            f.write("dummy")

    command = ['manager', '--create-db', '--log-level', 'debug', '--log-stdout', '--config-file', env.config_file]
    process = run_command(command)
    env.logger.debug(f"return code from 'db created': {process.returncode}")
    if process.returncode == 0:
        env.logger.info(f'Database created')
    else:
        env.logger.error(f'Something went wrong creating the database')
        stdout, stderr = process.stdout, process.stderr 
        env.logger.error(f"stderr: {stderr}")
        env.logger.error(f"stdout: {stdout}")
        sys.exit(1)



    test_files = {
        f'specific_FULL_{date_100_days_ago}.1.dar': 'dummy',
        f'specific_FULL_{date_100_days_ago}.1.dar.vol001.par2': 'dummy',
        f'specific_FULL_{date_100_days_ago}.1.dar.par2': 'dummy',
        f'specific_FULL_{date_100_days_ago}.2.dar': 'dummy',
        f'specific_FULL_{date_100_days_ago}.2.dar.vol666.par2': 'dummy',
        f'specific_FULL_{date_100_days_ago}.2.dar.par2': 'dummy',
        f'specific_FULL_{date_40_days_ago}.1.dar': 'dummy',
        f'specific_FULL_{date_40_days_ago}.1.dar.vol001.par2': 'dummy',
        f'specific_FULL_{date_40_days_ago}.1.dar.par2': 'dummy',
        f'specific_FULL_{date_40_days_ago}.2.dar': 'dummy',
        f'specific_FULL_{date_40_days_ago}.2.dar.vol666.par2': 'dummy',
        f'specific_FULL_{date_40_days_ago}.2.dar.par2': 'dummy',
        f'specific_FULL_{date_20_days_ago}.1.dar': 'dummy',
        f'specific_FULL_{date_20_days_ago}.1.dar.vol001.par2': 'dummy',
        f'specific_FULL_{date_20_days_ago}.1.dar.par2': 'dummy',
        f'specific_FULL_{date_20_days_ago}.2.dar': 'dummy',
        f'specific_FULL_{date_20_days_ago}.2.dar.vol666.par2': 'dummy',
        f'specific_FULL_{date_20_days_ago}.2.dar.par2': 'dummy',
    }
    for filename, content in test_files.items():
        with open(os.path.join(env.test_dir, 'backups', filename), 'w') as f:
            f.write(content)


    command = ['cleanup', '--cleanup-specific-archives', f'specific_FULL_{date_100_days_ago} , specific_FULL_{date_20_days_ago}'  , '--config-file', env.config_file, '--verbose', '--log-level', 'debug', '--log-stdout']
    env.logger.info(command)
    result = subprocess.run(command, capture_output=True, text=True)
    env.logger.info(result.stdout)
    if result.returncode != 0:
        env.logger.error(result.stderr)
        raise RuntimeError(f"Cleanup script failed with return code {result.returncode}")

    assert (not os.path.exists(os.path.join(env.test_dir, 'backups', f'specific_FULL_{date_100_days_ago}.1.dar'))), f"File {os.path.join(env.test_dir, 'backups', f'specific_FULL_{date_100_days_ago}.1.dar')} still exists"
    assert (not os.path.exists(os.path.join(env.test_dir, 'backups', f'specific_FULL_{date_100_days_ago}.1.dar.vol001.par2'))), f"File {os.path.join(env.test_dir, 'backups', f'specific_FULL_{date_100_days_ago}.1.dar.vol001.par2')} still exists"
    assert (not os.path.exists(os.path.join(env.test_dir, 'backups', f'specific_FULL_{date_100_days_ago}.1.dar.par2'))), f"File {os.path.join(env.test_dir, 'backups', f'specific_FULL_{date_100_days_ago}.1.dar.par2')} still exists"
    assert (not os.path.exists(os.path.join(env.test_dir, 'backups', f'specific_FULL_{date_100_days_ago}.2.dar'))), f"File {os.path.join(env.test_dir, 'backups', f'specific_FULL_{date_100_days_ago}.2.dar')} still exists"
    assert (not os.path.exists(os.path.join(env.test_dir, 'backups', f'specific_FULL_{date_100_days_ago}.2.dar.vol666.par2'))), f"File {os.path.join(env.test_dir, 'backups', f'specific_FULL_{date_100_days_ago}.2.dar.vol666.par2')} still exists"
    assert (not os.path.exists(os.path.join(env.test_dir, 'backups', f'specific_FULL_{date_100_days_ago}.2.dar.par2'))), f"File {os.path.join(env.test_dir, 'backups', f'specific_FULL_{date_100_days_ago}.2.dar.par2')} still exists"

    assert (not os.path.exists(os.path.join(env.test_dir, 'backups', f'specific_FULL_{date_20_days_ago}.1.dar'))), f"File {os.path.join(env.test_dir, 'backups', f'specific_FULL_{date_20_days_ago}.1.dar')} still exists"
    assert (not os.path.exists(os.path.join(env.test_dir, 'backups', f'specific_FULL_{date_20_days_ago}.1.dar.vol001.par2'))), f"File {os.path.join(env.test_dir, 'backups', f'specific_FULL_{date_20_days_ago}.1.dar.vol001.par2')} still exists"
    assert (not os.path.exists(os.path.join(env.test_dir, 'backups', f'specific_FULL_{date_20_days_ago}.1.dar.par2'))), f"File {os.path.join(env.test_dir, 'backups', f'specific_FULL_{date_20_days_ago}.1.dar.par2')} still exists"
    assert (not os.path.exists(os.path.join(env.test_dir, 'backups', f'specific_FULL_{date_20_days_ago}.2.dar'))), f"File {os.path.join(env.test_dir, 'backups', f'specific_FULL_{date_20_days_ago}.2.dar')} still exists"
    assert (not os.path.exists(os.path.join(env.test_dir, 'backups', f'specific_FULL_{date_20_days_ago}.2.dar.vol666.par2'))), f"File {os.path.join(env.test_dir, 'backups', f'specific_FULL_{date_20_days_ago}.2.dar.vol666.par2')} still exists"
    assert (not os.path.exists(os.path.join(env.test_dir, 'backups', f'specific_FULL_{date_20_days_ago}.2.dar.par2'))), f"File {os.path.join(env.test_dir, 'backups', f'specific_FULL_{date_20_days_ago}.2.dar.par2')} still exists"

    assert (os.path.exists(os.path.join(env.test_dir, 'backups', f'specific_FULL_{date_40_days_ago}.1.dar'))), f"File {os.path.join(env.test_dir, 'backups', f'specific_FULL_{date_40_days_ago}.1.dar')} still exists"
    assert (os.path.exists(os.path.join(env.test_dir, 'backups', f'specific_FULL_{date_40_days_ago}.1.dar.vol001.par2'))), f"File {os.path.join(env.test_dir, 'backups', f'specific_FULL_{date_40_days_ago}.1.dar.vol001.par2')} still exists"
    assert (os.path.exists(os.path.join(env.test_dir, 'backups', f'specific_FULL_{date_40_days_ago}.1.dar.par2'))), f"File {os.path.join(env.test_dir, 'backups', f'specific_FULL_{date_40_days_ago}.1.dar.par2')} still exists"
    assert (os.path.exists(os.path.join(env.test_dir, 'backups', f'specific_FULL_{date_40_days_ago}.2.dar'))), f"File {os.path.join(env.test_dir, 'backups', f'specific_FULL_{date_40_days_ago}.2.dar')} still exists"
    assert (os.path.exists(os.path.join(env.test_dir, 'backups', f'specific_FULL_{date_40_days_ago}.2.dar.vol666.par2'))), f"File {os.path.join(env.test_dir, 'backups', f'specific_FULL_{date_40_days_ago}.2.dar.vol666.par2')} still exists"
    assert (os.path.exists(os.path.join(env.test_dir, 'backups', f'specific_FULL_{date_40_days_ago}.2.dar.par2'))), f"File {os.path.join(env.test_dir, 'backups', f'specific_FULL_{date_40_days_ago}.2.dar.par2')} still exists"



def test_cleanup_multiple_specific_archives(setup_environment, env):
    test_files = {
        f'specific_FULL_{date_100_days_ago}.1.dar': 'dummy',
        f'specific_FULL_{date_100_days_ago}.1.dar.vol001.par2': 'dummy',
        f'specific_FULL_{date_100_days_ago}.1.dar.par2': 'dummy',
        f'specific_FULL_{date_100_days_ago}.2.dar': 'dummy',
        f'specific_FULL_{date_100_days_ago}.2.dar.vol666.par2': 'dummy',
        f'specific_FULL_{date_100_days_ago}.2.dar.par2': 'dummy',
    }
    for filename, content in test_files.items():
        with open(os.path.join(env.test_dir, 'backups', filename), 'w') as f:
            f.write(content)

    with open(os.path.join(env.test_dir, 'backup.d', "specific"), 'w') as f:  # Create a dummy backup definition, so th catalog db is created
            f.write("dummy")
    
    command = ['manager', '--create-db' ,'--config-file', env.config_file, '--log-level', 'debug', '--log-stdout']
    process = run_command(command)
    if process.returncode != 0:
        stdout, stderr = process.stdout, process.stderr
        print(f"stdout: {stdout}")  
        print(f"stderr: {stderr}")  
        raise Exception(f"Command failed: {command}")



    command = ['cleanup', '--cleanup-specific-archives', f'specific_FULL_{date_100_days_ago}'  , '--config-file', env.config_file, '--log-level', 'debug', '--log-stdout']
    env.logger.info(command)
    result = subprocess.run(command, capture_output=True, text=True)
    env.logger.info(result.stdout)
    if result.returncode != 0:
        env.logger.error(result.stderr)
        raise RuntimeError(f"Cleanup script failed with return code {result.returncode}")

    assert (not os.path.exists(os.path.join(env.test_dir, 'backups', f'specific_FULL_{date_100_days_ago}.1.dar'))), f"File {os.path.join(env.test_dir, 'backups', f'specific_FULL_{date_100_days_ago}.1.dar')} still exists"
    assert (not os.path.exists(os.path.join(env.test_dir, 'backups', f'specific_FULL_{date_100_days_ago}.1.dar.vol001.par2'))), f"File {os.path.join(env.test_dir, 'backups', f'specific_FULL_{date_100_days_ago}.1.dar.vol001.par2')} still exists"
    assert (not os.path.exists(os.path.join(env.test_dir, 'backups', f'specific_FULL_{date_100_days_ago}.1.dar.par2'))), f"File {os.path.join(env.test_dir, 'backups', f'specific_FULL_{date_100_days_ago}.1.dar.par2')} still exists"

    assert (not os.path.exists(os.path.join(env.test_dir, 'backups', f'specific_FULL_{date_100_days_ago}.2.dar'))), f"File {os.path.join(env.test_dir, 'backups', f'specific_FULL_{date_100_days_ago}.2.dar')} still exists"
    assert (not os.path.exists(os.path.join(env.test_dir, 'backups', f'specific_FULL_{date_100_days_ago}.2.dar.vol666.par2'))), f"File {os.path.join(env.test_dir, 'backups', f'specific_FULL_{date_100_days_ago}.2.dar.vol666.par2')} still exists"
    assert (not os.path.exists(os.path.join(env.test_dir, 'backups', f'specific_FULL_{date_100_days_ago}.2.dar.par2'))), f"File {os.path.join(env.test_dir, 'backups', f'specific_FULL_{date_100_days_ago}.2.dar.par2')} still exists"





def test_cleanup_alternate_dir(setup_environment, env):
    alternate_dir = os.path.join(env.test_dir, 'backups-alternate')
    if not alternate_dir.startswith('/tmp/unit-test'):
        raise RuntimeError("Alternate directory is not a temporary directory")

    os.makedirs(alternate_dir, exist_ok=True)

    test_files = {
        f'example_DIFF_{date_20_days_ago}.1.dar': 'dummy',
        f'example_INCR_{date_10_days_ago}.1.dar': 'dummy',
    }


    for filename, content in test_files.items():
        with open(os.path.join(env.test_dir, 'backups', filename), 'w') as f:
            f.write(content)

    for filename, content in test_files.items():
        with open(os.path.join(alternate_dir, filename), 'w') as f:
            f.write(content)


    command = ['cleanup', '--alternate-archive-dir', alternate_dir, '--config-file', env.config_file, '--log-level', 'debug', '--log-stdout']
    env.logger.info(command)
    result = subprocess.run(command, capture_output=True, text=True)
    env.logger.info(result.stdout)
    if result.returncode != 0:
        env.logger.error(result.stderr)
        raise RuntimeError(f"Cleanup script failed with return code {result.returncode}")

    assert (not os.path.exists(os.path.join(env.test_dir, 'alternate_dir', f'example_DIFF_{date_20_days_ago}.1.dar'))), f"File {os.path.join(env.test_dir, 'alternate_dir', f'example_DIFF_{date_20_days_ago}.1.dar')} still exists"
    assert (not os.path.exists(os.path.join(env.test_dir, 'alternate_dir', f'example_INCR_{date_10_days_ago}.1.dar'))), f"File {os.path.join(env.test_dir, 'alternate_dir', f'example_INCR_{date_10_days_ago}.1.dar')} still exists"

    assert (os.path.exists(os.path.join(env.test_dir, 'backups', f'example_DIFF_{date_20_days_ago}.1.dar'))), f"File {os.path.join(env.test_dir, 'backups', f'example_DIFF_{date_20_days_ago}.1.dar')} does not exist"
    assert (os.path.exists(os.path.join(env.test_dir, 'backups', f'example_INCR_{date_10_days_ago}.1.dar'))), f"File {os.path.join(env.test_dir, 'backups', f'example_INCR_{date_10_days_ago}.1.dar')} does not exist"

