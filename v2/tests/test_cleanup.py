import os
import subprocess
import logging
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from pathlib import Path
from datetime import timedelta
from datetime import datetime

from dar_backup.command_runner import CommandRunner

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

    command = ['cleanup', '-d', 'example', '--config-file', env.config_file, '--log-level', 'debug', '--log-stdout']
    env.logger.info(command)
    result = subprocess.run(command, capture_output=True, text=True)
    env.logger.info(result.stdout)

    if result.returncode != 0:
        env.logger.error(result.stderr)
        raise RuntimeError(f"Cleanup script failed with return code {result.returncode}")
    return result.returncode


def test_cleanup_functionality(setup_environment, env):
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
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


def test_cleanup_specific_archives(setup_environment, env, monkeypatch):
    """
    Verify that the cleanup script can delete multiple specific archives
    """
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)

    filename = "specific"
    with open(os.path.join(env.test_dir, 'backup.d', filename), 'w') as f:
            f.write("dummy")

    command = ['manager', '--create-db', '--log-level', 'debug', '--log-stdout', '--config-file', env.config_file]
    process = runner.run(command)
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

    monkeypatch.setenv('CLEANUP_TEST_DELETE_FULL', "yes")
    command = ['cleanup', '--test-mode', '--cleanup-specific-archives', f'specific_FULL_{date_100_days_ago} , specific_FULL_{date_20_days_ago}'  , '--config-file', env.config_file, '--verbose', '--log-level', 'debug', '--log-stdout']
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



def test_cleanup_multiple_specific_archives(setup_environment, env, monkeypatch):
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
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
    process = runner.run(command)
    if process.returncode != 0:
        stdout, stderr = process.stdout, process.stderr
        print(f"stdout: {stdout}")  
        print(f"stderr: {stderr}")  
        raise Exception(f"Command failed: {command}")


    monkeypatch.setenv('CLEANUP_TEST_DELETE_FULL', "yes")
    command = ['cleanup', '--test-mode', '--cleanup-specific-archives', f'specific_FULL_{date_100_days_ago}'  , '--config-file', env.config_file, '--log-level', 'debug', '--log-stdout']
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
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
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



def test_confirmation_no_stops_deleting_full(setup_environment, env, monkeypatch):
    """
    Verify that the cleanup script does not delete a FULL archive if the user does not confirm the deletion
    """
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
    test_files = {
            f'example_FULL_1970-01-01.1.dar': 'dummy'
        }

    for filename, content in test_files.items():
        with open(os.path.join(env.test_dir, 'backups', filename), 'w') as f:
            f.write(content)

    monkeypatch.setenv('CLEANUP_TEST_DELETE_FULL', "no")
    command = ['cleanup', '--test-mode', '--cleanup-specific-archives', 'example_FULL_1970-01-01', '--config-file', env.config_file, '--log-level', 'debug', '--log-stdout']
    env.logger.info(command)
    result = subprocess.run(command, text=True, capture_output=True, timeout=1)
    env.logger.info(result.stdout)

    assert "User did not answer 'yes' to confirm deletion of FULL archive: " in result.stdout, f"Expected confirmation message not found in stdout"
    assert result.returncode == 0, f"Cleanup script failed with return code {result.returncode}"
    assert os.path.exists(os.path.join(env.test_dir, 'backups', 'example_FULL_1970-01-01.1.dar')), f"File {os.path.join(env.test_dir, 'backups', 'example_FULL_1970-01-01.1.dar')} was deleted"


def test_confirmation_yes_deletes_full(setup_environment, env, monkeypatch):
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
    test_files = {
            f'example_FULL_1970-01-01.1.dar': 'dummy',
            f'example_FULL_1970-01-01.1.dar.par2': 'dummy',
        }

    for filename, content in test_files.items():
        with open(os.path.join(env.test_dir, 'backups', filename), 'w') as f:
            f.write(content)

    monkeypatch.setenv('CLEANUP_TEST_DELETE_FULL', "yes")
    command = ['cleanup', '--test-mode', '--cleanup-specific-archives', 'example_FULL_1970-01-01', '--config-file', env.config_file, '--log-level', 'debug', '--log-stdout']
    env.logger.info(command)
    result = subprocess.run(command, text=True, capture_output=True, timeout=1)
    env.logger.info(result.stdout)

    assert result.returncode == 0, f"Cleanup script failed to delete the FULL archive"
    for file in test_files:
        assert not os.path.exists(os.path.join(env.test_dir, 'backups', file)), f"File {os.path.join(env.test_dir, 'backups', file)} was not deleted"
    


def test_logs_warning_when_no_matching_archives(setup_environment, env, monkeypatch):
    """
    Ensure cleanup logs a message when no matching archives are found
    """
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
    monkeypatch.setenv('CLEANUP_TEST_DELETE_FULL', "yes")

    env.logger.info("No files will be created for this test.")

    command = [
        'cleanup',
        '--test-mode',
        '--cleanup-specific-archives',
        'nonexistent_FULL_2000-01-01',
        '--config-file', env.config_file,
        '--log-level', 'debug',
        '--log-stdout'
    ]

    result = subprocess.run(command, capture_output=True, text=True)

    output = result.stdout + result.stderr
    assert (
        "No .dar files matched the regex for deletion." in output
        and "No .par2 matched the regex for deletion." in output
    ), f"Expected messages not found in output:\n{output}"



def test_age_based_cleanup_runs_when_no_specific_archives_given(setup_environment, env):
    """
    Ensure the script doesn’t break and logs appropriately when --cleanup-specific-archives is not given.
    """
    command = [
        'cleanup',
        '--test-mode',
        '--config-file', env.config_file,
        '--log-level', 'debug',
        '--log-stdout'
    ]
    env.logger.info(f"Running: {' '.join(command)}")
    result = subprocess.run(command, capture_output=True, text=True)
    env.logger.info(result.stdout)

    assert result.returncode == 0  # Should not crash
    assert "No --cleanup-specific-archives provided" in result.stdout


def test_missing_cleanup_specific_archives_argument(setup_environment, env):
    """
    Ensure the script doesn’t break and logs appropriately when --cleanup-specific-archives is not given.
    """
    command = [
        'cleanup',
        '--test-mode',
        '--config-file', env.config_file,
        '--log-level', 'debug',
        '--log-stdout'
    ]
    result = subprocess.run(command, capture_output=True, text=True)

    assert result.returncode == 0
    assert (
    "No --cleanup-specific-archives provided" in result.stdout
)