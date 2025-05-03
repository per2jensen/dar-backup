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
from unittest.mock import MagicMock
from dar_backup.util import requirements
from typing import NamedTuple

import pytest
from dar_backup.cleanup import confirm_full_archive_deletion
from inputimeout import TimeoutOccurred


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




def test_confirmation_no_stops_deleting_full(monkeypatch, capsys):
    os.environ["CLEANUP_TEST_DELETE_FULL"] = "no"
    monkeypatch.setattr("sys.argv", ["cleanup", "--cleanup-specific-archives", "example_FULL_2024-01-01", "--test-mode"])
    monkeypatch.setattr("dar_backup.cleanup.delete_archive", lambda *a, **kw: pytest.fail("Should not delete FULL"))
    monkeypatch.setattr("dar_backup.cleanup.ConfigSettings", lambda x: MagicMock(backup_dir=".", config={}, logfile_location="/dev/null", backup_d_dir="."))
    
    from dar_backup import cleanup
    with pytest.raises(SystemExit):
        cleanup.main()

    captured = capsys.readouterr()
    assert "Simulated confirmation for FULL archive" in captured.out


def _test_confirmation_no_stops_deleting_full(setup_environment, env, monkeypatch):
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
    result = subprocess.run(command, text=True, capture_output=True, timeout=30)
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
    


def test_prereq_script_success(monkeypatch):
    config_settings = MagicMock()
    config_settings.config = {'PREREQ': {'check': 'echo "ok"'}}

    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_result.stdout = "all good"
    monkeypatch.setattr("subprocess.run", lambda *a, **kw: mock_result)

    # If no exception is raised, it's a pass
    requirements("PREREQ", config_settings)




def test_cleanup_confirmation_timeout(monkeypatch, caplog):
    monkeypatch.setattr("dar_backup.cleanup.inputimeout", lambda **kw: (_ for _ in ()).throw(TimeoutOccurred))

    result = confirm_full_archive_deletion("backup_FULL_2024-01-01", test_mode=False)

    assert result is False
    assert "Timeout waiting for confirmation" in caplog.text



import logging

def test_cleanup_confirmation_timeout(monkeypatch, caplog):
    monkeypatch.setattr("sys.argv", ["cleanup", "--cleanup-specific-archives", "example_FULL_2024-01-01"])

    # Simulate timeout during confirmation
    monkeypatch.setattr("dar_backup.cleanup.inputimeout", lambda **kwargs: (_ for _ in ()).throw(TimeoutOccurred))
    monkeypatch.setattr("dar_backup.cleanup.delete_archive", lambda *a, **kw: pytest.fail("Should not delete FULL"))

    monkeypatch.setattr("dar_backup.cleanup.ConfigSettings", lambda x: MagicMock(
        backup_dir=".", config={}, logfile_location="/dev/null", backup_d_dir="."
    ))

    # This is key: capture logs from this logger
    logger = logging.getLogger("main_logger")
    logger.setLevel(logging.INFO)
    monkeypatch.setattr("dar_backup.cleanup.setup_logging", lambda *a, **kw: logger)
    monkeypatch.setattr("dar_backup.cleanup.get_logger", lambda **kw: logger)

    monkeypatch.setattr("dar_backup.cleanup.CommandRunner", lambda *a, **kw: MagicMock(run=lambda x: MagicMock(returncode=0)))

    # Patch the logger in util module
    import dar_backup.util
    dar_backup.util.logger = logger

    with pytest.raises(SystemExit):
        from dar_backup import cleanup
        cleanup.main()

    assert "Timeout waiting for confirmation for FULL archive" in caplog.text


def test_cleanup_confirmation_keyboard_interrupt(monkeypatch, caplog):
    monkeypatch.setattr("sys.argv", ["cleanup", "--cleanup-specific-archives", "example_FULL_2024-01-01"])
    monkeypatch.setattr("dar_backup.cleanup.inputimeout", lambda **kw: (_ for _ in ()).throw(KeyboardInterrupt))
    monkeypatch.setattr("dar_backup.cleanup.delete_archive", lambda *a, **kw: pytest.fail("Should not delete FULL"))
    monkeypatch.setattr("dar_backup.cleanup.ConfigSettings", lambda x: MagicMock(
        backup_dir=".", config={}, logfile_location="/dev/null", backup_d_dir="."
    ))
    monkeypatch.setattr("dar_backup.cleanup.setup_logging", lambda *a, **kw: logging.getLogger("main_logger"))
    monkeypatch.setattr("dar_backup.cleanup.get_logger", lambda **kw: logging.getLogger("command_output_logger"))
    monkeypatch.setattr("dar_backup.cleanup.CommandRunner", lambda *a, **kw: MagicMock(run=lambda x: MagicMock(returncode=0)))

    # Patch the global logger used by `util.requirements`
    import dar_backup.util
    logger = logging.getLogger("main_logger")
    logger.setLevel(logging.DEBUG)
    dar_backup.util.logger = logger

    # Ensure caplog captures from the logger
    caplog.set_level(logging.INFO, logger="main_logger")

    with pytest.raises(SystemExit):
        from dar_backup import cleanup
        cleanup.main()

    assert "User interrupted confirmation for FULL archive" in caplog.text




from datetime import date

def test_cleanup_confirmation_none_response(monkeypatch, caplog):
    caplog.set_level(logging.INFO)

    today_str = date.today().strftime("%Y-%m-%d")
    archive_name = f"example_FULL_{today_str}"

    monkeypatch.setattr("sys.argv", ["cleanup", "--cleanup-specific-archives", archive_name])
    monkeypatch.setattr("dar_backup.cleanup.inputimeout", lambda **kw: None)
    monkeypatch.setattr("dar_backup.cleanup.delete_archive", lambda *a, **kw: pytest.fail("Should not delete FULL"))
    monkeypatch.setattr("dar_backup.cleanup.ConfigSettings", lambda x: MagicMock(
        backup_dir=".", config={}, logfile_location="/dev/null", backup_d_dir="."
    ))
    monkeypatch.setattr("dar_backup.cleanup.setup_logging", lambda *a, **kw: logging.getLogger("main_logger"))
    monkeypatch.setattr("dar_backup.cleanup.get_logger", lambda **kw: logging.getLogger("command_output_logger"))
    monkeypatch.setattr("dar_backup.cleanup.CommandRunner", lambda *a, **kw: MagicMock(run=lambda x: MagicMock(returncode=0)))

    import dar_backup.util
    dar_backup.util.logger = logging.getLogger("main_logger")

    with pytest.raises(SystemExit):
        from dar_backup import cleanup
        cleanup.main()

    assert f"No confirmation received for FULL archive: {archive_name}" in caplog.text


def test_show_version_flag_exits(monkeypatch):
    monkeypatch.setattr("sys.argv", ["cleanup", "--version"])
    with pytest.raises(SystemExit):
        from dar_backup import cleanup
        cleanup.main()


def test_invalid_date_in_filename(monkeypatch, tmp_path, env):
    backups = tmp_path / "backups"
    backups.mkdir()
    bad_file = backups / "example_DIFF_invalid-date.1.dar"
    bad_file.write_text("dummy")

    config_settings = MagicMock()
    config_settings.backup_dir = str(backups)
    config_settings.diff_age = 30
    config_settings.incr_age = 30
    config_settings.config = {}

    monkeypatch.setattr("dar_backup.cleanup.logger", env.logger)

    from dar_backup.cleanup import delete_old_backups

    with pytest.raises(Exception) as exc_info:
        delete_old_backups(str(backups), config_settings.diff_age, "DIFF", args=MagicMock(), backup_definition="example")

    # ✅ Match the actual ValueError message raised by datetime.strptime()
    assert "does not match format '%Y-%m-%d'" in str(exc_info.value)

def test_delete_file_permission_error(monkeypatch, tmp_path):
    backups = tmp_path / "backups"
    backups.mkdir()
    filename = backups / f"example_DIFF_{date_100_days_ago}.1.dar"
    filename.write_text("dummy")

    # Simulate os.remove throwing an exception
    monkeypatch.setattr("os.remove", lambda path: (_ for _ in ()).throw(PermissionError("Mock permission denied")))

    monkeypatch.setattr("dar_backup.cleanup.delete_catalog", lambda *a, **kw: True)
    monkeypatch.setattr("dar_backup.cleanup.logger", logging.getLogger("test"))

    from dar_backup.cleanup import delete_old_backups
    delete_old_backups(str(backups), 30, "DIFF", args=MagicMock(), backup_definition="example")



def test_delete_catalog_failure(monkeypatch):
    monkeypatch.setattr("dar_backup.cleanup.logger", logging.getLogger("test"))
    monkeypatch.setattr("dar_backup.cleanup.runner", MagicMock(run=lambda x: MagicMock(returncode=1, stderr="Failure")))

    from dar_backup.cleanup import delete_catalog
    result = delete_catalog("bad_catalog", args=MagicMock(config_file="/dev/null"))
    assert result is False


def test_invalid_backup_type(monkeypatch, tmp_path):
    backup_dir = tmp_path / "backups"
    backup_dir.mkdir()

    monkeypatch.setattr("dar_backup.cleanup.logger", logging.getLogger("test"))
    from dar_backup.cleanup import delete_old_backups
    # Should log error and return early
    delete_old_backups(str(backup_dir), 30, "INVALID_TYPE", args=MagicMock())




def test_postreq_script_success(monkeypatch, env, caplog):
    config_settings = MagicMock()
    config_settings.config = {'POSTREQ': {'check': 'echo "post check ok"'}}

    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_result.stdout = "post check ok"
    mock_result.stderr = ""
    monkeypatch.setattr("subprocess.run", lambda *a, **kw: mock_result)

    # Use the env's logger to patch util.logger
    import dar_backup.util
    monkeypatch.setattr(dar_backup.util, "logger", env.logger)

    caplog.set_level(logging.DEBUG)

    from dar_backup.util import requirements
    requirements("POSTREQ", config_settings)

    assert "post check ok" in caplog.text or "POSTREQ" in caplog.text


def test_postreq_script_failure(monkeypatch, env, caplog):
    config_settings = MagicMock()
    config_settings.config = {'POSTREQ': {'check': 'exit 1'}}

    mock_result = MagicMock()
    mock_result.returncode = 1
    mock_result.stdout = ""
    mock_result.stderr = "mocked failure"
    monkeypatch.setattr("subprocess.run", lambda *a, **kw: mock_result)

    import dar_backup.util
    monkeypatch.setattr(dar_backup.util, "logger", env.logger)

    caplog.set_level(logging.DEBUG)

    from dar_backup.util import requirements

    with pytest.raises(RuntimeError) as exc_info:
        requirements("POSTREQ", config_settings)

    assert "POSTREQ check: 'exit 1' failed" in str(exc_info.value)
    assert "mocked failure" in caplog.text


import pytest
from types import SimpleNamespace
from unittest.mock import patch
from dar_backup.cleanup import delete_catalog

def test_cleanup_invalid_symlink(tmp_path):
    broken_link = tmp_path / "broken_symlink"
    broken_link.symlink_to("/nonexistent/target")

    dummy_args = SimpleNamespace(config_file=str(tmp_path / "dummy.conf"))

    with patch("dar_backup.cleanup.runner") as mock_runner, \
         patch("dar_backup.cleanup.logger") as mock_logger:
        mock_runner.run.return_value = SimpleNamespace(returncode=2, stdout="", stderr="")
        result = delete_catalog("example", dummy_args)

        assert result is True
        mock_logger.warning.assert_called_once_with("catalog 'example' not found in the database, skipping deletion")

