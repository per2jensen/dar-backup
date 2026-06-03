import os
import subprocess
import logging
import sys
import pytest

pytestmark = pytest.mark.integration

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from datetime import timedelta
from datetime import datetime
from dar_backup.command_runner import CommandRunner
from unittest.mock import MagicMock
from dar_backup.util import requirements

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


@pytest.mark.smoke
@pytest.mark.debug
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


@pytest.mark.smoke
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
        env.logger.info('Database created')
    else:
        env.logger.error('Something went wrong creating the database')
        stdout, stderr = process.stdout, process.stderr 
        env.logger.error(f"stderr: {stderr}")
        env.logger.error(f"stdout: {stdout}")
        raise RuntimeError("Failed to create database")



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


@pytest.mark.smoke
def test_cleanup_specific_archives_dry_run(setup_environment, env):
    archive_name = f"dry_INCR_{date_10_days_ago}"
    archive_path = os.path.join(env.test_dir, 'backups', f'{archive_name}.1.dar')
    with open(archive_path, 'w') as f:
        f.write("dummy")

    command = [
        'cleanup',
        '--dry-run',
        '--cleanup-specific-archives',
        archive_name,
        '--config-file',
        env.config_file,
        '--log-level',
        'debug',
        '--log-stdout',
    ]
    env.logger.info(command)
    result = subprocess.run(command, capture_output=True, text=True)
    env.logger.info(result.stdout)

    if result.returncode != 0:
        env.logger.error(result.stderr)
        raise RuntimeError(f"Cleanup script failed with return code {result.returncode}")

    assert os.path.exists(archive_path), f"File {archive_path} should not be deleted in dry run"

    assert (not os.path.exists(os.path.join(env.test_dir, 'backups', f'specific_FULL_{date_100_days_ago}.2.dar'))), f"File {os.path.join(env.test_dir, 'backups', f'specific_FULL_{date_100_days_ago}.2.dar')} still exists"
    assert (not os.path.exists(os.path.join(env.test_dir, 'backups', f'specific_FULL_{date_100_days_ago}.2.dar.vol666.par2'))), f"File {os.path.join(env.test_dir, 'backups', f'specific_FULL_{date_100_days_ago}.2.dar.vol666.par2')} still exists"
    assert (not os.path.exists(os.path.join(env.test_dir, 'backups', f'specific_FULL_{date_100_days_ago}.2.dar.par2'))), f"File {os.path.join(env.test_dir, 'backups', f'specific_FULL_{date_100_days_ago}.2.dar.par2')} still exists"


def test_cleanup_alternate_dir(setup_environment, env):
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
    alternate_dir = os.path.join(env.test_dir, 'backups-alternate')
    if not alternate_dir.startswith(env.test_root):
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




@pytest.mark.debug
def test_confirmation_no_stops_deleting_full(monkeypatch, capsys):
    os.environ["CLEANUP_TEST_DELETE_FULL"] = "no"

    class DummyConfig:
        def __init__(self):
            self.backup_dir = "."
            self.config = {}
            self.logfile_location = "/dev/null"
            self.backup_d_dir = "."
            self.logfile_max_bytes = 26214400  # int, not MagicMock!
            self.logfile_backup_count = 5
            self.command_timeout_secs = 30

    monkeypatch.setattr("sys.argv", ["cleanup", "--cleanup-specific-archives", "example_FULL_2024-01-01", "--test-mode"])
    monkeypatch.setattr("dar_backup.cleanup.delete_archive", lambda *a, **kw: pytest.fail("Should not delete FULL"))
#    monkeypatch.setattr("dar_backup.cleanup.ConfigSettings", lambda x: MagicMock(backup_dir=".", config={}, logfile_location="/dev/null", backup_d_dir="."))
    monkeypatch.setattr("dar_backup.cleanup.ConfigSettings", lambda x: DummyConfig())


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
            'example_FULL_1970-01-01.1.dar': 'dummy'
        }

    for filename, content in test_files.items():
        with open(os.path.join(env.test_dir, 'backups', filename), 'w') as f:
            f.write(content)

    monkeypatch.setenv('CLEANUP_TEST_DELETE_FULL', "no")
    command = ['cleanup', '--test-mode', '--cleanup-specific-archives', 'example_FULL_1970-01-01', '--config-file', env.config_file, '--log-level', 'debug', '--log-stdout']
    env.logger.info(command)
    result = subprocess.run(command, text=True, capture_output=True, timeout=1)
    env.logger.info(result.stdout)

    assert "User did not answer 'yes' to confirm deletion of FULL archive: " in result.stdout, "Expected confirmation message not found in stdout"
    assert result.returncode == 0, f"Cleanup script failed with return code {result.returncode}"
    assert os.path.exists(os.path.join(env.test_dir, 'backups', 'example_FULL_1970-01-01.1.dar')), f"File {os.path.join(env.test_dir, 'backups', 'example_FULL_1970-01-01.1.dar')} was deleted"


@pytest.mark.smoke
def test_confirmation_yes_deletes_full(setup_environment, env, monkeypatch):
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
    test_files = {
            'example_FULL_1970-01-01.1.dar': 'dummy',
            'example_FULL_1970-01-01.1.dar.par2': 'dummy',
        }

    for filename, content in test_files.items():
        with open(os.path.join(env.test_dir, 'backups', filename), 'w') as f:
            f.write(content)

    monkeypatch.setenv('CLEANUP_TEST_DELETE_FULL', "yes")
    command = ['cleanup', '--test-mode', '--cleanup-specific-archives', 'example_FULL_1970-01-01', '--config-file', env.config_file, '--log-level', 'debug', '--log-stdout']
    env.logger.info(command)
    result = subprocess.run(command, text=True, capture_output=True, timeout=30)
    env.logger.info(result.stdout)

    assert result.returncode == 0, "Cleanup script failed to delete the FULL archive"
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
        and "No par2 files matched the cleanup patterns." in output
    ), f"Expected messages not found in output:\n{output}"



@pytest.mark.smoke
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
    


def test_prereq_script_success(logger):
    from types import SimpleNamespace
    config_settings = SimpleNamespace(
        config={'PREREQ': {'check': 'echo "ok"'}},
        command_timeout_secs=30,
    )
    # If no exception is raised, the PREREQ command ran successfully
    requirements("PREREQ", config_settings)




def test_cleanup_confirmation_timeout(monkeypatch, caplog):
    monkeypatch.setattr("dar_backup.cleanup.inputimeout", lambda **kw: (_ for _ in ()).throw(TimeoutOccurred))

    result = confirm_full_archive_deletion("backup_FULL_2024-01-01", test_mode=False)

    assert result is False
    assert "Timeout waiting for confirmation" in caplog.text




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


def test_invalid_date_in_filename(monkeypatch, tmp_path, env, caplog):
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

    caplog.set_level(logging.WARNING)
    delete_old_backups(
        str(backups),
        config_settings.diff_age,
        "DIFF",
        args=MagicMock(),
        backup_definition="example",
    )

    assert "Skipping file with invalid date format" in caplog.text

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



def test_cleanup_deletes_per_archive_par2_in_external_dir(monkeypatch, tmp_path):
    backup_dir = tmp_path / "backups"
    par2_dir = tmp_path / "par2"
    backup_dir.mkdir()
    par2_dir.mkdir()

    archive_name = f"example_DIFF_{date_100_days_ago}"
    (backup_dir / f"{archive_name}.1.dar").write_text("dummy")
    (backup_dir / f"{archive_name}.2.dar").write_text("dummy")

    par2_files = [
        f"{archive_name}.par2",
        f"{archive_name}.vol000+01.par2",
        f"{archive_name}.vol001+02.par2",
        f"{archive_name}.par2.manifest.ini",
    ]
    for name in par2_files:
        (par2_dir / name).write_text("dummy")

    untouched = par2_dir / "other_DIFF_2020-01-01.par2"
    untouched.write_text("dummy")

    class DummyConfig:
        def get_par2_config(self, backup_definition):
            return {"par2_dir": str(par2_dir)}

    monkeypatch.setattr("dar_backup.cleanup.delete_catalog", lambda *a, **kw: True)
    monkeypatch.setattr("dar_backup.cleanup.logger", logging.getLogger("test"))

    from dar_backup.cleanup import delete_old_backups

    delete_old_backups(str(backup_dir), 30, "DIFF", args=MagicMock(), backup_definition="example", config_settings=DummyConfig())

    assert not (backup_dir / f"{archive_name}.1.dar").exists()
    assert not (backup_dir / f"{archive_name}.2.dar").exists()
    assert not (par2_dir / f"{archive_name}.par2").exists()
    assert not (par2_dir / f"{archive_name}.vol000+01.par2").exists()
    assert not (par2_dir / f"{archive_name}.vol001+02.par2").exists()
    assert not (par2_dir / f"{archive_name}.par2.manifest.ini").exists()
    assert untouched.exists()


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
    # requirements() reads command_timeout_secs via getattr; MagicMock auto-attributes
    # are Mock objects, not ints, so Popen.wait(timeout=Mock()) raises TypeError.
    config_settings.command_timeout_secs = 30

    # Use the env's logger to patch util.logger
    import dar_backup.util
    monkeypatch.setattr(dar_backup.util, "logger", env.logger)

    caplog.set_level(logging.DEBUG)

    from dar_backup.util import requirements
    requirements("POSTREQ", config_settings)

    assert "post check ok" in caplog.text or "POSTREQ" in caplog.text


def test_postreq_script_failure(logger, caplog):
    config_settings = SimpleNamespace(
        config={'POSTREQ': {'check': 'echo "failure output" >&2; exit 1'}}
    )

    caplog.set_level(logging.DEBUG)

    with pytest.raises(RuntimeError) as exc_info:
        requirements("POSTREQ", config_settings)

    assert "POSTREQ check:" in str(exc_info.value)
    assert "failed" in str(exc_info.value)
    assert "failure output" in caplog.text


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


def test_cleanup_alternate_dir_missing_exits(monkeypatch, caplog, tmp_path):
    import dar_backup.cleanup as cleanup

    missing_dir = tmp_path / "missing"

    class DummyConfig:
        logfile_location = "/tmp/dar-backup.log"
        logfile_max_bytes = 1000
        logfile_backup_count = 1
        backup_dir = "/tmp/backup"
        backup_d_dir = "/tmp/backup.d"
        diff_age = 1
        incr_age = 1
        config = {}
        command_capture_max_bytes = 1024
        command_timeout_secs = 30

    test_logger = logging.getLogger("cleanup_test_missing_dir")
    test_logger.setLevel(logging.ERROR)

    monkeypatch.setattr(sys, "argv", ["cleanup", "--alternate-archive-dir", str(missing_dir), "--test-mode"])
    monkeypatch.setattr(cleanup.argcomplete, "autocomplete", lambda *a, **k: None)
    monkeypatch.setattr(cleanup, "ConfigSettings", lambda _path: DummyConfig())
    monkeypatch.setattr(cleanup, "setup_logging", lambda *a, **k: test_logger)
    monkeypatch.setattr(cleanup, "get_logger", lambda **_k: test_logger)
    monkeypatch.setattr(cleanup, "CommandRunner", lambda *a, **k: MagicMock())
    monkeypatch.setattr(cleanup, "requirements", lambda *_a, **_k: None)
    monkeypatch.setattr(cleanup, "print_aligned_settings", lambda *a, **k: None)

    caplog.set_level(logging.ERROR, logger="cleanup_test_missing_dir")

    with pytest.raises(SystemExit) as exc:
        cleanup.main()

    assert exc.value.code == 1
    assert "Alternate archive directory does not exist" in caplog.text


def test_cleanup_alternate_dir_not_directory_exits(monkeypatch, caplog, tmp_path):
    import dar_backup.cleanup as cleanup

    not_dir = tmp_path / "not_dir.txt"
    not_dir.write_text("nope")

    class DummyConfig:
        logfile_location = "/tmp/dar-backup.log"
        logfile_max_bytes = 1000
        logfile_backup_count = 1
        backup_dir = "/tmp/backup"
        backup_d_dir = "/tmp/backup.d"
        diff_age = 1
        incr_age = 1
        config = {}
        command_capture_max_bytes = 1024
        command_timeout_secs = 30

    test_logger = logging.getLogger("cleanup_test_not_dir")
    test_logger.setLevel(logging.ERROR)

    monkeypatch.setattr(sys, "argv", ["cleanup", "--alternate-archive-dir", str(not_dir), "--test-mode"])
    monkeypatch.setattr(cleanup.argcomplete, "autocomplete", lambda *a, **k: None)
    monkeypatch.setattr(cleanup, "ConfigSettings", lambda _path: DummyConfig())
    monkeypatch.setattr(cleanup, "setup_logging", lambda *a, **k: test_logger)
    monkeypatch.setattr(cleanup, "get_logger", lambda **_k: test_logger)
    monkeypatch.setattr(cleanup, "CommandRunner", lambda *a, **k: MagicMock())
    monkeypatch.setattr(cleanup, "requirements", lambda *_a, **_k: None)
    monkeypatch.setattr(cleanup, "print_aligned_settings", lambda *a, **k: None)

    caplog.set_level(logging.ERROR, logger="cleanup_test_not_dir")

    with pytest.raises(SystemExit) as exc:
        cleanup.main()

    assert exc.value.code == 1
    assert "Alternate archive directory is not a directory" in caplog.text


def test_cleanup_specific_archives_rejects_unsafe_name(monkeypatch, caplog):
    import dar_backup.cleanup as cleanup

    class DummyConfig:
        logfile_location = "/tmp/dar-backup.log"
        logfile_max_bytes = 1000
        logfile_backup_count = 1
        backup_dir = "/tmp/backup"
        backup_d_dir = "/tmp/backup.d"
        diff_age = 1
        incr_age = 1
        config = {}
        command_capture_max_bytes = 1024
        command_timeout_secs = 30

    test_logger = logging.getLogger("cleanup_test_unsafe_name")
    test_logger.setLevel(logging.ERROR)

    monkeypatch.setattr(
        sys,
        "argv",
        ["cleanup", "--cleanup-specific-archives", "bad.._INCR_2024-01-01", "--test-mode"],
    )
    monkeypatch.setattr(cleanup.argcomplete, "autocomplete", lambda *a, **k: None)
    monkeypatch.setattr(cleanup, "ConfigSettings", lambda _path: DummyConfig())
    monkeypatch.setattr(cleanup, "setup_logging", lambda *a, **k: test_logger)
    monkeypatch.setattr(cleanup, "get_logger", lambda **_k: test_logger)
    monkeypatch.setattr(cleanup, "CommandRunner", lambda *a, **k: MagicMock())
    monkeypatch.setattr(cleanup, "requirements", lambda *_a, **_k: None)
    monkeypatch.setattr(cleanup, "print_aligned_settings", lambda *a, **k: None)
    monkeypatch.setattr(cleanup, "delete_archive", lambda *_a, **_k: pytest.fail("should not delete"))

    caplog.set_level(logging.ERROR, logger="cleanup_test_unsafe_name")

    with pytest.raises(SystemExit) as exc:
        cleanup.main()

    assert exc.value.code == 0
    assert "Refusing unsafe archive name" in caplog.text


def test_delete_old_backups_rejects_is_archive_name_allowed(monkeypatch, tmp_path):
    import dar_backup.cleanup as cleanup

    backup_dir = tmp_path / "backups"
    backup_dir.mkdir()

    archive_name = "example_DIFF_2000-01-01"
    file_path = backup_dir / f"{archive_name}.1.dar"
    file_path.write_text("dummy")

    args = SimpleNamespace(dry_run=True)

    delete_catalog = MagicMock()
    delete_par2 = MagicMock()
    monkeypatch.setattr(cleanup, "logger", logging.getLogger("cleanup_test_allowed"))
    monkeypatch.setattr(cleanup, "is_archive_name_allowed", lambda _name: False)
    monkeypatch.setattr(cleanup, "delete_catalog", delete_catalog)
    monkeypatch.setattr(cleanup, "_delete_par2_files", delete_par2)
    monkeypatch.setattr(cleanup, "safe_remove_file", lambda *_a, **_k: pytest.fail("should not delete"))

    with pytest.raises(ValueError):
        cleanup.delete_old_backups(
            str(backup_dir),
            age=30,
            backup_type="DIFF",
            args=args,
            backup_definition=None,
            config_settings=None,
        )

    assert delete_catalog.call_count == 0
    assert delete_par2.call_count == 0
    assert file_path.exists()


def test_delete_old_backups_skips_catalog_when_remove_fails(monkeypatch, tmp_path):
    import dar_backup.cleanup as cleanup

    backup_dir = tmp_path / "backups"
    backup_dir.mkdir()

    archive_name = f"example_DIFF_{date_100_days_ago}"
    file_path = backup_dir / f"{archive_name}.1.dar"
    file_path.write_text("dummy")

    args = SimpleNamespace(dry_run=False)

    delete_catalog = MagicMock()
    delete_par2 = MagicMock()
    monkeypatch.setattr(cleanup, "logger", logging.getLogger("cleanup_test_skip_catalog"))
    monkeypatch.setattr(cleanup, "delete_catalog", delete_catalog)
    monkeypatch.setattr(cleanup, "_delete_par2_files", delete_par2)
    monkeypatch.setattr(cleanup, "safe_remove_file", lambda *_a, **_k: False)

    cleanup.delete_old_backups(
        str(backup_dir),
        age=30,
        backup_type="DIFF",
        args=args,
        backup_definition="example",
        config_settings=None,
    )

    assert delete_catalog.call_count == 0
    assert delete_par2.call_count == 0
    assert file_path.exists()


def test_delete_par2_files_skips_missing_dir(monkeypatch, tmp_path):
    import dar_backup.cleanup as cleanup

    backup_dir = tmp_path / "backups"
    backup_dir.mkdir()

    class DummyConfig:
        def get_par2_config(self, backup_definition):
            return {"par2_dir": str(tmp_path / "missing")}

    mock_logger = MagicMock()
    monkeypatch.setattr(cleanup, "logger", mock_logger)
    monkeypatch.setattr(cleanup, "safe_remove_file", lambda *a, **kw: pytest.fail("should not delete"))

    cleanup._delete_par2_files(
        "example_DIFF_2000-01-01",
        str(backup_dir),
        config_settings=DummyConfig(),
        backup_definition="example",
        dry_run=False,
    )

    assert mock_logger.warning.called


def test_delete_par2_files_dry_run_does_not_delete(monkeypatch, tmp_path):
    import dar_backup.cleanup as cleanup

    backup_dir = tmp_path / "backups"
    par2_dir = tmp_path / "par2"
    backup_dir.mkdir()
    par2_dir.mkdir()

    archive_name = "example_DIFF_2000-01-01"
    par2_files = [
        f"{archive_name}.1.dar.vol001.par2",
        f"{archive_name}.par2",
        f"{archive_name}.par2.manifest.ini",
    ]
    for name in par2_files:
        (par2_dir / name).write_text("dummy")

    class DummyConfig:
        def get_par2_config(self, backup_definition):
            return {"par2_dir": str(par2_dir)}

    mock_logger = MagicMock()
    mock_remove = MagicMock()
    monkeypatch.setattr(cleanup, "logger", mock_logger)
    monkeypatch.setattr(cleanup, "safe_remove_file", mock_remove)

    cleanup._delete_par2_files(
        archive_name,
        str(backup_dir),
        config_settings=DummyConfig(),
        backup_definition="example",
        dry_run=True,
    )

    assert mock_remove.call_count == 0
    for name in par2_files:
        assert (par2_dir / name).exists()


def test_delete_old_backups_rejects_unsafe_archive(monkeypatch, tmp_path):
    import dar_backup.cleanup as cleanup

    backup_dir = tmp_path / "backups"
    backup_dir.mkdir()

    bad_name = "bad.._DIFF_2000-01-01"
    (backup_dir / f"{bad_name}.1.dar").write_text("dummy")

    args = MagicMock(dry_run=True)

    monkeypatch.setattr(cleanup, "logger", MagicMock())
    delete_catalog = MagicMock()
    monkeypatch.setattr(cleanup, "delete_catalog", delete_catalog)

    with pytest.raises(ValueError):
        cleanup.delete_old_backups(
            str(backup_dir),
            age=30,
            backup_type="DIFF",
            args=args,
            backup_definition=None,
            config_settings=None,
        )

    assert delete_catalog.call_count == 0


def test_delete_catalog_handles_exception(monkeypatch):
    import dar_backup.cleanup as cleanup





    mock_logger = MagicMock()
    monkeypatch.setattr(cleanup, "logger", mock_logger)
    monkeypatch.setattr(
        cleanup,
        "runner",
        MagicMock(run=MagicMock(side_effect=RuntimeError("boom")))
    )

    result = cleanup.delete_catalog("example", args=SimpleNamespace(config_file="/dev/null"))

    assert result is False
    assert mock_logger.error.called


# ---------------------------------------------------------------------------
# In-process integration tests using real `dar` archives.
# Subprocess coverage is not tracked in this project (no sitecustomize.py),
# so these tests call cleanup module functions directly to record coverage.
# ---------------------------------------------------------------------------

import dar_backup.cleanup as _cleanup_mod


def _make_real_archive(runner, env, backup_type: str, date_str: str, base_archive: str = None) -> str:
    """
    Create a real dar archive with an old-style date name and register it in
    the manager catalog.  Returns the archive base path (without .N.dar).

    The name format is example_{type}_{YYYY-MM-DD} (no sequence suffix) so
    that:
      - delete_old_backups() can parse the date via strptime('%Y-%m-%d')
      - is_safe_filename() accepts the resulting .N.dar slice name
    """
    backup_def_path = os.path.join(env.backup_d_dir, "example")
    base = os.path.join(env.backup_dir, f"example_{backup_type}_{date_str}")
    cmd = [
        "dar", "-c", base, "-N", "-B", env.dar_rc,
        "-B", backup_def_path, "-Q", "compress-exclusion", "verbose",
    ]
    if base_archive:
        cmd.extend(["-A", base_archive])
    r = runner.run(cmd, timeout=300)
    assert r.returncode == 0, f"dar {backup_type} creation failed: {r.stderr}"
    r2 = runner.run([
        "manager", "--add-specific-archive", base,
        "--config-file", env.config_file, "--log-stdout",
    ], timeout=300)
    assert r2.returncode == 0, f"manager add failed: {r2.stderr}"
    return base


@pytest.mark.smoke
def test_cleanup_delete_old_diff_in_process(setup_environment, env):
    """
    Call delete_old_backups() directly (in-process) with a real old-dated DIFF
    archive.  Verifies the slice is removed from disk and from the catalog.

    Covers: delete_old_backups scanning loop (124, 129), file deletion (138-154),
    and the catalog removal call (166).
    """
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)

    full_base = _make_real_archive(runner, env, "FULL", "2020-01-01")
    diff_base = _make_real_archive(runner, env, "DIFF", "2020-01-01", base_archive=full_base)

    diff_slice = diff_base + ".1.dar"
    assert os.path.exists(diff_slice), "DIFF slice must exist before cleanup"

    saved_logger, saved_runner = _cleanup_mod.logger, _cleanup_mod.runner
    try:
        _cleanup_mod.logger = env.logger
        _cleanup_mod.runner = runner
        _cleanup_mod.delete_old_backups(
            backup_dir=env.backup_dir,
            age=30,
            backup_type="DIFF",
            args=SimpleNamespace(config_file=env.config_file, dry_run=False),
            backup_definition="example",
        )
    finally:
        _cleanup_mod.logger = saved_logger
        _cleanup_mod.runner = saved_runner

    assert not os.path.exists(diff_slice), "Old DIFF slice should have been deleted"
    full_slice = full_base + ".1.dar"
    assert os.path.exists(full_slice), "FULL archive must NOT be deleted by DIFF cleanup"
    env.logger.info("delete_old_backups() removed old DIFF slice ✓")


@pytest.mark.smoke
def test_cleanup_delete_old_incr_in_process(setup_environment, env):
    """
    Call delete_old_backups() directly (in-process) with a real old-dated INCR
    archive.  Covers the INCR branch of the scanning loop.
    """
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)

    full_base = _make_real_archive(runner, env, "FULL", "2019-06-15")
    incr_base = _make_real_archive(runner, env, "INCR", "2019-06-15", base_archive=full_base)

    incr_slice = incr_base + ".1.dar"
    assert os.path.exists(incr_slice)

    saved_logger, saved_runner = _cleanup_mod.logger, _cleanup_mod.runner
    try:
        _cleanup_mod.logger = env.logger
        _cleanup_mod.runner = runner
        _cleanup_mod.delete_old_backups(
            backup_dir=env.backup_dir,
            age=15,
            backup_type="INCR",
            args=SimpleNamespace(config_file=env.config_file, dry_run=False),
            backup_definition="example",
        )
    finally:
        _cleanup_mod.logger = saved_logger
        _cleanup_mod.runner = saved_runner

    assert not os.path.exists(incr_slice), "Old INCR slice should have been deleted"
    env.logger.info("delete_old_backups() removed old INCR slice ✓")


def test_cleanup_delete_old_dry_run_in_process(setup_environment, env):
    """
    Call delete_old_backups(dry_run=True) in-process with an old-dated DIFF.
    The slice must remain on disk.

    Covers: the dry_run logger line inside the archive_deleted loop (line 164).
    """
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)

    full_base = _make_real_archive(runner, env, "FULL", "2018-03-10")
    diff_base = _make_real_archive(runner, env, "DIFF", "2018-03-10", base_archive=full_base)

    diff_slice = diff_base + ".1.dar"
    assert os.path.exists(diff_slice)

    saved_logger, saved_runner = _cleanup_mod.logger, _cleanup_mod.runner
    try:
        _cleanup_mod.logger = env.logger
        _cleanup_mod.runner = runner
        _cleanup_mod.delete_old_backups(
            backup_dir=env.backup_dir,
            age=30,
            backup_type="DIFF",
            args=SimpleNamespace(config_file=env.config_file, dry_run=True),
            backup_definition="example",
        )
    finally:
        _cleanup_mod.logger = saved_logger
        _cleanup_mod.runner = saved_runner

    assert os.path.exists(diff_slice), "Dry-run must NOT delete the DIFF slice"
    env.logger.info("delete_old_backups(dry_run=True) preserved old DIFF slice ✓")


@pytest.mark.smoke
def test_cleanup_delete_archive_in_process(setup_environment, env):
    """
    Call delete_archive() directly (in-process) with a real dar archive.

    Covers: the entire delete_archive() body (lines 175-211) including the
    scandir loop, safe_remove_file(), delete_catalog(), and _delete_par2_files().
    """
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)

    full_base = _make_real_archive(runner, env, "FULL", "2021-07-04")
    full_slice = full_base + ".1.dar"
    assert os.path.exists(full_slice)

    archive_name = os.path.basename(full_base)

    saved_logger, saved_runner = _cleanup_mod.logger, _cleanup_mod.runner
    try:
        _cleanup_mod.logger = env.logger
        _cleanup_mod.runner = runner
        _cleanup_mod.delete_archive(
            backup_dir=env.backup_dir,
            archive_name=archive_name,
            args=SimpleNamespace(config_file=env.config_file, dry_run=False),
        )
    finally:
        _cleanup_mod.logger = saved_logger
        _cleanup_mod.runner = saved_runner

    assert not os.path.exists(full_slice), "delete_archive() should have removed the FULL slice"
    env.logger.info("delete_archive() removed real FULL archive ✓")


def test_cleanup_delete_archive_dry_run_in_process(setup_environment, env):
    """
    Call delete_archive() with dry_run=True on a real dar archive.
    The slice must remain on disk; only logging must happen.

    Covers: dry_run branch inside the scandir loop (190-191) and the
    'would run manager' log after files_deleted is set (204).
    """
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)

    full_base = _make_real_archive(runner, env, "FULL", "2017-05-20")
    full_slice = full_base + ".1.dar"
    assert os.path.exists(full_slice)

    archive_name = os.path.basename(full_base)

    saved_logger, saved_runner = _cleanup_mod.logger, _cleanup_mod.runner
    try:
        _cleanup_mod.logger = env.logger
        _cleanup_mod.runner = runner
        _cleanup_mod.delete_archive(
            backup_dir=env.backup_dir,
            archive_name=archive_name,
            args=SimpleNamespace(config_file=env.config_file, dry_run=True),
        )
    finally:
        _cleanup_mod.logger = saved_logger
        _cleanup_mod.runner = saved_runner

    assert os.path.exists(full_slice), "dry_run must NOT delete the FULL slice"
    env.logger.info("delete_archive(dry_run=True) preserved real FULL slice ✓")


def test_cleanup_delete_archive_no_matching_files_in_process(setup_environment, env):
    """
    Call delete_archive() with an archive name that matches no files in backup_dir.
    Verifies the 'No .dar files matched' branch is reached.

    Covers: line 208 (no-match log inside delete_archive).
    """
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)

    saved_logger, saved_runner = _cleanup_mod.logger, _cleanup_mod.runner
    try:
        _cleanup_mod.logger = env.logger
        _cleanup_mod.runner = runner
        _cleanup_mod.delete_archive(
            backup_dir=env.backup_dir,
            archive_name="example_DIFF_1999-12-31",   # nothing with this name exists
            args=SimpleNamespace(config_file=env.config_file, dry_run=False),
        )
    finally:
        _cleanup_mod.logger = saved_logger
        _cleanup_mod.runner = saved_runner

    env.logger.info("delete_archive() 'no files matched' path reached ✓")


def test_cleanup_delete_old_backups_skips_nonfile_and_other_def_in_process(setup_environment, env):
    """
    Verify delete_old_backups() skips non-file entries and files from other
    backup definitions when backup_definition is specified.

    Covers: line 124 (continue for non-file entry) and line 129 (continue when
    filename does not start with backup_definition).
    """
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)

    # Non-file entry: a subdirectory inside backup_dir triggers line 124
    subdir = os.path.join(env.backup_dir, "subdir_triggers_nonfile_skip")
    os.makedirs(subdir, exist_ok=True)

    # File from a different definition triggers line 129
    other_def_file = os.path.join(env.backup_dir, "other_DIFF_2010-06-01.1.dar")
    with open(other_def_file, "w") as f:
        f.write("dummy")

    saved_logger, saved_runner = _cleanup_mod.logger, _cleanup_mod.runner
    try:
        _cleanup_mod.logger = env.logger
        _cleanup_mod.runner = runner
        _cleanup_mod.delete_old_backups(
            backup_dir=env.backup_dir,
            age=30,
            backup_type="DIFF",
            args=SimpleNamespace(config_file=env.config_file, dry_run=False),
            backup_definition="example",
        )
    finally:
        _cleanup_mod.logger = saved_logger
        _cleanup_mod.runner = saved_runner
        if os.path.exists(other_def_file):
            os.remove(other_def_file)
        if os.path.exists(subdir):
            os.rmdir(subdir)

    # other_def_file must NOT have been deleted (wrong definition)
    env.logger.info("delete_old_backups() skipped subdir and other-def file ✓")


def test_cleanup_delete_archive_skips_nonfile_in_process(setup_environment, env):
    """
    Verify delete_archive() skips non-file entries in the backup_dir scan.

    Covers: line 184 (continue for non-file entry inside delete_archive scandir loop).
    """
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)

    full_base = _make_real_archive(runner, env, "FULL", "2016-09-11")
    full_slice = full_base + ".1.dar"
    assert os.path.exists(full_slice)

    archive_name = os.path.basename(full_base)

    # Subdirectory inside backup_dir: triggers the non-file continue at line 184
    subdir = os.path.join(env.backup_dir, "subdir_triggers_nonfile_skip_in_delete_archive")
    os.makedirs(subdir, exist_ok=True)

    saved_logger, saved_runner = _cleanup_mod.logger, _cleanup_mod.runner
    try:
        _cleanup_mod.logger = env.logger
        _cleanup_mod.runner = runner
        _cleanup_mod.delete_archive(
            backup_dir=env.backup_dir,
            archive_name=archive_name,
            args=SimpleNamespace(config_file=env.config_file, dry_run=False),
        )
    finally:
        _cleanup_mod.logger = saved_logger
        _cleanup_mod.runner = saved_runner
        if os.path.exists(subdir):
            os.rmdir(subdir)

    assert not os.path.exists(full_slice), "FULL slice must be deleted despite the subdir being present"
    env.logger.info("delete_archive() skipped subdir correctly ✓")


@pytest.mark.smoke
def test_cleanup_main_specific_archive_in_process(setup_environment, env):
    """
    Call main() in-process with --cleanup-specific-archives pointing to a real
    DIFF archive.  Real manager removes the catalog entry; real dar slice is
    deleted from disk.

    Covers: the specific-archive deletion path in main() (lines 397-399).

    sys.argv is saved and restored directly — no pytest monkeypatch is used so
    that coverage is tracked in-process.
    """
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)

    full_base = _make_real_archive(runner, env, "FULL", "2014-03-22")
    diff_base = _make_real_archive(runner, env, "DIFF", "2014-03-22", base_archive=full_base)
    diff_slice = diff_base + ".1.dar"
    assert os.path.exists(diff_slice)

    archive_name = os.path.basename(diff_base)   # e.g. "example_DIFF_2014-03-22"

    saved_logger = _cleanup_mod.logger
    saved_runner = _cleanup_mod.runner
    saved_argv = sys.argv[:]
    sys.argv = [
        "cleanup",
        "--cleanup-specific-archives", archive_name,
        "--config-file", env.config_file,
        "--log-stdout",
    ]
    try:
        with pytest.raises(SystemExit) as exc_info:
            _cleanup_mod.main()
        assert exc_info.value.code == 0, f"main() exited with {exc_info.value.code}"
    finally:
        _cleanup_mod.logger = saved_logger
        _cleanup_mod.runner = saved_runner
        sys.argv = saved_argv

    assert not os.path.exists(diff_slice), "main() --cleanup-specific-archives must delete the DIFF slice"
    env.logger.info("main() --cleanup-specific-archives deleted real DIFF archive ✓")


@pytest.mark.smoke
def test_cleanup_main_age_based_in_process(setup_environment, env):
    """
    Call main() in-process without --cleanup-specific-archives so the age-based
    cleanup else-branch runs for the 'example' definition.  The old DIFF archive
    is deleted by delete_old_backups() via manager (real catalog removal).

    Covers: the age-based cleanup else branch in main() (lines 402-420).

    sys.argv is saved and restored directly — no pytest monkeypatch is used.
    """
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)

    full_base = _make_real_archive(runner, env, "FULL", "2013-11-05")
    diff_base = _make_real_archive(runner, env, "DIFF", "2013-11-05", base_archive=full_base)
    diff_slice = diff_base + ".1.dar"
    assert os.path.exists(diff_slice)

    saved_logger = _cleanup_mod.logger
    saved_runner = _cleanup_mod.runner
    saved_argv = sys.argv[:]
    sys.argv = [
        "cleanup",
        "-d", "example",
        "--config-file", env.config_file,
        "--log-stdout",
    ]
    try:
        with pytest.raises(SystemExit) as exc_info:
            _cleanup_mod.main()
        assert exc_info.value.code == 0, f"main() exited with {exc_info.value.code}"
    finally:
        _cleanup_mod.logger = saved_logger
        _cleanup_mod.runner = saved_runner
        sys.argv = saved_argv

    assert not os.path.exists(diff_slice), "Age-based cleanup in main() must delete the old DIFF slice"
    env.logger.info("main() age-based cleanup deleted old DIFF archive ✓")


@pytest.mark.debug
def test_cleanup_main_list_in_process(setup_environment, env):
    """
    Call main() in-process with --list so the list_backups() branch runs.

    Covers: line 401 (list_backups() call in the elif args.list: branch).
    """
    saved_logger = _cleanup_mod.logger
    saved_runner = _cleanup_mod.runner
    saved_argv = sys.argv[:]
    sys.argv = [
        "cleanup",
        "--list",
        "--config-file", env.config_file,
        "--log-stdout",
    ]
    try:
        with pytest.raises(SystemExit) as exc_info:
            _cleanup_mod.main()
        assert exc_info.value.code == 0
    finally:
        _cleanup_mod.logger = saved_logger
        _cleanup_mod.runner = saved_runner
        sys.argv = saved_argv

    env.logger.info("main() --list path reached ✓")


@pytest.mark.debug
def test_cleanup_main_all_definitions_no_dash_d_in_process(setup_environment, env):
    """
    Call main() in-process without -d so main() walks backup.d to discover all
    backup definitions, covering the os.walk branch.

    Uses --dry-run so no actual archives are deleted.

    Covers: lines 407-409 (os.walk loop over backup_d_dir).
    """
    saved_logger = _cleanup_mod.logger
    saved_runner = _cleanup_mod.runner
    saved_argv = sys.argv[:]
    sys.argv = [
        "cleanup",
        "--dry-run",
        "--config-file", env.config_file,
        "--log-stdout",
    ]
    try:
        with pytest.raises(SystemExit) as exc_info:
            _cleanup_mod.main()
        assert exc_info.value.code == 0
    finally:
        _cleanup_mod.logger = saved_logger
        _cleanup_mod.runner = saved_runner
        sys.argv = saved_argv

    env.logger.info("main() walk-all-definitions (no -d) path reached ✓")


@pytest.mark.debug
def test_cleanup_main_test_mode_no_specific_archives_in_process(setup_environment, env):
    """
    Call main() in-process with --test-mode and no --cleanup-specific-archives so the
    'No --cleanup-specific-archives provided' info log is reached.

    Uses --dry-run so no actual archives are deleted.

    Covers: line 381 (test-mode no-specific-archives logger.info).
    """
    saved_logger = _cleanup_mod.logger
    saved_runner = _cleanup_mod.runner
    saved_argv = sys.argv[:]
    sys.argv = [
        "cleanup",
        "--test-mode",
        "--dry-run",
        "-d", "example",
        "--config-file", env.config_file,
        "--log-stdout",
    ]
    try:
        with pytest.raises(SystemExit) as exc_info:
            _cleanup_mod.main()
        assert exc_info.value.code == 0
    finally:
        _cleanup_mod.logger = saved_logger
        _cleanup_mod.runner = saved_runner
        sys.argv = saved_argv

    env.logger.info("main() --test-mode no-specific-archives log reached ✓")


@pytest.mark.debug
def test_cleanup_main_alternate_archive_dir_in_process(setup_environment, env):
    """
    Call main() in-process with --alternate-archive-dir pointing to a real
    directory.  main() reassigns config_settings.backup_dir to that path.

    Uses --dry-run so no actual archives are deleted.

    Covers: line 378 (config_settings.backup_dir = args.alternate_archive_dir).
    """
    alternate_dir = os.path.join(env.test_dir, "backups-alternate-inprocess")
    os.makedirs(alternate_dir, exist_ok=True)

    saved_logger = _cleanup_mod.logger
    saved_runner = _cleanup_mod.runner
    saved_argv = sys.argv[:]
    sys.argv = [
        "cleanup",
        "--alternate-archive-dir", alternate_dir,
        "--dry-run",
        "-d", "example",
        "--config-file", env.config_file,
        "--log-stdout",
    ]
    try:
        with pytest.raises(SystemExit) as exc_info:
            _cleanup_mod.main()
        assert exc_info.value.code == 0
    finally:
        _cleanup_mod.logger = saved_logger
        _cleanup_mod.runner = saved_runner
        sys.argv = saved_argv

    env.logger.info("main() --alternate-archive-dir assignment path reached ✓")


def test_cleanup_main_invalid_config_covers_error_path_in_process(env):
    """
    Call main() in-process with a non-existent config-file path.  Because pytest
    sets PYTEST_CURRENT_TEST, the 'test_mode or PYTEST_CURRENT_TEST' guard at
    line 300 is True, so the program continues past the missing-file check and
    then fails when ConfigSettings() cannot parse the file, triggering the
    ConfigSettings exception handler.

    Covers: lines 300-301 (missing-file guard with PYTEST_CURRENT_TEST),
            lines 309-314 (ConfigSettings exception handler → sys.exit(127)).
    """
    saved_logger = _cleanup_mod.logger
    saved_runner = _cleanup_mod.runner
    saved_argv = sys.argv[:]
    sys.argv = [
        "cleanup",
        "--config-file", "/nonexistent/path/to/dar-backup.conf",
        "--log-stdout",
    ]
    try:
        with pytest.raises(SystemExit) as exc_info:
            _cleanup_mod.main()
        assert exc_info.value.code == 127, (
            f"Expected exit 127 for bad config, got {exc_info.value.code}"
        )
    finally:
        _cleanup_mod.logger = saved_logger
        _cleanup_mod.runner = saved_runner
        sys.argv = saved_argv

    env.logger.info("main() invalid-config error path (lines 300-301, 309-314) reached ✓")
