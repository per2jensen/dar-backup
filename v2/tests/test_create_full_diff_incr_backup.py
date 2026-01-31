#!/usr/bin/env python3

import os
import shutil
import sys
import pytest

pytestmark = [pytest.mark.integration, pytest.mark.slow]


# Add src to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))


from pathlib import Path

from dar_backup.command_runner import CommandRunner
from tests.conftest import test_files 
from testdata_verification import verify_backup_contents, verify_restore_contents,run_backup_script







def list_catalog_db(env):  
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
    command = ['manager', '--list-catalogs' ,'--config-file', env.config_file, '--log-level', 'debug', '--log-stdout']
    process = runner.run(command)
    if process.returncode != 0:
        stdout, stderr = process.stdout, process.stderr
        print(f"stdout: {stdout}")  
        print(f"stderr: {stderr}")  
        raise Exception(f"Command failed: {command}")
    print(process.stdout)
    return process.stdout




def test_backup_functionality(setup_environment, env):
    try:
        # full backup
        run_backup_script("--full-backup", env)

        # Verify FULL backup contents
        verify_backup_contents(test_files, f"example_FULL_{env.datestamp}",env)
        env.logger.info("FULL backup verification succeeded")

        verify_restore_contents(test_files, f"example_FULL_{env.datestamp}", env )

        # cleanup restore directory
        shutil.rmtree(os.path.join(env.test_dir, 'restore'))
        Path(os.path.join(env.test_dir, 'restore')).mkdir(parents=True, exist_ok=True)

        # Differential backup
        # Modify one file for differential backup
        test_files_diff = {'file2.txt' : 'This is file 2.\nThis is an additional line.'}
        with open(os.path.join(env.test_dir, 'data', 'file2.txt'), 'w') as f:
            f.write(test_files_diff['file2.txt'])

        run_backup_script("--differential-backup", env)

        # Verify DIFF backup contents
        verify_backup_contents(test_files_diff, f"example_DIFF_{env.datestamp}", env)
        verify_restore_contents(test_files_diff, f"example_DIFF_{env.datestamp}", env )
        env.logger.info("Differential backup verification succeeded")
        

        # cleanup restore directory
        shutil.rmtree(os.path.join(env.test_dir, 'restore'))
        Path(os.path.join(env.test_dir, 'restore')).mkdir(parents=True, exist_ok=True)

        # Incremental backup
        # Modify one file for incremental backup
        test_files_inc = {'file3.txt' : 'This is file 3.\nThis is an additional line.',
                          'file2.txt' : 'This is file 2.\nThis is another line.'}

        for file, content in test_files_inc.items():
            with open(os.path.join(env.test_dir, 'data', file), 'w') as f:
                f.write(content)

        run_backup_script("--incremental-backup", env)
        
        verify_backup_contents(test_files_inc, f"example_INCR_{env.datestamp}", env)
        verify_restore_contents(test_files_inc, f"example_INCR_{env.datestamp}", env )

        env.logger.info("Incremental backup verification succeeded")

        list_catalog_db(env)


    except Exception:
        env.logger.exception("Backup functionality test failed")
        raise
    env.logger.info("test_backup_functionality() finished successfully")


def test_backup_functionality_short_options(setup_environment, env):
    try:
        # full backup
        run_backup_script("-F", env)

        # Verify FULL backup contents
        verify_backup_contents(test_files, f"example_FULL_{env.datestamp}", env)
        env.logger.info("FULL backup verification succeeded")

        verify_restore_contents(test_files, f"example_FULL_{env.datestamp}", env )

        # cleanup restore directory
        shutil.rmtree(os.path.join(env.test_dir, 'restore'))
        Path(os.path.join(env.test_dir, 'restore')).mkdir(parents=True, exist_ok=True)

        # Differential backup
        # Modify one file for differential backup
        test_files_diff = {'file2.txt' : 'This is file 2.\nThis is an additional line.'}
        with open(os.path.join(env.test_dir, 'data', 'file2.txt'), 'w') as f:
            f.write(test_files_diff['file2.txt'])


        run_backup_script("-D", env)

        # Verify DIFF backup contents
        verify_backup_contents(['data/file2.txt'], f"example_DIFF_{env.datestamp}", env)
        verify_restore_contents(test_files_diff, f"example_DIFF_{env.datestamp}", env )

        env.logger.info("Differential backup verification succeeded")

        # cleanup restore directory
        shutil.rmtree(os.path.join(env.test_dir, 'restore'))
        Path(os.path.join(env.test_dir, 'restore')).mkdir(parents=True, exist_ok=True)



        # Incremental backup
        # Modify one file for incremental backup
        test_files_inc = {'file3.txt' : 'This is file 3.\nThis is an additional line.',
                          'file2.txt' : 'This is file 2.\nThis is another line.'}

        for file, content in test_files_inc.items():
            with open(os.path.join(env.test_dir, 'data', file), 'w') as f:
                f.write(content)

        run_backup_script("-I", env)
        # Verify INCR backup contents
        
        verify_backup_contents(test_files_inc, f"example_INCR_{env.datestamp}", env)
        verify_restore_contents(test_files_inc, f"example_INCR_{env.datestamp}", env )
        env.logger.info("Incremental backup verification succeeded")

        list_catalog_db(env)

    except Exception:
        env.logger.exception("Backup functionality test failed")
        raise
    env.logger.info("test_backup_functionality() finished successfully")


def test_backup_with_missing_config_file(setup_environment, env):
    # Simulate missing config file
    if os.path.exists(env.config_file):
        os.remove(env.config_file)

    assert not os.path.exists(env.config_file)

    # Run backup script and capture result
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
    result = runner.run(["dar-backup", "--full-backup", "--config-file", env.config_file])

    env.logger.info("Ran dar-backup with missing config file")

    # Assert correct failure behavior
    assert result.returncode == 127, f"Expected return code 127, got {result.returncode}"
    assert "must exist and be readable" in result.stderr.lower()


def test_backup_with_malformed_config_file(setup_environment, env):
    # Malformed config (missing [MISC]) + unresolved placeholders fixed manually

    backup_d_dir = os.path.join(env.test_dir, "backup.d")

    malformed_content = f"""
    [DIRECTORIES]
    BACKUP_DIR = {env.backup_dir}
    BACKUP.D_DIR = {backup_d_dir}
    DATA_DIR = {env.data_dir}
    TEST_RESTORE_DIR = {env.restore_dir}
    """

    with open(env.config_file, "w") as f:
        f.write(malformed_content)

    assert os.path.exists(env.config_file)

    # Run the backup script
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
    result = runner.run(["dar-backup", "--full-backup", "--config-file", env.config_file])

    env.logger.info("Ran dar-backup with malformed config file")

    # Expect failure (non-zero exit code)
    assert result.returncode != 0
    assert "missing" in result.stderr.lower() or "error" in result.stderr.lower() or "section" in result.stderr.lower()


def test_config_with_invalid_timeout_value(setup_environment, env):
    # Set up backup.d path manually since it's not in EnvData
    backup_d_dir = os.path.join(env.test_dir, "backup.d")

    # Write a config with an invalid COMMAND_TIMEOUT_SECS value
    invalid_config = f"""
[MISC]
LOGFILE_LOCATION = {env.log_file}
MAX_SIZE_VERIFICATION_MB = 20
MIN_SIZE_VERIFICATION_MB = 0
NO_FILES_VERIFICATION = 5
COMMAND_TIMEOUT_SECS = banana  # ← invalid!

[DIRECTORIES]
BACKUP_DIR = {env.backup_dir}
BACKUP.D_DIR = {backup_d_dir}
DATA_DIR = {env.data_dir}
TEST_RESTORE_DIR = {env.restore_dir}

[AGE]
DIFF_AGE = 30
INCR_AGE = 15

[PAR2]
ERROR_CORRECTION_PERCENT = 5
ENABLED = True
"""

    with open(env.config_file, "w") as f:
        f.write(invalid_config)

    assert os.path.exists(env.config_file)

    # Run the script
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
    result = runner.run(["dar-backup", "--full-backup", "--config-file", env.config_file])

    env.logger.info("Ran dar-backup with invalid config value")

    # Expect failure due to type error
    assert result.returncode != 0
    assert "invalid" in result.stderr.lower() or "error" in result.stderr.lower() or "value" in result.stderr.lower()


def test_config_with_invalid_boolean_value(setup_environment, env):
    """
    What happens if someone writes:

    ENABLED = maybe  # 🤔 not valid

    We want to ensure:

        The script fails fast and loud if it can't coerce that to a boolean

        It gives a useful error (e.g., invalid literal, or ValueError)

        The test fails if the script silently accepts "maybe" as True/False without warning
    """

    backup_d_dir = os.path.join(env.test_dir, "backup.d")

    invalid_config = f"""
[MISC]
LOGFILE_LOCATION = {env.log_file}
MAX_SIZE_VERIFICATION_MB = 20
MIN_SIZE_VERIFICATION_MB = 0
NO_FILES_VERIFICATION = 5
COMMAND_TIMEOUT_SECS = 86400

[DIRECTORIES]
BACKUP_DIR = {env.backup_dir}
BACKUP.D_DIR = {backup_d_dir}
DATA_DIR = {env.data_dir}
TEST_RESTORE_DIR = {env.restore_dir}

[AGE]
DIFF_AGE = 30
INCR_AGE = 15

[PAR2]
ERROR_CORRECTION_PERCENT = 5
ENABLED = maybe  # ← bad value
"""

    with open(env.config_file, "w") as f:
        f.write(invalid_config)

    assert os.path.exists(env.config_file)

    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
    result = runner.run(["dar-backup", "--full-backup", "--config-file", env.config_file])

    env.logger.info("Ran dar-backup with invalid boolean value for PAR2.ENABLED")

    assert result.returncode != 0
    assert "Invalid boolean value for 'ENABLED'" in result.stderr, "Expected error message not found in stderr"


def test_config_with_invalid_integer_value(setup_environment, env):
    """
    Test that dar-backup fails when a required int config value is invalid.

    This test deliberately sets NO_FILES_VERIFICATION to a non-integer ('ten')
    and expects the script to fail with a ValueError.
    """

    backup_d_dir = os.path.join(env.test_dir, "backup.d")

    invalid_config = f"""
[MISC]
LOGFILE_LOCATION = {env.log_file}
MAX_SIZE_VERIFICATION_MB = 20
MIN_SIZE_VERIFICATION_MB = 0
NO_FILES_VERIFICATION = ten  # ← invalid
COMMAND_TIMEOUT_SECS = 86400

[DIRECTORIES]
BACKUP_DIR = {env.backup_dir}
BACKUP.D_DIR = {backup_d_dir}
DATA_DIR = {env.data_dir}
TEST_RESTORE_DIR = {env.restore_dir}

[AGE]
DIFF_AGE = 30
INCR_AGE = 15

[PAR2]
ERROR_CORRECTION_PERCENT = 5
ENABLED = true
"""

    with open(env.config_file, "w") as f:
        f.write(invalid_config)

    assert os.path.exists(env.config_file)

    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
    result = runner.run(["dar-backup", "--full-backup", "--config-file", env.config_file])

    env.logger.info("Ran dar-backup with non-integer value for NO_FILES_VERIFICATION")

    # Verify non-zero exit and correct error
    assert result.returncode != 0, "Expected non-zero exit due to invalid int"
    assert "invalid literal for int()" in result.stderr.lower(), "Expected ValueError in stderr"


def test_config_missing_age_section(setup_environment, env):
    """
    Test behavior when the [AGE] section is missing from the config file.
    Expect: dar-backup should exit with an error and report the missing section.
    """
    backup_d_dir = os.path.join(env.test_dir, "backup.d")

    invalid_config = f"""
[MISC]
LOGFILE_LOCATION = {env.log_file}
MAX_SIZE_VERIFICATION_MB = 20
MIN_SIZE_VERIFICATION_MB = 0
NO_FILES_VERIFICATION = 5
COMMAND_TIMEOUT_SECS = 86400

[DIRECTORIES]
BACKUP_DIR = {env.backup_dir}
BACKUP.D_DIR = {backup_d_dir}
DATA_DIR = {env.data_dir}
TEST_RESTORE_DIR = {env.restore_dir}

[PAR2]
ERROR_CORRECTION_PERCENT = 5
ENABLED = True
"""

    with open(env.config_file, "w") as f:
        f.write(invalid_config)

    assert os.path.exists(env.config_file)

    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
    result = runner.run(["dar-backup", "--full-backup", "--config-file", env.config_file])

    env.logger.info("Ran dar-backup with config missing [AGE] section")

    assert result.returncode != 0
    assert "missing mandatory configuration key" in result.stderr.lower()
    assert "age" in result.stderr.lower()


def test_config_missing_diff_age_key(setup_environment, env):
    """
    Validate that the script fails if the [AGE] section exists but the DIFF_AGE key is missing.
    This tests for:
      - Fast failure
      - Clear error about missing DIFF_AGE
      - Non-zero exit code
    """
    backup_d_dir = os.path.join(env.test_dir, "backup.d")

    invalid_config = f"""
[MISC]
LOGFILE_LOCATION = {env.log_file}
MAX_SIZE_VERIFICATION_MB = 20
MIN_SIZE_VERIFICATION_MB = 0
NO_FILES_VERIFICATION = 5
COMMAND_TIMEOUT_SECS = 86400

[DIRECTORIES]
BACKUP_DIR = {env.backup_dir}
BACKUP.D_DIR = {backup_d_dir}
DATA_DIR = {env.data_dir}
TEST_RESTORE_DIR = {env.restore_dir}

[AGE]
# DIFF_AGE is intentionally missing
INCR_AGE = 15

[PAR2]
ERROR_CORRECTION_PERCENT = 5
ENABLED = True
"""

    with open(env.config_file, "w") as f:
        f.write(invalid_config)

    assert os.path.exists(env.config_file)

    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
    result = runner.run(["dar-backup", "--full-backup", "--config-file", env.config_file])
    env.logger.info("Ran dar-backup with config missing DIFF_AGE key in [AGE]")

    assert result.returncode != 0
    assert "Missing mandatory configuration key" in result.stderr
    assert "DIFF_AGE" in result.stderr


def test_config_missing_incr_age(setup_environment, env):
    """
    Simulate a config file missing the INCR_AGE key in [AGE] section.

    This should raise a KeyError and cause the script to exit.
    """
    # Construct a config with missing INCR_AGE
    backup_d_dir = os.path.join(env.test_dir, "backup.d")

    config_missing_incr_age = f"""
[MISC]
LOGFILE_LOCATION = {env.log_file}
MAX_SIZE_VERIFICATION_MB = 20
MIN_SIZE_VERIFICATION_MB = 0
NO_FILES_VERIFICATION = 5
COMMAND_TIMEOUT_SECS = 86400

[DIRECTORIES]
BACKUP_DIR = {env.backup_dir}
BACKUP.D_DIR = {backup_d_dir}
DATA_DIR = {env.data_dir}
TEST_RESTORE_DIR = {env.restore_dir}

[AGE]
DIFF_AGE = 30

[PAR2]
ERROR_CORRECTION_PERCENT = 5
ENABLED = True
"""

    with open(env.config_file, "w") as f:
        f.write(config_missing_incr_age)

    assert os.path.exists(env.config_file)
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
    result = runner.run(["dar-backup", "--full-backup", "--config-file", env.config_file])

    env.logger.info("Ran dar-backup with config missing INCR_AGE")
    
    assert result.returncode != 0
    assert "INCR_AGE" in result.stderr.upper() or "MANDATORY" in result.stderr.upper()
