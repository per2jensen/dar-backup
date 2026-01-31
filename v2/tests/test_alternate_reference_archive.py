
import os
import sys
import pytest

pytestmark = pytest.mark.integration

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from dar_backup.command_runner import CommandRunner








test_files = {
        'file1.txt': 'This is file 1.',
        'file2.txt': 'This is file 2.',
        'file3.txt': 'This is file 3.',
        'file with spaces.txt': 'This is file with spaces.',
        'file_with_danish_chars_æøå.txt': 'This is file with danish chars æøå.',
        'file_with_DANISH_CHARS_ÆØÅ.txt': 'This is file with DANISH CHARS ÆØÅ.',
        'file_with_colon:.txt': 'This is file with colon :.',
        'file_with_hash#.txt': 'This is file with hash #.',
        'file_with_currency¤.txt': 'This is file with currency ¤.'
 }


def create_test_files(env):
    env.logger.info("Creating test files...")
    for filename, content in test_files.items():
        env.logger.info(f"Creating {filename} with content: {content} in {env.test_dir}")
        with open(os.path.join(env.test_dir, 'data', filename), 'w') as f:
            f.write(content)


def test_diff_extected_to_work(setup_environment, env):
    """
    Test that a diff backup works as expected without any alternate reference archive.
    """
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)

    create_test_files(env)

    # Do a full backup
    command = ['dar-backup', '--full-backup', '-d', "example", '--config-file', env.config_file]
    process = runner.run(command)
    assert process.returncode == 0, "dar-backup must succeed"

    # Do a DIFF
    command = ['dar-backup', '--differential-backup' ,'-d', "example", '--config-file', env.config_file]
    process = runner.run(command)
    assert process.returncode == 0, "dar-backup must succeed"


def test_diff_missing_alternate_reference_archive(setup_environment, env):
    """
    Provide a non-existing alternate archive me.
    dar-backup must fail doing a DIFF.
    """
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)

    create_test_files(env)

    # Do a DIFF with a non-existing alternate reference archive
    command = ['dar-backup', '--differential-backup' ,'-d', "example", '--config-file', env.config_file, '--alternate-reference-archive', 'non-existing-archive']
    process = runner.run(command)
    print("return code", process.returncode)
    assert process.returncode != 0, "dar-backup must fail when the alternate reference archive does not exist"

def test_incr_missing_alternate_reference_archive(setup_environment, env):
    """
    Provide a non-existing alternate archive me.
    dar-backup must fail doing an INCR.
    """
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)

    create_test_files(env)

    # Do a INCRIFF with a non-existing alternate reference archive
    command = ['dar-backup', '--incremental-backup' ,'-d', "example", '--config-file', env.config_file, '--alternate-reference-archive', 'non-existing-archive']
    process = runner.run(command)
    print("return code", process.returncode)
    assert process.returncode != 0, "dar-backup must fail when the alternate reference archive does not exist"



