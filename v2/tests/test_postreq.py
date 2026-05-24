import os
import sys
import pytest

pytestmark = [pytest.mark.integration, pytest.mark.smoke]

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))
from dar_backup.command_runner import CommandRunner


def test_postreq_success_runs_backup(setup_environment, env):
    """A passing POSTREQ command must not prevent the backup from succeeding."""
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
    with open(env.config_file, 'a') as f:
        f.write('\n[POSTREQ]\n')
        f.write(f'POSTREQ_01 = ls {env.backup_dir}\n')
    command = ['dar-backup', '--full-backup', '-d', 'example', '--config-file', env.config_file, '--log-level', 'debug']
    process = runner.run(command)
    assert process.returncode == 0, "dar-backup must succeed when POSTREQ passes"


def test_postreq_failure_aborts_backup(setup_environment, env):
    """A failing POSTREQ command must cause dar-backup to exit non-zero."""
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
    with open(env.config_file, 'a') as f:
        f.write('\n[POSTREQ]\n')
        f.write('POSTREQ_01 = command-does-not-exist\n')
    command = ['dar-backup', '--full-backup', '-d', 'example', '--config-file', env.config_file, '--log-stdout']
    process = runner.run(command)
    assert process.returncode != 0, "dar-backup must fail when a POSTREQ command fails"
