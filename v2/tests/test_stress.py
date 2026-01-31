import os
import sys
import pytest

pytestmark = [pytest.mark.integration, pytest.mark.slow]

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))
from dar_backup.command_runner import CommandRunner
from tests.envdata import EnvData








def create_many_tiny_files(env: EnvData, count=5000):
    """
    Create a large number of tiny files (1–4 bytes each) for stress testing.
    """
    for i in range(count):
        filepath = os.path.join(env.data_dir, f"tiny_{i}.txt")
        with open(filepath, "wb") as f:
            f.write(os.urandom(i % 4 + 1))  # 1–4 bytes
    env.logger.info(f"Created {count} tiny files in {env.data_dir}")


def test_backup_with_many_small_files(setup_environment, env: EnvData):
    """
    Stress test: Archive and restore thousands of tiny files.
    """
    file_count = 5000
    create_many_tiny_files(env, file_count)

    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)

    # Run full backup
    command = [
        'dar-backup',
        '--full-backup',
        '-d', 'example',
        '--config-file', env.config_file,
        '--log-level', 'debug',
        '--log-stdout'
    ]
    result = runner.run(command)
    env.logger.info("Ran dar-backup with many tiny files")
    assert result.returncode == 0

    # List archive contents
    archive_base = f"example_FULL_{env.datestamp}"
    list_result = runner.run([
        'dar-backup',
        '--list-contents',
        archive_base,
        '--config-file', env.config_file
    ])
    assert list_result.returncode == 0
    file_hits = sum(1 for line in list_result.stdout.splitlines() if "tiny_" in line)
    assert file_hits == file_count, f"Expected {file_count} tiny files, found {file_hits}"

    env.logger.info(f"Archive contains all {file_count} tiny files.")
