

import os
import sys
import pytest

pytestmark = pytest.mark.integration

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

import shutil
from types import SimpleNamespace
from tests.envdata import EnvData
from dar_backup import __about__ as about
from dar_backup import clean_log as clean_log_module
from dar_backup.command_runner import CommandRunner


LOG_ENTRIES_TO_REMOVE = [
    "INFO - <File",
    "INFO - <Attributes",
    "INFO - </Directory",
    "INFO - <Directory",
    "INFO - </File",
    "INFO - Inspecting directory",
    "INFO - Finished Inspecting",
]

def write_minimal_config(config_path, logfile_location):
    config_path = os.fspath(config_path)
    logfile_location = os.fspath(logfile_location)
    config_content = f"""[MISC]
LOGFILE_LOCATION = {logfile_location}
MAX_SIZE_VERIFICATION_MB = 20
MIN_SIZE_VERIFICATION_MB = 0
NO_FILES_VERIFICATION = 5
COMMAND_TIMEOUT_SECS = 30

[DIRECTORIES]
BACKUP_DIR = /tmp/fake/backup/
BACKUP.D_DIR = /tmp/fake/backup.d/
TEST_RESTORE_DIR = /tmp/fake/restore/

[AGE]
DIFF_AGE = 30
INCR_AGE = 15

[PAR2]
ERROR_CORRECTION_PERCENT = 5
ENABLED = True
"""
    with open(config_path, "w") as f:
        f.write(config_content)


@pytest.fixture
def sample_log_file(env: EnvData):
    """Creates a sample log file for testing."""
    log_file_path = os.path.join(env.test_dir, "test.log")
    sample_content = """
    INFO - <File example.txt>
    INFO - <Attributes modified>
    INFO - </Directory>
    INFO - <Directory>
    INFO - </File>
    INFO - Inspecting directory /var/tmp
    INFO - Finished Inspecting
    WARNING - Something happened
    ERROR - Failed operation
    DEBUG - This is a debug log
    """

    with open(log_file_path, "w") as f:
        f.write(sample_content.strip())

    yield log_file_path

    if os.path.exists(log_file_path):
        os.remove(log_file_path)



def test_version(setup_environment, env: EnvData):
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)

    command = ['clean-log', '-v']
    process = runner.run(command)
    if process.returncode != 0:
        raise Exception(f"Command failed {command}")
    env.logger.info("clean-log -v:\n" + process.stdout)

    stdout_normalized = " ".join(process.stdout.split())
    assert f"clean-log version {about.__version__}" in stdout_normalized, "Version # not found in output"
    assert 'Licensed under GNU GENERAL PUBLIC LICENSE v3' in stdout_normalized, "License not found in output"



def test_clean_log_removes_entries(setup_environment, env: EnvData, sample_log_file):
    """Test that `clean-log` removes the expected log entries."""
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)

    command = ["clean-log", "-f", sample_log_file, '-c', env.config_file]
    process = runner.run(command)

    assert process.returncode == 0, f"Command failed: {process.stderr}"

    # Read the cleaned log file
    with open(sample_log_file, "r") as f:
        content = f.readlines()

    # Ensure all log entries that should be removed are gone
    for entry in LOG_ENTRIES_TO_REMOVE:
        assert not any(entry in line for line in content), f"Log entry '{entry}' was not removed!"


def test_clean_log_keeps_unrelated_entries(setup_environment, env: EnvData, sample_log_file):
    """Test that `clean-log` does not remove unrelated log entries."""
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)

    command = ["clean-log", "-f", sample_log_file, '-c', env.config_file]
    runner.run(command)

    with open(sample_log_file, "r") as f:
        content = f.read()

    assert "WARNING - Something happened" in content, "WARNING log was incorrectly removed!"
    assert "ERROR - Failed operation" in content, "ERROR log was incorrectly removed!"
    assert "DEBUG - This is a debug log" in content, "DEBUG log was incorrectly removed!"


def test_clean_log_keeps_non_info_pattern_lines(tmp_path, logger):
    runner = CommandRunner(logger=logger["logger"], command_logger=logger["command_logger"])
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    config_path = tmp_path / "dar-backup.conf"
    log_file = log_dir / "commands.log"

    write_minimal_config(config_path, log_dir / "dar-backup.log")

    log_file.write_text(
        "ERROR - Something INFO - <File keep_me>\n"
        "WARNING - <Directory keep_me>\n"
        "Just some text without separators\n"
        "2024-01-01 00:00:00,000 - INFO - <File remove_me>\n"
        "INFO - <Directory remove_me>\n"
    )

    command = ["clean-log", "-f", str(log_file), "-c", str(config_path)]
    process = runner.run(command)

    assert process.returncode == 0, f"Command failed: {process.stderr}"

    cleaned = log_file.read_text()
    assert "ERROR - Something INFO - <File keep_me>" in cleaned
    assert "WARNING - <Directory keep_me>" in cleaned
    assert "Just some text without separators" in cleaned
    assert "<File remove_me>" not in cleaned
    assert "INFO - <Directory remove_me>" not in cleaned


def test_clean_log_empty_file(setup_environment, env: EnvData):
    """Test `clean-log` on an empty log file."""
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
    log_file = os.path.join(env.test_dir, "empty.log")

    # Create an empty file
    open(log_file, "w").close()

    command = ["clean-log", "-f", log_file, '-c', env.config_file]
    process = runner.run(command)

    assert process.returncode == 0, f"Command failed: {process.stderr}"

    # Check that file is still empty
    with open(log_file, "r") as f:
        content = f.read()

    assert content == "", "Empty file was modified when it shouldn't be!"


def test_clean_log_multiple_files(setup_environment, env: EnvData, sample_log_file):
    """Test `clean-log` with multiple log files."""
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
    log_file_2 = os.path.join(env.test_dir, "test2.log")
    shutil.copy(sample_log_file, log_file_2)  # Duplicate the log file

    command = ["clean-log", "-f", sample_log_file, log_file_2, '-c', env.config_file]
    process = runner.run(command)

    assert process.returncode == 0, f"Command failed: {process.stderr}"

    for log_file in [sample_log_file, log_file_2]:
        with open(log_file, "r") as f:
            content = f.readlines()
        for entry in LOG_ENTRIES_TO_REMOVE:
            assert not any(entry in line for line in content), f"Log entry '{entry}' was not removed!"


def test_clean_log_non_existent_file(setup_environment, env: EnvData):
    """Test `clean-log` on a non-existent file."""
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
    log_file = os.path.join(env.test_dir, "does_not_exist.log")

    command = ["clean-log", "-f", log_file, '-c', env.config_file]
    process = runner.run(command)

    assert process.returncode != 0, "Command should fail on a non-existent file!"


import os
import stat



def test_clean_log_read_only_file(setup_environment, env: EnvData, sample_log_file):
    """Test `clean-log` on a read-only file (should fail)."""
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)

    import stat




    os.chmod(sample_log_file, stat.S_IREAD)  # Make file read-only

    command = ["clean-log", "-f", sample_log_file, '-c', env.config_file]
    process = runner.run(command)

    assert process.returncode != 0, "Command should fail on a read-only file!"

    # Check both stdout and stderr for the error message
    error_output = process.stderr + process.stdout
    assert "No write permission" in error_output, f"Expected 'No write permission' error but got: {error_output}"

    os.chmod(sample_log_file, stat.S_IWRITE)  # Restore write permissions after test


def test_clean_log_dry_run_read_only_file(setup_environment, env: EnvData, sample_log_file):
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)

    with open(sample_log_file, "r") as f:
        original_content = f.read()

    os.chmod(sample_log_file, stat.S_IREAD)
    try:
        command = ["clean-log", "-f", sample_log_file, "--dry-run", "-c", env.config_file]
        process = runner.run(command)

        assert process.returncode == 0, f"Command failed: {process.stderr}"

        with open(sample_log_file, "r") as f:
            new_content = f.read()
        assert original_content == new_content, "Dry-run must not modify the file!"
    finally:
        os.chmod(sample_log_file, stat.S_IRUSR | stat.S_IWUSR)


def test_clean_log_corrupted_file(setup_environment, env: EnvData):
    """Test `clean-log` on a log file with corrupted content."""
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
    log_file = os.path.join(env.test_dir, "corrupted.log")

    corrupted_content = "INFO - <File example.txt>\x00\x01\x02ERROR - Bad data\nINFO - Finished Inspecting"
    with open(log_file, "w", encoding="utf-8", errors="ignore") as f:
        f.write(corrupted_content)

    command = ["clean-log", "-f", log_file, '-c', env.config_file]
    process = runner.run(command)

    assert process.returncode == 0, "Command should handle corrupted files!"

    with open(log_file, "r") as f:
        content = f.read()

    print(f"Final log file content:\n{content}")

    assert "ERROR - Bad data"          not in content, "Valid log entries were incorrectly removed!"
    assert "INFO - <File example.txt>" not in content, "Corrupted data was not properly processed!"



def test_clean_log_dry_run(setup_environment, env: EnvData, sample_log_file):
    """Test `clean-log --dry-run` to ensure it correctly displays removable lines."""
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)

    with open(sample_log_file, "r") as f:
        original_content = f.read()

    command = ["clean-log", "-f", sample_log_file, "--dry-run", '-c', env.config_file]
    process = runner.run(command)

    assert process.returncode == 0, "Command failed in dry-run mode!"

    dry_run_output = process.stdout
    print(f"Dry-run output:\n{dry_run_output}")  # Debugging step

    missing_entries = [entry for entry in LOG_ENTRIES_TO_REMOVE if f"Would remove: {entry}" not in dry_run_output]

    assert not missing_entries, f"Dry-run did not show these removable entries: {missing_entries}"

    # Ensure the log file was NOT modified
    with open(sample_log_file, "r") as f:
        new_content = f.read()

    assert original_content == new_content, "Dry-run must not modify the file!"



def test_clean_log_uses_config_file_when_no_file_provided(setup_environment, env: EnvData):
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)

    logfile_path = os.path.join(env.test_root, "dar-backup.log")
    os.makedirs(os.path.dirname(logfile_path), exist_ok=True)
    with open(logfile_path, "w") as f:
        f.write("INFO - <File should be removed>\nERROR - Keep this\n")

    command = ["clean-log", "-c", env.config_file]
    process = runner.run(command)

    assert process.returncode == 0

    # ✅ Only inspect the cleaned file content (not stdout)
    with open(logfile_path) as f:
        cleaned = f.read()

    assert "ERROR - Keep this" in cleaned
    assert "<File should be removed>" not in cleaned


def test_clean_log_invalid_empty_filename(setup_environment, env: EnvData):
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
    command = ["clean-log", "-f", "", "-c", env.config_file]
    process = runner.run(command)
    assert process.returncode != 0
    error_output = process.stderr + process.stdout
    assert "Error: Invalid empty filename" in error_output


def test_clean_log_missing_config_file(setup_environment, env: EnvData, sample_log_file):
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
    command = ["clean-log", "-f", sample_log_file, "-c", "/nonexistent.conf"]
    process = runner.run(command)
    assert process.returncode != 0
    assert "Configuration file not found or unreadable:" in process.stderr or process.stdout


def test_clean_log_rejects_path_traversal(tmp_path, logger):
    runner = CommandRunner(logger=logger["logger"], command_logger=logger["command_logger"])
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    config_path = tmp_path / "dar-backup.conf"

    write_minimal_config(config_path, log_dir / "dar-backup.log")

    command = ["clean-log", "-f", "../evil.log", "-c", str(config_path)]
    process = runner.run(command)

    assert process.returncode != 0
    error_output = process.stderr + process.stdout
    assert "Path traversal is not allowed" in error_output


def test_clean_log_rejects_outside_log_dir(tmp_path, logger):
    runner = CommandRunner(logger=logger["logger"], command_logger=logger["command_logger"])
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    config_path = tmp_path / "dar-backup.conf"

    write_minimal_config(config_path, log_dir / "dar-backup.log")

    outside_file = tmp_path / "outside.log"
    outside_file.write_text("INFO - <File example.txt>\n")

    command = ["clean-log", "-f", str(outside_file), "-c", str(config_path)]
    process = runner.run(command)

    assert process.returncode != 0
    error_output = process.stderr + process.stdout
    assert "outside allowed directory" in error_output


def test_clean_log_file_missing_file(tmp_path, capsys):
    missing_path = tmp_path / "missing.log"
    with pytest.raises(SystemExit) as exc:
        clean_log_module.clean_log_file(str(missing_path))
    assert exc.value.code == 127

    captured = capsys.readouterr()
    assert f"File '{missing_path}' not found!" in captured.out + captured.err


def test_clean_log_file_no_read_permission(tmp_path, capsys):
    log_file = tmp_path / "no_read.log"
    log_file.write_text("INFO - <File example.txt>\n")
    os.chmod(log_file, stat.S_IWUSR)
    try:
        with pytest.raises(SystemExit) as exc:
            clean_log_module.clean_log_file(str(log_file))
        assert exc.value.code == 1
        captured = capsys.readouterr()
        assert "No read permission" in captured.out + captured.err
    finally:
        os.chmod(log_file, stat.S_IRUSR | stat.S_IWUSR)


def test_clean_log_rejects_non_pathlike(tmp_path, monkeypatch, capsys):
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    config_path = tmp_path / "dar-backup.conf"
    write_minimal_config(config_path, log_dir / "dar-backup.log")

    fake_args = SimpleNamespace(file=[object()], config_file=str(config_path), dry_run=False)
    monkeypatch.setattr(
        clean_log_module.argparse.ArgumentParser,
        "parse_args",
        lambda self, *args, **kwargs: fake_args,
    )

    with pytest.raises(SystemExit) as exc:
        clean_log_module.main()
    assert exc.value.code == 1

    captured = capsys.readouterr()
    assert "Invalid file path type" in captured.out + captured.err


def test_clean_log_file_handles_open_error(tmp_path, monkeypatch, capsys):
    log_file = tmp_path / "log.log"
    log_file.write_text("INFO - <File example.txt>\n")

    def boom(*args, **kwargs):
        raise OSError("boom")

    monkeypatch.setattr("builtins.open", boom)

    with pytest.raises(SystemExit) as exc:
        clean_log_module.clean_log_file(str(log_file))
    assert exc.value.code == 1

    captured = capsys.readouterr()
    assert "Error processing file" in captured.out + captured.err
