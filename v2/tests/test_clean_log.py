

import os
import pytest
import shutil
from tests.envdata import EnvData
from dar_backup.util import run_command
from dar_backup import __about__ as about


LOG_ENTRIES_TO_REMOVE = [
    "INFO - <File",
    "INFO - <Attributes",
    "INFO - </Directory",
    "INFO - <Directory",
    "INFO - </File",
    "INFO - Inspecting directory",
    "INFO - Finished Inspecting"
]



@pytest.fixture
def sample_log_file(env: EnvData):
    """Creates a sample log file for testing."""
    log_file_path = os.path.join(env.test_dir, "test.log")
    sample_content = f"""
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

    command = ['clean-log', '-v']
    process = run_command(command)
    if process.returncode != 0:
        raise Exception(f"Command failed {command}")
    env.logger.info("clean-log -v:\n" + process.stdout)


    assert f"clean-log version {about.__version__}" in process.stdout, f"Version # not found in output"   




def test_clean_log_removes_entries(setup_environment, env: EnvData, sample_log_file):
    """Test that `clean-log` removes the expected log entries."""
    
    command = ["clean-log", "-f", sample_log_file, '-c', env.config_file]
    process = run_command(command)
    
    assert process.returncode == 0, f"Command failed: {process.stderr}"
    
    # Read the cleaned log file
    with open(sample_log_file, "r") as f:
        content = f.readlines()

    # Ensure all log entries that should be removed are gone
    for entry in LOG_ENTRIES_TO_REMOVE:
        assert not any(entry in line for line in content), f"Log entry '{entry}' was not removed!"


def test_clean_log_keeps_unrelated_entries(setup_environment, env: EnvData, sample_log_file):
    """Test that `clean-log` does not remove unrelated log entries."""
    
    command = ["clean-log", "-f", sample_log_file, '-c', env.config_file]
    run_command(command)

    with open(sample_log_file, "r") as f:
        content = f.read()

    assert "WARNING - Something happened" in content, "WARNING log was incorrectly removed!"
    assert "ERROR - Failed operation" in content, "ERROR log was incorrectly removed!"
    assert "DEBUG - This is a debug log" in content, "DEBUG log was incorrectly removed!"


def test_clean_log_empty_file(setup_environment, env: EnvData):
    """Test `clean-log` on an empty log file."""
    log_file = os.path.join(env.test_dir, "empty.log")

    # Create an empty file
    open(log_file, "w").close()

    command = ["clean-log", "-f", log_file, '-c', env.config_file]
    process = run_command(command)

    assert process.returncode == 0, f"Command failed: {process.stderr}"

    # Check that file is still empty
    with open(log_file, "r") as f:
        content = f.read()
    
    assert content == "", "Empty file was modified when it shouldn't be!"


def test_clean_log_multiple_files(setup_environment, env: EnvData, sample_log_file):
    """Test `clean-log` with multiple log files."""
    log_file_2 = os.path.join(env.test_dir, "test2.log")
    shutil.copy(sample_log_file, log_file_2)  # Duplicate the log file

    command = ["clean-log", "-f", sample_log_file, log_file_2, '-c', env.config_file]
    process = run_command(command)

    assert process.returncode == 0, f"Command failed: {process.stderr}"

    for log_file in [sample_log_file, log_file_2]:
        with open(log_file, "r") as f:
            content = f.readlines()
        for entry in LOG_ENTRIES_TO_REMOVE:
            assert not any(entry in line for line in content), f"Log entry '{entry}' was not removed!"


def test_clean_log_non_existent_file(setup_environment, env: EnvData):
    """Test `clean-log` on a non-existent file."""
    log_file = os.path.join(env.test_dir, "does_not_exist.log")

    command = ["clean-log", "-f", log_file, '-c', env.config_file]
    process = run_command(command)

    assert process.returncode != 0, "Command should fail on a non-existent file!"


import os
import stat

def test_clean_log_read_only_file(setup_environment, env: EnvData, sample_log_file):
    """Test `clean-log` on a read-only file (should fail)."""
    
    import stat
    os.chmod(sample_log_file, stat.S_IREAD)  # Make file read-only

    command = ["clean-log", "-f", sample_log_file, '-c', env.config_file]
    process = run_command(command)

    assert process.returncode != 0, "Command should fail on a read-only file!"

    # Check both stdout and stderr for the error message
    error_output = process.stderr + process.stdout  
    assert "No write permission" in error_output, f"Expected 'No write permission' error but got: {error_output}"

    os.chmod(sample_log_file, stat.S_IWRITE)  # Restore write permissions after test


def test_clean_log_corrupted_file(setup_environment, env: EnvData):
    """Test `clean-log` on a log file with corrupted content."""
    log_file = os.path.join(env.test_dir, "corrupted.log")

    corrupted_content = "INFO - <File example.txt>\x00\x01\x02ERROR - Bad data\nINFO - Finished Inspecting"
    with open(log_file, "w", encoding="utf-8", errors="ignore") as f:
        f.write(corrupted_content)

    command = ["clean-log", "-f", log_file, '-c', env.config_file]
    process = run_command(command)

    assert process.returncode == 0, "Command should handle corrupted files!"

    with open(log_file, "r") as f:
        content = f.read()

    print(f"Final log file content:\n{content}")

    assert "ERROR - Bad data" in content, "Valid log entries were incorrectly removed!"
    assert "INFO - <File example.txt>" not in content, "Corrupted data was not properly processed!"



def test_clean_log_dry_run(setup_environment, env: EnvData, sample_log_file):
    """Test `clean-log --dry-run` to ensure it correctly displays removable lines."""
    
    command = ["clean-log", "-f", sample_log_file, "--dry-run", '-c', env.config_file]
    process = run_command(command)

    assert process.returncode == 0, "Command failed in dry-run mode!"

    dry_run_output = process.stdout
    print(f"Dry-run output:\n{dry_run_output}")  # Debugging step

    missing_entries = [entry for entry in LOG_ENTRIES_TO_REMOVE if f"Would remove: {entry}" not in dry_run_output]
    
    assert not missing_entries, f"Dry-run did not show these removable entries: {missing_entries}"

    # Ensure the log file was NOT modified
    with open(sample_log_file, "r") as f:
        original_content = f.read()

    with open(sample_log_file, "r") as f:
        new_content = f.read()

    assert original_content == new_content, "Dry-run should not modify the file!"
