

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
    assert "Error writing temp file" in captured.err


# ---------------------------------------------------------------------------
# In-process tests that cover lines missed because subprocess coverage is not
# tracked (no sitecustomize.py in the venv).  These call clean_log_file() and
# the private helpers directly so coverage IS recorded.
# ---------------------------------------------------------------------------

_DAR_LOG_CONTENT = (
    # timestamped format → exercises the timestamp branch in _split_level_and_message
    "2026-01-01 12:00:00,000 - INFO - <File example.txt>\n"
    "2026-01-01 12:00:00,000 - INFO - <Directory /some/path>\n"
    "2026-01-01 12:00:00,000 - INFO - Inspecting directory /mnt/data\n"
    "2026-01-01 12:00:00,000 - INFO - Finished Inspecting /mnt/data\n"
    # non-timestamped format → exercises the else branch
    "INFO - <Attributes modified>\n"
    "INFO - </File>\n"
    # lines that must be KEPT
    "2026-01-01 12:00:00,000 - WARNING - Disk nearly full\n"
    "ERROR - Something failed badly\n"
)


def test_clean_log_file_in_process_removes_dar_lines(tmp_path, capsys):
    """
    Call clean_log_file() directly in-process.

    Covers: _split_level_and_message (53-65), _should_remove_line (68-72),
    and the non-dry-run write path in clean_log_file (105-110).
    """
    log_file = tmp_path / "dar.log"
    log_file.write_text(_DAR_LOG_CONTENT)

    clean_log_module.clean_log_file(str(log_file))

    cleaned = log_file.read_text()
    for marker in ["<File", "<Directory", "Inspecting directory", "Finished Inspecting", "<Attributes", "</File"]:
        assert marker not in cleaned, f"dar line with '{marker}' should have been removed"
    assert "WARNING - Disk nearly full" in cleaned
    assert "ERROR - Something failed badly" in cleaned
    captured = capsys.readouterr()
    assert "Successfully cleaned" in captured.out


def test_clean_log_file_in_process_dry_run(tmp_path, capsys):
    """
    Call clean_log_file(dry_run=True) directly in-process.

    Covers: the dry-run print (line 92) and the dry-run reading loop (98-102).
    """
    log_file = tmp_path / "dar.log"
    log_file.write_text(_DAR_LOG_CONTENT)
    original = log_file.read_text()

    clean_log_module.clean_log_file(str(log_file), dry_run=True)

    # File must be unchanged
    assert log_file.read_text() == original

    captured = capsys.readouterr()
    out = captured.out
    assert "Performing a dry run" in out
    assert "Would remove" in out


def test_clean_log_file_write_permission_denied_in_process(tmp_path, capsys):
    """
    Call clean_log_file() (not dry_run) on a file that has read but no write
    permission.

    Covers: the write-permission guard (lines 87-88).
    """
    log_file = tmp_path / "readonly.log"
    log_file.write_text(_DAR_LOG_CONTENT)
    os.chmod(log_file, stat.S_IRUSR)  # readable, not writable
    try:
        with pytest.raises(SystemExit) as exc:
            clean_log_module.clean_log_file(str(log_file))
        assert exc.value.code == 1
        captured = capsys.readouterr()
        assert "No write permission" in captured.out + captured.err
    finally:
        os.chmod(log_file, stat.S_IRUSR | stat.S_IWUSR)


# ---------------------------------------------------------------------------
# main() in-process tests — no subprocess, coverage is tracked.
# All use sys.argv save/restore; no pytest monkeypatch.
# ---------------------------------------------------------------------------

def test_clean_log_split_no_separator_returns_none_pair():
    """
    _split_level_and_message() must return (None, None) when the line contains
    no ' - ' separator, so that _should_remove_line() treats such lines as
    non-removable (preserving them in the output).

    Covers: line 55 (return None, None branch).
    """
    level, message = clean_log_module._split_level_and_message("a plain line with no separator")
    assert level is None
    assert message is None
    # Downstream guard: such lines must NOT be silently dropped
    assert clean_log_module._should_remove_line("a plain line with no separator") is False


def test_clean_log_main_invalid_config_exits_127(capsys):
    """
    main() must exit with code 127 and print a config-error message to stderr
    when the config file does not exist.

    Covers: lines 150-155 (ConfigSettings exception handler in main()).
    """
    saved_argv = sys.argv[:]
    sys.argv = ["clean-log", "--config-file", "/nonexistent/path/to/dar-backup.conf"]
    try:
        with pytest.raises(SystemExit) as exc_info:
            clean_log_module.main()
        assert exc_info.value.code == 127, f"expected 127, got {exc_info.value.code}"
    finally:
        sys.argv = saved_argv

    captured = capsys.readouterr()
    assert "Config error" in captured.err, (
        f"expected 'Config error' in stderr; got: {captured.err!r}"
    )


def test_clean_log_main_empty_filename_exits_1(setup_environment, env, capsys):
    """
    main() must reject an empty filename with exit code 1 and an informative
    error message.  An empty string passed as -f must never reach the filesystem
    or corrupt any file.

    Covers: lines 172-173 (empty-filename guard in main()).
    """
    saved_argv = sys.argv[:]
    sys.argv = ["clean-log", "-f", "", "--config-file", env.config_file]
    try:
        with pytest.raises(SystemExit) as exc_info:
            clean_log_module.main()
        assert exc_info.value.code == 1
    finally:
        sys.argv = saved_argv

    out = capsys.readouterr().out
    assert "Invalid empty filename" in out, f"expected empty-filename error; got: {out!r}"


def test_clean_log_main_path_traversal_exits_1(setup_environment, env, capsys):
    """
    main() must reject a path containing '..' with exit code 1 — the
    path-traversal guard prevents clean-log from being pointed at arbitrary
    files outside the allowed log directory.

    Covers: lines 176-177 (path-traversal guard in main()).
    """
    saved_argv = sys.argv[:]
    sys.argv = ["clean-log", "-f", "../../etc/passwd", "--config-file", env.config_file]
    try:
        with pytest.raises(SystemExit) as exc_info:
            clean_log_module.main()
        assert exc_info.value.code == 1
    finally:
        sys.argv = saved_argv

    out = capsys.readouterr().out
    assert "traversal" in out.lower() or "not allowed" in out.lower(), (
        f"expected traversal-rejection message; got: {out!r}"
    )


def test_clean_log_main_file_not_found_in_logdir_exits_1(setup_environment, env, capsys):
    """
    main() must exit with code 1 when the requested file is inside the allowed
    log directory but does not exist on disk — verifying the file-existence
    check that guards against silent no-ops.

    Covers: lines 185-187 (file-not-found guard after logfile_dir validation).
    """
    from dar_backup.config_settings import ConfigSettings
    config = ConfigSettings(env.config_file)
    logfile_dir = os.path.dirname(os.path.realpath(config.logfile_location))
    missing_file = os.path.join(logfile_dir, "nonexistent_test_clean_log.log")

    saved_argv = sys.argv[:]
    sys.argv = ["clean-log", "-f", missing_file, "--config-file", env.config_file]
    try:
        with pytest.raises(SystemExit) as exc_info:
            clean_log_module.main()
        assert exc_info.value.code == 1
    finally:
        sys.argv = saved_argv

    out = capsys.readouterr().out
    assert "does not exist" in out, f"expected 'does not exist' message; got: {out!r}"


def test_clean_log_main_removes_dar_lines_and_keeps_others(setup_environment, env, capsys):
    """
    main() must remove dar INFO lines from a log file and preserve WARNING /
    ERROR lines.  The file is modified in-place; the success message is printed
    to stdout.

    Covers: lines 189 (validated_files.append), 193-199 (cleaning loop and
    success prints).
    """
    from dar_backup.config_settings import ConfigSettings
    config = ConfigSettings(env.config_file)
    logfile_dir = os.path.dirname(os.path.realpath(config.logfile_location))

    log_file = os.path.join(logfile_dir, "test_main_clean.log")
    dar_line    = "2026-01-01 12:00:00,000 - INFO - <File example.txt>\n"
    kept_line   = "2026-01-01 12:00:00,000 - WARNING - Disk nearly full\n"
    with open(log_file, "w") as f:
        f.write(dar_line + kept_line)

    saved_argv = sys.argv[:]
    sys.argv = ["clean-log", "-f", log_file, "--config-file", env.config_file]
    try:
        clean_log_module.main()   # returns normally — no sys.exit on success
    finally:
        sys.argv = saved_argv

    with open(log_file) as f:
        cleaned = f.read()
    os.remove(log_file)

    assert "<File example.txt>" not in cleaned, "dar INFO line must be stripped"
    assert "Disk nearly full" in cleaned, "WARNING line must be preserved"

    out = capsys.readouterr().out
    assert "cleaned" in out.lower() or "successfully" in out.lower(), (
        f"expected success message; got: {out!r}"
    )
