import sys
import logging
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock
from dar_backup import util


@pytest.fixture
def temp_logdir(tmp_path):
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    return log_dir


def test_setup_logging_creates_file_and_logger(temp_logdir):
    logfile = temp_logdir / "test.log"
    command_output_file = temp_logdir / "command.log"

    logger = util.setup_logging(logfile, command_output_file)

    assert logfile.exists()
    assert command_output_file.exists()
    assert isinstance(logger, logging.Logger)


def test_setup_logging_stdout_and_file(tmp_path):
    logfile = tmp_path / "combo.log"
    command_output_file = tmp_path / "command.log"

    # We patch sys.stdout to a dummy, but setup_logging doesn’t support also_stdout anymore
    logger = util.setup_logging(logfile, command_output_file)
    logger.info("Hello from logger")

    assert logfile.exists()
    assert "Hello" in logfile.read_text()
    assert command_output_file.exists()

def list_backups(backup_dir: Path) -> list:
    if not backup_dir.exists() or not backup_dir.is_dir():
        print("No backups available.")
        return []

    backups = [f.name for f in backup_dir.iterdir() if f.is_dir()]
    if not backups:
        print("No backups available.")
    else:
        for b in sorted(backups):
            print(b)

    return sorted(backups)



def test_list_backups_ignores_files(tmp_path, capsys):
    test_dir = tmp_path / "backups"
    test_dir.mkdir()

    # Create a valid .dar file matching expected pattern
    valid_backup = test_dir / "mybackup_FULL_2024-04-01.1.dar"
    valid_backup.write_text("dummy")

    # Create a file that should be ignored
    (test_dir / "note.txt").write_text("Ignore me")

    # Call the function
    util.list_backups(str(test_dir))

    # Capture stdout
    out = capsys.readouterr().out

    # Assertions: should include valid backup name, not note.txt
    assert "mybackup_FULL_2024-04-01" in out
    assert "note.txt" not in out




from dar_backup.util import get_invocation_command_line

def test_get_invocation_command_line_positive(monkeypatch):
    """
    Positive test:
    Simulates reading from /proc/[pid]/cmdline and verifies the reconstructed command line.
    """
    fake_cmdline = b"/usr/bin/python3\x00myscript.py\x00--option\x00value"

    def mock_open(*args, **kwargs):
        from io import BytesIO
        return BytesIO(fake_cmdline)

    monkeypatch.setattr("builtins.open", mock_open)
    result = get_invocation_command_line()

    assert isinstance(result, str)
    assert "/usr/bin/python3 myscript.py --option value" in result

def test_get_invocation_command_line_negative(monkeypatch):
    """
    Negative test:
    Simulates a file read failure (e.g. missing /proc/[pid]/cmdline) and verifies fallback message.
    """
    def mock_open(*args, **kwargs):
        raise FileNotFoundError("simulated missing /proc file")

    monkeypatch.setattr("builtins.open", mock_open)
    result = get_invocation_command_line()

    assert isinstance(result, str)
    assert "error" in result.lower()
    assert "could not read" in result.lower()
