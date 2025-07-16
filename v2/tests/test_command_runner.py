import logging
import tempfile
import os
import pytest
import sys
import re
import tempfile

from dar_backup.command_runner import CommandRunner, CommandResult
from io import StringIO
from unittest.mock import patch, MagicMock



def test_command_runner_executes_successfully():
    # Setup temporary log files
    main_log = tempfile.NamedTemporaryFile(delete=False)
    command_log = tempfile.NamedTemporaryFile(delete=False)

    logger = logging.getLogger("main_logger_test")
    command_logger = logging.getLogger("command_logger_test")
    logger.setLevel(logging.DEBUG)
    command_logger.setLevel(logging.DEBUG)

    main_handler = logging.FileHandler(main_log.name)
    command_handler = logging.FileHandler(command_log.name)

    logger.addHandler(main_handler)
    command_logger.addHandler(command_handler)

    # Run a simple echo command
    runner = CommandRunner(logger=logger, command_logger=command_logger)
    result = runner.run(["echo", "Hello, world!"])

    # Validate the result
    assert result.returncode == 0
    assert "Hello, world!" in result.stdout
    
    # Check that log files captured the output
    with open(command_log.name) as f:
        command_log_output = f.read()
        print("\n===== command log  ======\n", command_log_output)
        assert "Executing command: "in command_log_output
        assert "Hello, world!" in command_log_output

    with open(main_log.name) as f:
        main_log_output = f.read()
        print("\n===== main log  ======\n", main_log_output)
        assert "Executing command" in main_log_output

    # Clean up
    os.unlink(main_log.name)
    os.unlink(command_log.name)



def test_logger_fallback_creates_loggers_and_files(tmp_path):
    runner = CommandRunner()
    
    with patch("tempfile.NamedTemporaryFile") as mock_tmp:
        # Setup two temp files (main log, command log)
        main_log_path = tmp_path / "main.log"
        command_log_path = tmp_path / "command.log"
        
        mock_tmp.side_effect = [
            type("MockFile", (), {"name": str(main_log_path), "close": lambda self: None})(),
            type("MockFile", (), {"name": str(command_log_path), "close": lambda self: None})(),
        ]

        runner.logger_fallback()

        # Log something to both
        runner.logger.info("Testing main log")
        runner.command_logger.info("Testing command log")

        # Make sure log files were written to
        with open(main_log_path) as f:
            main_log_content = f.read()
        with open(command_log_path) as f:
            command_log_content = f.read()

        assert "Testing main log" in main_log_content
        assert "Testing command log" in command_log_content



def test_logger_fallback_raises_on_filehandler_failure():
    runner = CommandRunner()

    with patch("tempfile.NamedTemporaryFile", side_effect=IOError("tempfile fail")):
        with pytest.raises(IOError, match="tempfile fail"):
            runner.logger_fallback()



def test_logger_fallback_logger_names():
    runner = CommandRunner()
    runner.logger_fallback()

    assert runner.logger.name == "command_runner_fallback_main_logger"
    assert runner.command_logger.name == "command_runner_fallback_command_logger"




def test_logger_fallback_warns_to_stderr():
    runner = CommandRunner.__new__(CommandRunner)  # bypass __init__

    with patch("sys.stderr", new_callable=StringIO) as mock_stderr:
        runner.logger_fallback()

        output = mock_stderr.getvalue()
        assert "[WARN] Using fallback loggers:" in output

        # Match and verify both log file paths
        match = re.search(r"Main log: (.+)\n  Command log: (.+)", output)
        assert match, "Expected log file paths not found in stderr"
        main_log_path = match.group(1)
        command_log_path = match.group(2)

        # Confirm those files actually exist
        assert tempfile.gettempdir() in main_log_path
        assert tempfile.gettempdir() in command_log_path



from dar_backup.command_runner import CommandRunner
def test_command_runner_fallback_logger(monkeypatch):
    runner = CommandRunner(logger=None, command_logger=None)
    assert runner.logger is not None
    assert runner.command_logger is not None





def test_command_runner_captures_all_outputs():
    runner = CommandRunner()

    # This will produce both stdout and stderr and return error
    result = runner.run(
        ['bash', '-c', 'echo "hello stdout"; echo "oops stderr" >&2; exit 2'],
        check=False
    )

    assert isinstance(result, CommandResult)
    assert result.returncode == 2
    assert "hello stdout" in result.stdout
    assert "oops stderr" in result.stderr
    assert result.stack is None  # Normal non-zero exit, no exception

def test_command_runner_stacktrace_on_failure():
    runner = CommandRunner()

    # Induce a subprocess failure via invalid command to trigger exception
    result = runner.run(['nonexistent-command'], check=False)

    assert isinstance(result, CommandResult)
    assert result.returncode == -1
    assert "No such file or directory" in result.stderr or result.stdout
    assert result.stack is not None
    assert "Traceback" in result.stack
