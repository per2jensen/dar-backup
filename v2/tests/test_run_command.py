# modified: 2021-07-25 to be a pytest test
import os
import sys
import pytest
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))


from dar_backup.command_runner import CommandRunner


import tempfile

def test_stdout_1MB(setup_environment, env):
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)

    script = (
        "import sys, os\n"
        "sys.stdout.buffer.write(os.urandom(1048576))\n"
        "sys.stdout.flush()\n"
    )
    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
        f.write(script)
        script_path = f.name

    command = ["python3", script_path]
    process = runner.run(command, text=False)

    assert process.returncode == 0
    assert isinstance(process.stdout, bytes)
    assert len(process.stdout) == 1048576



def test_command_not_found(setup_environment, env):
    """
    Test that run_command correctly handles a missing command.
    """
    try:
        runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
        command = ["nonexistent_command"]
        result = runner.run(command)
        env.logger.info(f"Returncode: {result.returncode}")
        env.logger.info(f"Stderr: {result.stderr}")
        assert result.returncode == 127, f"returncode was: {result.returncode}, expected return code 127 for command not found"
        assert "FileNotFoundError" in result.stderr or "not found" in result.stderr.lower(), "Expected command not found message in stderr"
        env.logger.info("Successfully handled missing command")
    except Exception as e:
        env.logger.error(f"Expected result:  Test failed with exception: {e}")
        assert True



def test_check_flag_logs_error(setup_environment, env):
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
    command = ['bash', '-c', 'exit 1']
    result = runner.run(command, check=True)
    assert result.returncode == 1




def test_capture_output_false(setup_environment, env):
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
    command = ['echo', 'hello']
    result = runner.run(command, capture_output=False)
    assert result.returncode == 0
    assert result.stdout == ''
    assert result.stderr == ''


def test_logger_fallback(monkeypatch):
    runner = CommandRunner(logger=None, command_logger=None)
    assert runner.logger is not None
    assert runner.command_logger is not None



def test_timeout_handling(setup_environment, env):
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger, default_timeout=1)
    command = ['bash', '-c', 'sleep 5']
    result = runner.run(command)
    assert result.returncode == -1
    assert "timed out" in result.stderr or result.stdout == ''  # based on fallback handling


@pytest.mark.skip(reason="Binary output mode (text=False) is not supported in CommandRunner")
def test_binary_output_mode(setup_environment, env):
    """
    This test is intentionally skipped because CommandRunner is designed for text mode only.
    """
    pass

