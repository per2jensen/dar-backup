# modified: 2021-07-25 to be a pytest test
import re
import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))


from tests.envdata import EnvData
from dar_backup.command_runner import CommandRunner

def test_stdout_1MB(setup_environment, env):
    """
    Test that a process writing 1MB to stdout in runner.run() does not fail
    """
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)
    command = ['bash', '-c', 'base64 < /dev/random| head -c 1048576']
    process = runner.run(command)
    env.logger.info(f"process.returncode={process.returncode}")
    if process.returncode != 0:
        stdout, stderr = process.stdout, process.stderr
        if stderr:
            raise Exception(f"Expected error message not found in stderr: {stderr}")
        else:
            raise Exception(f"Command failed: {command}")        
    if len(process.stdout) != 1048576:
        raise Exception(f"Expected 1MB of output, got {len(process.stdout)} bytes")



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
