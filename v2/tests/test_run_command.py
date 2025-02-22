# modified: 2021-07-25 to be a pytest test
import re

from tests.envdata import EnvData
from dar_backup.util import run_command

def test_stdout_1MB(setup_environment, env):
    """
    Test that a process writing 1MB to stdout in run_command() does not fail
    """
    command = ['bash', '-c', 'base64 < /dev/random| head -c 1048576']
    process = run_command(command)
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
    command = ["nonexistent_command"]
    result = run_command(command)
    
    assert result.returncode == 127, "Expected return code 127 for command not found"
    assert "Command not found" in result.stderr or "not found" in result.stderr.lower(), "Expected command not found message in stderr"
    env.logger.info("Successfully handled missing command")
                        