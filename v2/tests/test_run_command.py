# modified: 2021-07-25 to be a pytest test
import re

from tests.envdata import EnvData
from dar_backup.util import run_command

def test_stdout_1MB(setup_environment, env):
    """
    Test that a process writing 1MB to stdout works
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



                        