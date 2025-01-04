# modified: 2021-07-25 to be a pytest test
import re

from tests.envdata import EnvData
from dar_backup.util import run_command

def test_restoredir_requires_value(setup_environment, env):
    command = ['dar-backup', '--restore', '--restore-dir', '--log-stdout', '--log-level', 'debug', '--config-file', env.config_file]
    process = run_command(command)
    env.logger.info(f"process.returncode={process.returncode}")
    if process.returncode == 0:
        raise Exception(f'dar-backup must fail because a value to --restore-dir is not given')
    else:
        stdout, stderr = process.communicate()
        if not re.search('usage: dar-backup', stderr):
            raise Exception(f"Expected error message not found in stderr: {stderr}")
        env.logger.info(f"process.returncode={process.returncode} which is expected")


                        