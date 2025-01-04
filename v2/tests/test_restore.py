# modified: 2021-07-25 to be a pytest test
import importlib
import re
import sys
import os

from tests.envdata import EnvData
from dar_backup.util import run_command

def test_restoredir_requires_value(setup_environment, env):
    command = ['dar-backup', '--restore', '--restore-dir', , '--log-stdout']
    process = run_command(command)
    if process.returncode == 0:
        raise Exception(f'dar-backup must fail because a value to --restore-dir is not given')


                        