# modified: 2021-07-25 to be a pytest test
import importlib
import re
import sys
import os

from tests.envdata import EnvData
from dar_backup.util import run_command
from dar_backup import __about__ as about


def test_version(setup_environment, env: EnvData):

    command = ['clean-log', '-v']
    process = run_command(command)
    if process.returncode != 0:
        raise Exception(f"Command failed {command}")
    env.logger.info("clean-log -v:\n" + process.stdout)


    assert f"clean-log version {about.__version__}" in process.stdout, f"Version # not found in output"   



