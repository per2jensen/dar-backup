import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))
from dar_backup.command_runner import CommandRunner


def test_prereq(setup_environment, env):
    """
    Test the prereq command in the config file.
    dar-backup must fail when a prereq command fails.
    """
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)

    # Patch config file with a successful command
    with open(env.config_file, 'a') as f:
        f.write('\n[PREREQ]\n')
        f.write('PREREQ_01 = ls /tmp\n')

    command = ['dar-backup', '--full-backup', '-d', "example", '--config-file', env.config_file]
    process = runner.run(command)
    if process.returncode != 0:
        raise Exception(f"Command failed {command}")

    # Patch the config file with a failing command
    with open(env.config_file, 'a') as f:
        f.write('PREREQ_02 = command-does-not-exist /tmp\n')
    env.logger.info(f"PREREQ_02 which fails has been added to config file: {env.config_file}")

    try:
        command = ['dar-backup', '--full-backup', '-d', "example", '--config-file', env.config_file]
        process = runner.run(command)
        env.logger.info(f"return code: {process.returncode}")
        if process.returncode == 0:
            raise Exception("dar-backup must fail when a prereq command fails")
    except Exception:
        env.logger.exception("Expected exception: dar-backup must fail when a prereq command fails")
        assert True
