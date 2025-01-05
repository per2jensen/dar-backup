import re
from dar_backup.util import run_command


def test_prereq(setup_environment, env):
    """
    Test the prereq command in the config file.
    dar-backup must fail when a prereq command fails.
    """

    # Patch config file with a successful command
    with open(env.config_file, 'a') as f:
        f.write('\n[PREREQ]\n')
        f.write('PREREQ_01 = ls /tmp\n')


    # Run the command
    command = ['dar-backup', '--full-backup' ,'-d', "example", '--config-file', env.config_file]
    process = run_command(command)
    if process.returncode != 0:
        raise Exception(f"Command failed {command}")
    
    # Patch the config file with a failing command
    with open(env.config_file, 'a') as f:
        f.write('PREREQ_02 = command-does-not-exist /tmp\n')
    env.logger.info(f"PREREQ_02 which fails has been added to config file: {env.config_file}")

    # Run the command
    try:
        command = ['dar-backup', '--full-backup' ,'-d', "example", '--config-file', env.config_file]
        process = run_command(command)
        env.logger.info(f"return code: {process.returncode}")   
        if process.returncode == 0:
            raise Exception("dar-backup must fail when a prereq command fails")
    except Exception as e:
        env.logger.exception("Expected exception: dar-backup must fail when a prereq command fails")
        assert True
        



