
from dar_backup.util import run_command


def test_prereq(setup_environment, env):
    """
    Test the prereq command in the config file.
    dar-backup must fail when a prereq command fails.
    """

    # setup_environment is a fixture
    print("env.test_dir: " + env.test_dir)

    # Patch config file with a successful command
    with open(env.config_file, 'a') as f:
        f.write('[PREREQ]\n')
        f.write('PREREQ_01 = ls /tmp\n')


    # Run the command
    command = ['dar-backup', '--full-backup' ,'-d', "example", '--config-file', env.config_file]
    process = run_command(command)

    # Patch the config file with a failing command
    with open(env.config_file, 'a') as f:
        f.write('PREREQ_02 = command-does-not-exist /tmp\n')
    
    # Run the command
    try:
        command = ['dar-backup', '--full-backup' ,'-d', "example", '--config-file', env.config_file]
        process = run_command(command)
        assert False, "dar-backup should fail when a prereq command fails"    
    except Exception as e:
        env.logger.exception("all ok, dar-backup should fail when a prereq command fails")
        assert True
        



