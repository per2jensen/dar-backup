import glob
import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))
from dar_backup.command_runner import CommandRunner


from envdata import EnvData

def delete_backups(env: EnvData):
    # Patterns for the file types to delete
    patterns = ["*.dar", "*.par2"]
    # Find and delete matching files
    for pattern in patterns:
        glob_pattern = os.path.join(env.backup_dir, pattern)
        files_to_delete = glob.glob(glob_pattern)  # Search for matching files
        for file_path in files_to_delete:
            env.logger.info(file_path)
            try:
                os.remove(file_path)
                env.logger.info(f"Removed: {file_path}")
            except Exception:
                pass

def test_postreq(setup_environment, env):
    """
    Test the postreq command in the config file.
    dar-backup must fail when a prereq command fails.
    """
    runner = CommandRunner(logger=env.logger, command_logger=env.command_logger)

    # Patch config file with a successful command
    with open(env.config_file, 'a') as f:
        f.write('\n[POSTREQ]\n')
        f.write(f'POSTREQ_01 = ls {env.backup_dir}\n')


    # Run the command
    command = ['dar-backup', '--full-backup' ,'-d', "example", '--config-file', env.config_file, '--log-level', 'debug']
    process = runner.run(command)
    assert process.returncode == 0

    # Patch the config file with a failing command
    with open(env.config_file, 'a') as f:
        f.write('PREREQ_02 = command-does-not-exist /tmp\n')

    # cleanup first backup, otherwise the POSTREQ result is skewed
    delete_backups(env)

    # Run the command
    try:
        command = ['dar-backup', '--full-backup' ,'-d', "example", '--config-file', env.config_file, '--log-stdout' ]
        process = runner.run(command)
        assert process.returncode != 0, "dar-backup must fail when a postreq command fails"    
    except Exception:
        env.logger.exception("Expected exception: dar-backup must fail when a prereq command fails")
        assert False, "dar-backup must fail when a prereq command fails"
        



