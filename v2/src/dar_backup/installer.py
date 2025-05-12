import argparse
import os
from . import __about__ as about
from pathlib import Path
from dar_backup.config_settings import ConfigSettings
from dar_backup.util import setup_logging, get_logger
from dar_backup.command_runner import CommandRunner
from dar_backup.manager import create_db
# Always expand manager DB dir correctly, using helper function
from dar_backup.manager import get_db_dir
from dar_backup.util import expand_path



def run_installer(config_file: str, create_db_flag: bool):
    """
    Run the installation process for dar-backup using the given config file.

    This includes:
    - Expanding and parsing the config file
    - Setting up logging
    - Creating required backup directories
    - Optionally initializing catalog databases for all backup definitions

    Args:
        config_file (str): Path to the configuration file (may include ~ or env vars).
        create_db_flag (bool): If True, databases are initialized for each backup definition.
    """
    config_file = os.path.expanduser(os.path.expandvars(config_file))
    config_settings = ConfigSettings(config_file)

    # Set up logging
    command_log = config_settings.logfile_location.replace("dar-backup.log", "dar-backup-commands.log")
    logger = setup_logging(
        config_settings.logfile_location,
        command_log,
        log_level="info",
        log_to_stdout=True,
    )
    command_logger = get_logger(command_output_logger=True)
    runner = CommandRunner(logger=logger, command_logger=command_logger)


    # Create required directories
    required_dirs = {
        "backup_dir": config_settings.backup_dir,
        "test_restore_dir": config_settings.test_restore_dir,
        "backup_d_dir": config_settings.backup_d_dir,
        "manager_db_dir": get_db_dir(config_settings),
    }

    for name, dir_path in required_dirs.items():
        expanded = Path(expand_path(dir_path))
        if not expanded.exists():
            logger.info(f"Creating directory: {expanded} ({name})")
            expanded.mkdir(parents=True, exist_ok=True)

    # Optionally create databases for all backup definitions
    if create_db_flag:
        for file in os.listdir(config_settings.backup_d_dir):
            backup_def = os.path.basename(file)
            print(f"Creating catalog for: {backup_def}")
            result = create_db(backup_def, config_settings, logger, runner)
            if result == 0:
                print(f"✔️  Catalog created (or already existed): {backup_def}")
            else:
                print(f"❌ Failed to create catalog: {backup_def}")


def main():
    parser = argparse.ArgumentParser(description="dar-backup installer")
    parser.add_argument("--config", required=True, help="Path to config file")
    parser.add_argument("--create-db", action="store_true", help="Create catalog databases")
    parser.add_argument("-v", "--version", action="version", version=f"%(prog)s version {about.__version__}, {about.__license__}"
    )

    args = parser.parse_args()

    run_installer(args.config, args.create_db)


if __name__ == "__main__":
    main()
