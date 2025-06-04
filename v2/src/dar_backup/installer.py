#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later

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
from dar_backup.util import is_safe_path

def install_autocompletion():
    """Detect user shell, choose RC file, and idempotently append autocompletion."""
    shell = Path(os.environ.get("SHELL", "")).name
    home = Path.home()

    # pick RC file based on shell
    if shell == "zsh":
        rc_file = home / ".zshrc"
    elif shell == "bash":
        # prefer ~/.bash_profile on macOS if present
        rc_file = home / ".bash_profile" if (home / ".bash_profile").exists() else home / ".bashrc"
    else:
        rc_file = home / ".bashrc"

    marker = "# >>> dar-backup autocompletion >>>"
    end_marker = "# <<< dar-backup autocompletion <<<"

    block = "\n".join([
        marker,
        'eval "$(register-python-argcomplete dar-backup)"',
        'eval "$(register-python-argcomplete cleanup)"',
        'eval "$(register-python-argcomplete manager)"',
        "#complete -o nosort -C 'python -m argcomplete cleanup' cleanup",
        "#complete -o nosort -C 'python -m argcomplete manager' manager",
        end_marker,
    ]) + "\n"

    # ensure RC file and parent directory exist
    rc_file.parent.mkdir(parents=True, exist_ok=True)
    if not rc_file.exists():
        rc_file.touch()

    content = rc_file.read_text()
    if marker in content:
        print(f"Autocompletion already installed in {rc_file}")
        return

    # append the autocompletion block
    rc_file.open("a").write("\n" + block)
    print(f"✔️ Appended autocompletion block to {rc_file}")



def uninstall_autocompletion() -> str:
    """Remove previously installed autocompletion block from shell RC file."""
    shell = Path(os.environ.get("SHELL", "")).name
    home = Path.home()

    # pick RC file based on shell
    if shell == "zsh":
        rc_file = home / ".zshrc"
    elif shell == "bash":
        rc_file = home / ".bash_profile" if (home / ".bash_profile").exists() else home / ".bashrc"
    else:
        rc_file = home / ".bashrc"

    marker = "# >>> dar-backup autocompletion >>>"
    end_marker = "# <<< dar-backup autocompletion <<<"

    if not rc_file.exists():
        print(f"❌ RC file not found: {rc_file}")
        return

    content = rc_file.read_text()
    if marker not in content:
        print(f"No autocompletion block found in {rc_file}")
        return f"No autocompletion block found in {rc_file}"  # for unit test

    lines = content.splitlines(keepends=True)
    new_lines = []
    skipping = False
    for line in lines:
        if marker in line:
            skipping = True
            continue
        if end_marker in line and skipping:
            skipping = False
            continue
        if not skipping:
            new_lines.append(line)

    rc_file.write_text(''.join(new_lines))
    print(f"✔️ Removed autocompletion block from {rc_file}")



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

    print(f"Using config settings: {config_settings}")

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
        if not is_safe_path(dir_path):
            logger.error(f"Unsafe path detected: {dir_path} ({name})")
            raise ValueError(f"Unsafe path detected: {dir_path} ({name})")
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
                print(f"✔️  Catalog created (or already exist): {backup_def}")
            else:
                print(f"❌ Failed to create catalog: {backup_def}")


def main():
    parser = argparse.ArgumentParser(description="dar-backup installer")
    parser.add_argument("--config", required=False, help="Path to config file")
    parser.add_argument("--create-db", action="store_true", help="Create catalog databases")
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--install-autocompletion", action="store_true",
        help="Append shell-completion setup to your shell RC"
    )
    group.add_argument(
        "--remove-autocompletion", action="store_true",
        help="Remove shell-completion setup from your shell RC"
    )
    parser.add_argument(
        "-v", "--version", action="version",
        version=f"%(prog)s version {about.__version__}, {about.__license__}"
    )

    args = parser.parse_args()


    if args.config:
        if not os.path.exists(args.config):
            print(f"❌ Config file does not exist: {args.config}")
            return
        run_installer(args.config, args.create_db)

    if args.install_autocompletion:
        install_autocompletion()
    elif args.remove_autocompletion:
        uninstall_autocompletion()  

    

if __name__ == "__main__":
    main()
