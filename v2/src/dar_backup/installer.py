#!/usr/bin/env python3
"""
installer.py source code is here: https://github.com/per2jensen/dar-backup/tree/main/v2/src/dar_backup/installer.py
This script is part of dar-backup, a backup solution for Linux using dar and systemd.

Licensed under GNU GENERAL PUBLIC LICENSE v3, see the supplied file "LICENSE" for details.

THERE IS NO WARRANTY FOR THE PROGRAM, TO THE EXTENT PERMITTED BY APPLICABLE LAW, 
not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
See section 15 and section 16 in the supplied "LICENSE" file

This script can be used to configure dar-backup on your system.
It is non-destructive and will not overwrite any existing files or directories.
"""

import argparse
import os
import shutil
import sys 

from . import __about__ as about
from pathlib import Path

LICENSE = '''Licensed under GNU GENERAL PUBLIC LICENSE v3, see the supplied file "LICENSE" for details.
THERE IS NO WARRANTY FOR THE PROGRAM, TO THE EXTENT PERMITTED BY APPLICABLE LAW, not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
See section 15 and section 16 in the supplied "LICENSE" file.'''

CONFIG_DIR = os.path.expanduser("~/.config/dar-backup")
DAR_BACKUP_DIR = os.path.expanduser("~/dar-backup/")

BACKUP_DEFINITION = '''
# Demo of a `dar-backup` definition file
# This back definition file configures a backup of ~/.config/dar-backup
# `dar-backup` puts the backups in ~/dar-backup/backups
# ------------------------------------------------------------------------

# Switch to ordered selection mode, which means that the following options
# will be considered top to bottom
-am

# Backup Root dir
-R @@HOME_DIR@@

# Directories to backup below the Root dir
-g .config/dar-backup

# Examples of directories to exclude below the Root dir
 -P mnt
 -P .private
 -P .cache   

# compression level
 -z5

 # no overwrite, if you rerun a backup, 'dar' halts and asks what to do
 -n
 
 # size of each slice in the archive
 --slice 10G

# bypass directores marked as cache directories
# http://dar.linux.free.fr/doc/Features.html
--cache-directory-tagging
'''


def main():
    parser = argparse.ArgumentParser(
        description="Set up `dar-backup` on your system.",
    )
    parser.add_argument(
        "-i", "--install",
        action="store_true",
        help="Deploy a simple config file, use ~/dar-backup/ for log file, archives and restore tests."
    )
    parser.add_argument(
        "-v", "--version",
        action="version",
        version=f"%(prog)s version {about.__version__}, {LICENSE}"
    )

    args = parser.parse_args()

    if args.install:
        errors = []
        if os.path.exists(CONFIG_DIR):
            errors.append(f"Config directory '{CONFIG_DIR}' already exists.")
        if os.path.exists(DAR_BACKUP_DIR):
            errors.append(f"Directory '{DAR_BACKUP_DIR}' already exists.")

        if errors:
            for error in errors:
                print(f"Error: {error}")
            sys.exit(1)

        try:
            os.makedirs(DAR_BACKUP_DIR, exist_ok=False)
            os.makedirs(os.path.join(DAR_BACKUP_DIR, "backups"), exist_ok=False)
            os.makedirs(os.path.join(DAR_BACKUP_DIR, "restore"), exist_ok=False)
            os.makedirs(CONFIG_DIR, exist_ok=False)
            os.makedirs(os.path.join(CONFIG_DIR, "backup.d"), exist_ok=False)
            print(f"Directories created: `{DAR_BACKUP_DIR}` and `{CONFIG_DIR}`")

            script_dir = Path(__file__).parent
            source_file = script_dir / "dar-backup.conf"
            destination_file = Path(CONFIG_DIR) / "dar-backup.conf"

            try:
                shutil.copy2(source_file, destination_file)
                print(f"Config file deployed to {destination_file}")
            except Exception as e:
                print(f"Error: Could not copy config file: {e}")
                sys.exit(1)


            backup_definition = BACKUP_DEFINITION.replace("@@HOME_DIR@@", os.path.expanduser("~"))

            try:
                with open(os.path.join(CONFIG_DIR, "backup.d", "default"), "w") as f:
                    f.write(backup_definition)
                print(f"Default backup definition file deployed to {os.path.join(CONFIG_DIR, 'backup.d', 'default')}")
            except Exception as e:
                print(f"Error: Could not write default backup definition: {e}")
                sys.exit(1)
        except Exception as e:
            print(f"Installation failed: {e}")
            sys.exit(1)

        print("1. Now run `manager --create` to create the catalog database.")
        print("2. Then you can run `dar-backup --full-backup` to create a backup.")
        print("3. List backups with `dar-backup --list`")
        print("4. List contents of a backup with `dar-backup --list-contents <backup-name>`")

    sys.exit(0)


if __name__ == "__main__":
    main()
