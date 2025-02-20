#!/usr/bin/env python3
"""
clean-log.py source code is here: https://github.com/per2jensen/dar-backup/tree/main/v2/src/dar_backup/clean-log.py
This script is part of dar-backup, a backup solution for Linux using dar and systemd.

Licensed under GNU GENERAL PUBLIC LICENSE v3, see the supplied file "LICENSE" for details.

THERE IS NO WARRANTY FOR THE PROGRAM, TO THE EXTENT PERMITTED BY APPLICABLE LAW, 
not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
See section 15 and section 16 in the supplied "LICENSE" file

This script can be used to remove (much of) the logged output from `dar`.
When `dar` verbose options are enabled, quite a lot of information is emitted.
"""


import argparse
import re
import os
import sys 

from . import __about__ as about
from dar_backup.config_settings import ConfigSettings

LICENSE = '''Licensed under GNU GENERAL PUBLIC LICENSE v3, see the supplied file "LICENSE" for details.
THERE IS NO WARRANTY FOR THE PROGRAM, TO THE EXTENT PERMITTED BY APPLICABLE LAW, not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
See section 15 and section 16 in the supplied "LICENSE" file.'''

def clean_log_file(log_file_path, dry_run=False):
    """Removes specific log lines from the given file using a memory-efficient streaming approach."""
    
    if not os.path.isfile(log_file_path):
        print(f"File '{log_file_path}' not found!")
        sys.exit(1)

    if not os.access(log_file_path, os.R_OK):
        print(f"No read permission for '{log_file_path}'")
        sys.exit(1)

    if dry_run:
        print(f"Performing a dry run on: {log_file_path}")

    temp_file_path = log_file_path + ".tmp"
    
    patterns = [
        r"INFO\s*-\s*<File",
        r"INFO\s*-\s*<Attributes",
        r"INFO\s*-\s*</Directory",
        r"INFO\s*-\s*<Directory",
        r"INFO\s*-\s*</File",
        r"INFO\s*-\s*Inspecting directory",
        r"INFO\s*-\s*Finished Inspecting"
        r"INFO - Finished Inspecting"
    ]

    try:
        with open(log_file_path, "r") as infile:
            for line in infile:
                if any(re.search(pattern, line) for pattern in patterns):
                    if dry_run:
                        print(f"Would remove: {line.strip()}")
                    continue  # Skip writing this line if not in dry-run mode

                if not dry_run:
                    with open(temp_file_path, "a") as outfile:
                        outfile.write(line)

        if not dry_run:
            os.replace(temp_file_path, log_file_path)

    except Exception as e:
        print(f"Error processing file: {e}")
        sys.exit(1)



    
def main():
    parser = argparse.ArgumentParser(
        description="Clean dar-backup log file for `dar` output"
    )
    parser.add_argument(
        "-f", "--file",
        nargs="+",
        type=str, help="Path(s) to the log file(s) that needs cleaning. Default is the log file specified in the configuration file."
    )

    parser.add_argument(
        '-c', '--config-file',
        type=str, help="Path to 'dar-backup.conf'",
        default='~/.config/dar-backup/dar-backup.conf')

    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show which lines would be removed without modifying the file."
    )


    parser.add_argument(
        "-v", "--version",
        action="version",
        version=f"%(prog)s version {about.__version__}, {LICENSE}"
    )

    args = parser.parse_args()

    config_settings = ConfigSettings(os.path.expanduser(args.config_file))

    if args.file and (not os.path.exists(args.file) or args.file.strip() == ""):
        print(f"Error: Log file '{args.file}' does not exist.")
        sys.exit(1)

    if not args.file:
        args.file = [config_settings.logfile_location]

    # Run the log file cleaning function
    for log_file in args.file:
        clean_log_file(log_file, dry_run=args.dry_run)
    print(f"Log file '{args.file}' has been cleaned successfully.")

if __name__ == "__main__":
    main()
