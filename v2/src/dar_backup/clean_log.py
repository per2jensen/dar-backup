#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later

"""
clean-log.py source code is here: https://github.com/per2jensen/dar-backup/tree/main/v2/src/dar_backup/clean-log.py
This script is part of dar-backup, a backup solution for Linux using dar and systemd.

Licensed under GNU GENERAL PUBLIC LICENSE v3, see the supplied file "LICENSE" for details.

THERE IS NO WARRANTY FOR THE PROGRAM, TO THE EXTENT PERMITTED BY APPLICABLE LAW, 
not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
See section 15 and section 16 in the supplied "LICENSE" file

This script can be used to remove (much of) the logged output from `dar`.
When `dar` verbose options are enabled, quite a lot of information is emitted.

If a rerex is matched, the entire line is removed (change in v2-beta-0.6.19).
"""


import argparse
import re
import os
import sys 

from dar_backup import __about__ as about
from dar_backup.config_settings import ConfigSettings

LICENSE = '''Licensed under GNU GENERAL PUBLIC LICENSE v3, see the supplied file "LICENSE" for details.
THERE IS NO WARRANTY FOR THE PROGRAM, TO THE EXTENT PERMITTED BY APPLICABLE LAW, not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
See section 15 and section 16 in the supplied "LICENSE" file.'''

def clean_log_file(log_file_path, dry_run=False):
    """Removes specific log lines from the given file using a memory-efficient streaming approach."""


    if not os.path.isfile(log_file_path):
        print(f"File '{log_file_path}' not found!")
        sys.exit(127)

    if not os.access(log_file_path, os.R_OK):
        print(f"No read permission for '{log_file_path}'")
        sys.exit(1)

    if not os.access(log_file_path, os.W_OK):
        print(f"Error: No write permission for '{log_file_path}'")
        sys.exit(1)


    if dry_run:
        print(f"Performing a dry run on: {log_file_path}")

    temp_file_path = log_file_path + ".tmp"
    
    patterns = [
        r"INFO\s*-\s*Inspecting\s*directory",
        r"INFO\s*-\s*Finished\s*Inspecting",
        r"INFO\s*-\s*<File",
        r"INFO\s*-\s*</File",
        r"INFO\s*-\s*<Attributes",
        r"INFO\s*-\s*</Attributes",
        r"INFO\s*-\s*</Directory",
        r"INFO\s*-\s*<Directory",
        r"INFO\s*-\s*<Catalog",
        r"INFO\s*-\s*</Catalog",
        r"INFO\s*-\s*<Symlink",
        r"INFO\s*-\s*</Symlink",
    ]

    try:
        with open(log_file_path, "r", errors="ignore") as infile, open(temp_file_path, "w") as outfile:

            for line in infile:
                original_line = line  # Store the original line before modifying it
                matched = False  # Track if a pattern is matched

                for pattern in patterns:
                    if re.search(pattern, line):  # Check if the pattern matches
                        if dry_run:
                            print(f"Would remove: {original_line.strip()}")  # Print full line for dry-run
                        matched = True  # Mark that a pattern matched
                        break  # No need to check other patterns if one matches

                if not dry_run and not matched:  # In normal mode, only write non-empty lines
                    outfile.write(line.rstrip() + "\n")

                if dry_run and matched:
                    continue  # In dry-run mode, skip writing (since we’re just showing)

        
        # Ensure the temp file exists before renaming
        if not os.path.exists(temp_file_path):
            open(temp_file_path, "w").close()  # Create an empty file if nothing was written

        os.replace(temp_file_path, log_file_path)
        print(f"Successfully cleaned log file: {log_file_path}")

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

    config_settings = ConfigSettings(os.path.expanduser(os.path.expandvars(args.config_file)))

    if not args.file:
        args.file = [config_settings.logfile_location]

    for file_path in args.file:

        if ".." in os.path.normpath(file_path).split(os.sep):
            print(f"Error: Path traversal is not allowed: '{file_path}'")
            sys.exit(1)

        logfile_dir = os.path.dirname(os.path.realpath(config_settings.logfile_location))
        resolved_path = os.path.realpath(file_path)

        if not resolved_path.startswith(logfile_dir + os.sep):
            print(f"Error: File is outside allowed directory: '{file_path}'")
            sys.exit(1)

        # Validate the file path type and existence        
        if not isinstance(file_path, (str, bytes, os.PathLike)):
            print(f"Error: Invalid file path type: {file_path}")
            sys.exit(1)

        if not os.path.exists(file_path):
            print(f"Error: Log file '{file_path}' does not exist.")
            sys.exit(1)

        if file_path.strip() == "":
            print(f"Error: Invalid empty filename '{file_path}'.")
            sys.exit(1)


    # Run the log file cleaning function
    for log_file in args.file:
        clean_log_file(log_file, dry_run=args.dry_run)
    print(f"Log file '{args.file}' has been cleaned successfully.")


if __name__ == "__main__":
    main()
