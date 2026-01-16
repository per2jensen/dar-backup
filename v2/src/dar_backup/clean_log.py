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

TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}\b")
CLEAN_MESSAGE_PREFIXES = (
    "Inspecting directory",
    "Finished Inspecting",
    "<File",
    "</File",
    "<Attributes",
    "</Attributes",
    "<Directory",
    "</Directory",
    "<Catalog",
    "</Catalog",
    "<Symlink",
    "</Symlink",
)

def _split_level_and_message(line):
    line = line.rstrip("\n")
    if " - " not in line:
        return None, None

    parts = line.split(" - ")
    if len(parts) >= 3 and TIMESTAMP_RE.match(parts[0].strip()):
        level = parts[1]
        message = " - ".join(parts[2:])
    else:
        level = parts[0]
        message = " - ".join(parts[1:])

    return level.strip(), message

def _should_remove_line(line):
    level, message = _split_level_and_message(line)
    if level != "INFO" or message is None:
        return False
    message = message.lstrip()
    return any(message.startswith(prefix) for prefix in CLEAN_MESSAGE_PREFIXES)

def clean_log_file(log_file_path, dry_run=False):
    """Removes specific log lines from the given file using a memory-efficient streaming approach."""


    if not os.path.isfile(log_file_path):
        print(f"File '{log_file_path}' not found!")
        sys.exit(127)

    if not os.access(log_file_path, os.R_OK):
        print(f"No read permission for '{log_file_path}'")
        sys.exit(1)

    if not dry_run and not os.access(log_file_path, os.W_OK):
        print(f"Error: No write permission for '{log_file_path}'")
        sys.exit(1)


    if dry_run:
        print(f"Performing a dry run on: {log_file_path}")

    temp_file_path = log_file_path + ".tmp"

    try:
        if dry_run:
            with open(log_file_path, "r", errors="ignore") as infile:
                for line in infile:
                    if _should_remove_line(line):
                        print(f"Would remove: {line.strip()}")
            return

        with open(log_file_path, "r", errors="ignore") as infile, open(temp_file_path, "w") as outfile:
            for line in infile:
                if not _should_remove_line(line):
                    outfile.write(line.rstrip() + "\n")

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

    files_to_clean = args.file if args.file else [config_settings.logfile_location]
    logfile_dir = os.path.dirname(os.path.realpath(config_settings.logfile_location))
    validated_files = []

    for file_path in files_to_clean:
        if not isinstance(file_path, (str, bytes, os.PathLike)):
            print(f"Error: Invalid file path type: {file_path}")
            sys.exit(1)

        file_path = os.fspath(file_path)
        if isinstance(file_path, bytes):
            file_path = os.fsdecode(file_path)

        if file_path.strip() == "":
            print(f"Error: Invalid empty filename '{file_path}'.")
            sys.exit(1)

        if ".." in os.path.normpath(file_path).split(os.sep):
            print(f"Error: Path traversal is not allowed: '{file_path}'")
            sys.exit(1)

        resolved_path = os.path.realpath(file_path)

        if not resolved_path.startswith(logfile_dir + os.sep):
            print(f"Error: File is outside allowed directory: '{file_path}'")
            sys.exit(1)

        if not os.path.exists(file_path):
            print(f"Error: Log file '{file_path}' does not exist.")
            sys.exit(1)

        validated_files.append(file_path)


    # Run the log file cleaning function
    for log_file in validated_files:
        clean_log_file(log_file, dry_run=args.dry_run)
    file_list = ", ".join(validated_files)
    if args.dry_run:
        print(f"Dry run complete for: {file_list}")
    else:
        print(f"Log file '{file_list}' has been cleaned successfully.")


if __name__ == "__main__":
    main()
