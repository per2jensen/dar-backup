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
import tempfile

from datetime import datetime
from typing import Optional, Tuple

from dar_backup import __about__ as about
from dar_backup.config_settings import ConfigSettings
from dar_backup.util import send_discord_message, get_logger

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

def _split_level_and_message(line: str) -> Tuple[Optional[str], Optional[str]]:
    """Split a log line into its level and message, handling both log formats.

    Two formats are supported: timestamped lines (e.g.
    "2026-01-01 12:00:00,000 - INFO - <File ...>") and plain "LEVEL - message"
    lines with no timestamp prefix. A line is treated as timestamped only if
    its first " - "-separated segment matches a leading YYYY-MM-DD date.

    Args:
        line: A single log line (trailing newline is stripped internally).

    Returns:
        A (level, message) tuple, or (None, None) if line contains no " - "
        separator at all (not a recognizable level/message line).
    """
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

def _should_remove_line(line: str) -> bool:
    """Check whether a log line is verbose dar output that should be stripped.

    Args:
        line: A single log line to check.

    Returns:
        True iff line is an INFO-level line whose message starts with one of
        CLEAN_MESSAGE_PREFIXES (dar's verbose per-file/directory chatter).
    """
    level, message = _split_level_and_message(line)
    if level != "INFO" or message is None:
        return False
    message = message.lstrip()
    return any(message.startswith(prefix) for prefix in CLEAN_MESSAGE_PREFIXES)

def clean_log_file(log_file_path: str, dry_run: bool = False) -> None:
    """Strip verbose dar output lines from a log file, streaming line by line.

    The file is rewritten via a temp file in the same directory (tempfile.mkstemp
    + os.replace) so a failure partway through never leaves the original log
    file partially modified.

    Args:
        log_file_path: Path to the log file to clean.
        dry_run: If True, print which lines would be removed without modifying
            the file.

    Returns:
        None. Does not raise on invalid input or I/O failure — instead prints
        a message and calls sys.exit(): 127 if log_file_path does not exist,
        1 for a permission error or any other read/write failure.
    """


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
        what = f"reading '{log_file_path}'"
        try:
            with open(log_file_path, errors="ignore") as infile:
                for line in infile:
                    if _should_remove_line(line):
                        print(f"Would remove: {line.strip()}")
        except OSError as e:
            print(f"Error {what}: {e}", file=sys.stderr)
            sys.exit(1)
        return

    dir_name = os.path.dirname(os.path.abspath(log_file_path))
    tmp_fd, temp_file_path = tempfile.mkstemp(
        dir=dir_name, prefix=os.path.basename(log_file_path) + "."
    )
    replaced = False
    what = f"writing temp file '{temp_file_path}'"
    try:
        with os.fdopen(tmp_fd, "w") as outfile, open(log_file_path, errors="ignore") as infile:
            for line in infile:
                if not _should_remove_line(line):
                    outfile.write(line.rstrip() + "\n")

        what = f"replacing '{log_file_path}' with temp file"
        os.replace(temp_file_path, log_file_path)
        replaced = True
        print(f"Successfully cleaned log file: {log_file_path}")

    except OSError as e:
        print(f"Error {what}: {e}", file=sys.stderr)
        sys.exit(1)
    finally:
        if not replaced and os.path.exists(temp_file_path):
            os.unlink(temp_file_path)



def main() -> None:
    """CLI entrypoint: validate --file path(s) and clean each one.

    Loads config to determine the allowed log directory (defaults to the
    configured LOGFILE_LOCATION's directory if --file is not given), rejects
    any path containing ".." or resolving outside that directory, then calls
    clean_log_file() on each validated path.

    Exits non-zero (127 for a config error, 1 for any validation or cleaning
    failure) rather than raising; never returns a value on success.
    """
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

    try:
        config_settings = ConfigSettings(os.path.expanduser(os.path.expandvars(args.config_file)))
    except Exception as exc:  # noqa: BLE001 — CLI-boundary catch: logs with context, reports, and exits
        msg = f"Config error: {exc}"
        print(msg, file=sys.stderr)
        ts = datetime.now().astimezone().strftime("%Y-%m-%d_%H:%M")
        send_discord_message(f"{ts} - clean-log: FAILURE - {msg}")
        sys.exit(127)

    try:
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
    except Exception as e:
        msg = f"Unexpected error during clean-log: {e}"
        logger = get_logger()
        if logger:
            logger.error(msg, exc_info=True)
        else:
            print(msg, file=sys.stderr)

        ts = datetime.now().astimezone().strftime("%Y-%m-%d_%H:%M")
        send_discord_message(f"{ts} - clean-log: FAILURE - {msg}", config_settings=config_settings)
        sys.exit(1)
if __name__ == "__main__":
    main()
