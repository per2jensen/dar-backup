#!/usr/bin/env python3

import argparse
import configparser
import datetime
import filecmp

import os
import random
import re
import shlex
import subprocess
import sys
import xml.etree.ElementTree as ET

from config_settings import ConfigSettings, read_config

from datetime import datetime
from pathlib import Path
from time import time

from util import list_backups
from util import run_command
from util import setup_logging
from util import BackupError
from util import DifferentialBackupError
from util import IncrementalBackupError
from util import RestoreError


VERSION = "alpha-0.3"

logger = None


def backup(backup_file, backup_definition):
    """
    Performs a full backup using the 'dar' command.

    This function initiates a full backup operation by constructing and executing a command
    with the 'dar' utility. It checks if the backup file already exists to avoid overwriting
    previous backups. If the backup file does not exist, it proceeds with the backup operation.

    Args:
        backup_file (str): The base name of the backup file. The actual backup will be saved
                           as '{backup_file}.1.dar'.
        backup_definition (str): The path to the backup definition file. This file contains
                                 specific instructions for the 'dar' utility, such as which
                                 directories to include or exclude.

    Note:
        This function logs an error and returns early if the backup file already exists.
        It logs the command being executed and reports upon successful completion of the backup.

    Raises:
        BackupError: If an error occurs during the backup process.
    """
    if os.path.exists(backup_file + '.1.dar'):
        logger.error(f"Backup file {backup_file}.1.dar already exists. Skipping backup.")
        return

    command = ['dar', '-c', backup_file, '-B', backup_definition, '-Q']
    logger.info(f"Running command: {' '.join(map(shlex.quote, command))}")
    try:
        run_command(command)
        logger.info("Backup completed successfully.")
    except subprocess.CalledProcessError as e:
        logger.error(f"Backup command failed: {e}")
        raise BackupError(f"Backup command failed: {e}") from e
    except Exception as e:
        logger.exception(f"Unexpected error during backup: {e}")
        raise BackupError(f"Unexpected error during backup: {e}") from e
 
 



def differential_backup(backup_file, backup_definition, base_backup_file):
    """
    Creates a differential backup based on a specified base backup.

    This function performs a differential backup by comparing the current state of the data
    against a specified base backup file. It captures only the changes made since that base
    backup, resulting in a smaller and faster backup process compared to a full backup.

    Args:
        backup_file (str): The base name for the differential backup file. The actual backup
                           will be saved as '{backup_file}.1.dar'.
        backup_definition (str): The path to the backup definition file. This file contains
                                 specific instructions for the 'dar' utility, such as which
                                 directories to include or exclude.
        base_backup_file (str): The base name of the full backup file that serves as the
                                reference point for the differential backup.

    Note:
        This function logs an error and returns early if the differential backup file already exists.
        It logs the command being executed and reports upon successful completion of the differential backup.

    Raises:
        DifferentialBackupError: If the differential backup command fails or encounters an unexpected error.
    """
    if os.path.exists(backup_file + '.1.dar'):
        logger.error(f"Backup file {backup_file}.1.dar already exists. Skipping backup.")
        return

    command = ['dar', '-c', backup_file, '-B', backup_definition, '-A', base_backup_file, '-Q']
    logger.info(f"Running command: {' '.join(map(shlex.quote, command))}")
    try:
        run_command(command)
        logger.info("Differential backup completed successfully.")
    except subprocess.CalledProcessError as e:
        logger.error(f"Differential backup command failed: {e}")
        raise DifferentialBackupError(f"Differential backup command failed: {e}") from e
    except Exception as e:
        logger.exception(f"Unexpected error during differential backup: {e}")
        raise DifferentialBackupError(f"Unexpected error during differential backup: {e}") from e


def incremental_backup(backup_file, backup_definition, last_backup_file):
    """
    Creates an incremental backup based on the last backup file.

    This function performs an incremental backup by comparing the current state of the data
    against the last backup file, whether it's a full backup or the most recent incremental backup.
    It captures only the changes made since that last backup, making it efficient for frequent
    backups with minimal data changes.

    Args:
        backup_file (str): The base name for the incremental backup file. The actual backup
                           will be saved with a unique identifier to distinguish it from other backups.
        backup_definition (str): The path to the backup definition file. This file contains
                                 specific instructions for the 'dar' utility, such as which
                                 directories to include or exclude.
        last_backup_file (str): The base name of the last backup file (full or incremental) that
                                serves as the reference point for the incremental backup.

    Note:
        This function checks if the incremental backup file already exists to prevent overwriting
        previous backups. It logs the command being executed and reports upon successful completion
        of the incremental backup.
    
    Raises:
        IncrementalBackupError: If the incremental backup command fails or an unexpected error occurs.
    """
    if os.path.exists(backup_file + '.1.dar'):
        logger.error(f"Backup file {backup_file}.1.dar already exists. Skipping backup.")
        return

    command = ['dar', '-c', backup_file, '-B', backup_definition, '-A', last_backup_file, '-Q']
    logger.info(f"Running command: {' '.join(map(shlex.quote, command))}")
    try:
        run_command(command)
        logger.info("Incremental backup completed successfully.")
    except subprocess.CalledProcessError as e:
        logger.error(f"Incremental backup command failed: {e}")
        raise IncrementalBackupError(f"Incremental backup command failed: {e}") from e
    except Exception as e:
        logger.exception(f"Unexpected error during incremental backup: {e}")
        raise IncrementalBackupError(f"Unexpected error during incremental backup: {e}") from e


# Function to recursively find <File> tags and build their full paths
def find_files_with_paths(element, current_path=""):
    """
    Recursively finds files within a directory element and returns a list of file paths with their sizes.

    Args:
        element (Element): The directory element to search within.
        current_path (str, optional): The current path of the directory element. Defaults to "".

    Returns:
        list: A list of tuples containing file paths and their sizes.
    """
    logger.debug(f"Recursively generate list of tuples with file paths and sizes for File elements in dar xml output")
    files = []
    if element.tag == "Directory":
        current_path = f"{current_path}/{element.get('name')}"
    for child in element:
        if child.tag == "File":
            file_path = (f"{current_path}/{child.get('name')}", child.get('size'))  # tuple (filepath, size)
            files.append(file_path)
        elif child.tag == "Directory":
            files.extend(find_files_with_paths(child, current_path))
    return files



def find_files_between_min_and_max_size(backed_up_files, min_size_verification_mb, max_size_verification_mb):
    """Find files within a specified size range.

    This function takes a list of backed up files, a minimum size in megabytes, and a maximum size in megabytes.
    It iterates through the list of files, converts the file size from the XML to a number, and compares it to the
    specified size range. If a file's size falls within the range, it is added to the result list.

    Args:
        backed_up_files (list): A list of tuples representing backed up files. Each tuple should contain at least
            two elements, where the first element is the file name and the second element is the file size in the
            format "<number> <unit>". For example, ("file.txt", "10 Mio").
        min_size_verification_mb (int): The minimum file size in megabytes.
        max_size_verification_mb (int): The maximum file size in megabytes.

    Returns:
        list: A list of file names that fall within the specified size range.
    """
    logger.debug(f"Finding files in archive between min and max sizes: {min_size_verification_mb}MB and {max_size_verification_mb}MB")
    files = []
    max_size = max_size_verification_mb
    min_size = min_size_verification_mb
    dar_sizes = {
        "o"   : 1,
        "kio" : 1024,
        "Mio" : 1024 * 1024,
        "Gio" : 1024 * 1024 * 1024,
        "Tio" : 1024 * 1024 * 1024 * 1024
     }
    pattern = r'(\d+)\s*(\w+)'
    for tuple in backed_up_files:
        if tuple is not None and len(tuple) >= 2  and tuple[0] is not None and tuple[1] is not None:
            logger.trace("tuple from dar xml list: {tuple}")
            match = re.match(pattern, tuple[1])
            if match:
                number = int(match.group(1))
                unit = match.group(2).strip()
                file_size = dar_sizes[unit] * number
            if (min_size_verification_mb  * 1024 * 1024) < file_size <= (max_size * 1024 * 1024):
                logger.trace(f"File found between min and max sizes: {tuple}")
                files.append(tuple[0])
    return files


def verify(args, backup_file, backup_definition, config_settings):
    """
    Verify the integrity of a DAR backup by performing the following steps:
    1. Run an archive integrity test on the backup file.
    2. Retrieve the list of backed up files.
    3. Find files within def perform_backup(args, ConfigSettings config_settings, backup_d, backup_dir, test_restore_dir, backup_type, min_size_verification_mb, max_size_verification_mb, no_files_verification):file and compare it with the original file.

    Args:
        args (object): Command-line arguments.
        backup_file (str): Path to the DAR backup file.
        backup_definition (str): Path to the backup definition file.
        ConfigSettings (object): An instance of the ConfigSettings class.

    Returns:
        True if the verification process completes successfully, False otherwise.

    Raises:
        Exception: If an error occurs during the verification process.
        PermissionError: If a permission error occurs while comparing files.
    """
    result = True
    test_command = ['dar', '-t', backup_file, '-Q']
    logger.info(f"Running command: {' '.join(map(shlex.quote, test_command))}")
    run_command(test_command)
    logger.info("Archive integrity test passed.")



    if args.do_not_compare:
        return result

    backed_up_files = get_backed_up_files(backup_file, config_settings.backup_dir) 

    files = find_files_between_min_and_max_size(backed_up_files, config_settings.min_size_verification_mb, config_settings.max_size_verification_mb)
    if len(files) == 0:
        logger.info(f"No files between {config_settings.min_size_verification_mb}MB and {config_settings.max_size_verification_mb}MB for verification, skipping")
        return result

    with open(backup_definition, 'r') as f:
        backup_definition_content = f.readlines()
        logger.debug(f"Backup definition: '{backup_definition}', content:\n{backup_definition_content}")
    # Initialize a variable to hold the path after "-R"
    root_path = None
    for line in backup_definition_content:
        line = line.strip()
        if line.startswith("-R"):
            root_path = line.split("-R", 1)[1].strip()
            break
    if root_path is None:
        logger.warning("No Root (-R) path specified in the backup definition file.")

    no_files_verification = config_settings.no_files_verification
    if len(files) < config_settings.no_files_verification:
        no_files_verification = len(files)
    random_files = random.sample(files, no_files_verification)
    for restored_file_path in random_files:
        try:
            logger.info(f"Restoring file: '{restored_file_path}' from backup to: '{config_settings.test_restore_dir}' for file comparing")
            command = ['dar', '-x', backup_file, '-g', restored_file_path.lstrip("/"), '-R', config_settings.test_restore_dir, '-O', '-Q']
            logger.info(f"Running command: {' '.join(map(shlex.quote, command))}")
            run_command(command)
            if filecmp.cmp(os.path.join(config_settings.test_restore_dir, restored_file_path.lstrip("/")), os.path.join(root_path, restored_file_path.lstrip("/")), shallow=False):
                logger.info(f"Success: file '{restored_file_path}' matches the original")
            else:
                logger.error(f"Failure: file '{restored_file_path}' did not match the original")
                result = False
        except PermissionError:
            result = False
            logger.exception(f"Permission error while comparing files, continuing....")

    return result



def restore_backup(backup_name, backup_dir, restore_dir, selection=None):
    """
    Restores a backup file to a specified directory.

    Args:
        backup_name (str): The name of the backup file.
        backup_dir (str): The directory where the backup file is located.
        restore_dir (str): The directory where the backup should be restored to.
        selection (str, optional): A selection criteria to restore specific files or directories. Defaults to None.
    """
    backup_file = os.path.join(backup_dir, backup_name)
    command = ['dar', '-x', backup_file, '-O', '-Q', '-D']
    if restore_dir:
        if not os.path.exists(restore_dir):
            os.makedirs(restore_dir)
        command.extend(['-R', restore_dir])
    if selection:
        selection_criteria = shlex.split(selection)
        command.extend(selection_criteria)
    logger.info(f"Running command: {' '.join(map(shlex.quote, command))}")
    try:
        run_command(command)
    except subprocess.CalledProcessError as e:
        logger.error(f"Restore command failed: {e}")
        raise RestoreError(f"Restore command failed: {e}") from e
    except Exception as e:
        logger.exception(f"Unexpected error during restore: {e}")
        raise RestoreError(f"Unexpected error during restore: {e}") from e



def get_backed_up_files(backup_name, backup_dir):
    """
    Retrieves the list of backed up files from a DAR archive.

    Args:
        backup_name (str): The name of the DAR archive.
        backup_dir (str): The directory where the DAR archive is located.

    Returns:
        list: A list of file paths for all backed up files in the DAR archive.
    """
    logger.debug(f"Getting backed up files from DAR archive in xml: '{backup_name}'")
    backup_path = os.path.join(backup_dir, backup_name)
    command = ['dar', '-l', backup_path, '-am', '-as', "-Txml" , '-Q']
    logger.info(f"Running command: {' '.join(map(shlex.quote, command))}")
    output = run_command(command)
    # Parse the XML data
    root = ET.fromstring(output)
    output = None  # help gc
    # Extract full paths and file size for all <File> elements
    file_paths = find_files_with_paths(root)
    root = None # help gc
    logger.trace(f"Backed up files in dar archive: '{backup_name}'")
    logger.trace(file_paths)
    return file_paths


def list_contents(backup_name, backup_dir, selection=None):
    """
    Lists the contents of a backup.

    Args:
        backup_name (str): The name of the backup.
        backup_dir (str): The directory where the backup is located.
        selection (str, optional): The selection criteria for listing specific contents. Defaults to None.

    Returns:
        None
    """
    backup_path = os.path.join(backup_dir, backup_name)
    command = ['dar', '-l', backup_path, '-am', '-as', '-Q']
    if selection:
        selection_criteria = shlex.split(selection)
        command.extend(selection_criteria)
    logger.info(f"Running command: {' '.join(map(shlex.quote, command))}")
    output = run_command(command)
    for line in output.splitlines():
        if "[--- REMOVED ENTRY ----]" in line or "[Saved]" in line:
            print(line)


def perform_backup(args, config_settings: ConfigSettings, backup_type):
    """
    Perform backup operation.

    Args:
        args: Command-line arguments.
        config_settings: An instance of the ConfigSettings class.
        backup_d: Directory containing backup definitions.
        backup_dir: Directory to store backup files.
        test_restore_dir: Directory to test restore backup files.
        backup_type: Type of backup (FULL, DIFF, INCR).
        min_size_verification_mb: Minimum size for verification in MB.
        max_size_verification_mb: Maximum size for verification in MB.
        no_files_verification: Flag indicating whether to skip file verification.

    Returns:
        None

    Raises:
        FileNotFoundError: If `backup_d` does not exist or a specified backup definition file does not exist.
        PermissionError: If there is insufficient permission to access directories or files specified.
        OSError: For various system-related errors, such as exhaustion of file descriptors.
        ValueError: If there is an issue with the format string in `datetime.now().strftime`.
        subprocess.CalledProcessError: If a subprocess invoked during the backup process exits with a non-zero status.
        Exception: Catches any unexpected exceptions that may occur during the backup process.

    Note: 
      This function assumes that any exceptions raised by the `backup` function or related subprocesses are handled
      within those functions or propagated up to be handled by the caller of `perform_backup`.
    """
    logger.debug(f"perform_backup({backup_type}) started")
    backup_definitions = []

    if args.backup_definition:
        backup_definitions.append((os.path.basename(args.backup_definition).split('.')[0], os.path.join(config_settings.backup_d_dir, args.backup_definition)))
    else:
        for root, _, files in os.walk(config_settings.backup_d_dir):
            for file in files:
                backup_definitions.append((file.split('.')[0], os.path.join(root, file)))

    for backup_definition, backup_definition_path in backup_definitions:
        try:
            date = datetime.now().strftime('%Y-%m-%d')
            backup_file = os.path.join(config_settings.backup_dir, f"{backup_definition}_{backup_type}_{date}")

            if os.path.exists(backup_file + '.1.dar'):
                logger.error(f"Backup file {backup_file}.1.dar already exists. Skipping backup.")
                continue

            if backup_type == 'FULL':
                backup(backup_file, backup_definition_path)
            else:
                base_backup_type = 'FULL' if backup_type == 'DIFF' else 'DIFF'
                base_backups = sorted(
                    [f for f in os.listdir(config_settings.backup_dir) if f.startswith(f"{backup_definition}_{base_backup_type}_") and f.endswith('.1.dar')],
                    key=lambda x: datetime.strptime(x.split('_')[-1].split('.')[0], '%Y-%m-%d')
                )
                if not base_backups:
                    logger.error(f"No {base_backup_type} backup found for {backup_definition}. Skipping {backup_type} backup.")
                    continue

                latest_base_backup = os.path.join(config_settings.backup_dir, base_backups[-1].rsplit('.', 2)[0])
                if backup_type == 'DIFF':
                    differential_backup(backup_file, backup_definition_path, latest_base_backup)
                elif backup_type == 'INCR':
                    incremental_backup(backup_file, backup_definition_path, latest_base_backup)

            logger.info("Starting verification...")
            result = verify(args, backup_file, backup_definition_path, config_settings)
            if result:
                logger.info("Verification completed successfully.")
            else:
                logger.error("Verification failed.")
            logger.info("Generate par2 redundancy files")
            generate_par2_files(backup_file, config_settings.backup_dir)
            logger.info("par2 files completed successfully.")
        # we want to continue with other backup definitions, thus only logging an error
        except Exception as e:
            logger.exception(f"Error during {backup_type} backup process, continuing on next backup definition: {e}")


def generate_par2_files(backup_file, backup_dir):
    """
    Generate PAR2 files for a given backup file in the specified backup directory.

    Args:
        backup_file (str): The name of the backup file.
        backup_dir (str): The path to the backup directory.

    Raises:
        subprocess.CalledProcessError: If the par2 command fails to execute.

    Returns:
        None
    """
    for filename in os.listdir(backup_dir):
        if os.path.basename(backup_file) in filename:
            # Construct the full path to the file
            file_path = os.path.join(backup_dir, filename)
            # Run the par2 command to generate redundancy files with 5% error correction
            command = ['par2', 'create', '-r5', '-q', '-q', file_path]
            run_command(command)
            #subprocess.run(command, check=True)
            logger.debug(f"par2 files generated for {file_path}")




def extract_error_lines(log_file_path, start_time, end_time):
    """
    Extracts error lines from a log file within a specific time range.

    Args:
        log_file_path (str): The path to the log file.
        start_time (str): The start time of the desired time range (unixtime).
        end_time (str): The end time of the desired time range (unixtime).

    Returns:
        list: A list of error lines within the specified time range.

    Raises:
        ValueError: If the start or end markers are not found in the log file.
    """
    with open(log_file_path, 'r') as log_file:
        lines = log_file.readlines()

    start_index = None
    end_index = None

    start_marker = f"START TIME: {start_time}"
    end_marker = f"END TIME: {end_time}"
    error_pattern = re.compile(r'ERROR')

    # Find the start and end index for the specific run
    for i, line in enumerate(lines):
        if start_marker in line:
            start_index = i
        elif end_marker in line and start_index is not None:
            end_index = i
            break

    if start_index is None or end_index is None:
        raise ValueError("Could not find start or end markers in the log file")

    error_lines = [line.rstrip("\n") for line in lines[start_index:end_index + 1] if error_pattern.search(line)]

    return error_lines


def show_version():
    script_name = os.path.basename(sys.argv[0])
    print(f"{script_name} {VERSION}")
    print(f"dar-backup.py source code is here: https://github.com/per2jensen/dar-backup")
    print('''Licensed under GNU GENERAL PUBLIC LICENSE v3, see the supplied file "LICENSE" for details.
THERE IS NO WARRANTY FOR THE PROGRAM, TO THE EXTENT PERMITTED BY APPLICABLE LAW, not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
See section 15 and section 16 in the supplied "LICENSE" file.''')


def show_examples():
    examples = """
FULL back of all backup definitions in backup.d:
  'python3 dar-backup.py  --full-backup'

FULL back of a single backup definition in backup.d
  'python3 dar-backup.py --full-backup -d <name of file in backup.d/>'

DIFF backup (differences to the latest FULL) of all backup definitions:
  'python3 dar-backup.py --differential-backup'

DIFF back of a single backup definition in backup.d
  'python3 dar-backup.py --differential-backup -d <name of file in backup.d/>'
  
INCR backup (differences to the latest DIFF) of all backup definitions:
  'python3 dar-backup.py --incremental-backup'

INCR back of a single backup definition in backup.d
  'python3 dar-backup.py --incremental-backup -d <name of file in backup.d/>'
  

--log-level
    "trace" logs output from programs (typically dar and par2) run in a subprocess
    "debug" logs various statuses and notices to better understand how to script works


File selection in `--selection`
--selection takes dar selection parameters between a pair of `"`. 

Example: select file names with this date in file names "2024-07-01" in the
directory "path/to/a/dir" where the path is relative to root of the backup.

python3 dar-backup.py --restore <name of dar archive>  --selection "-I '*2024-07-01*' -g path/to/a/dir"

See dar documentation on file selection: http://dar.linux.free.fr/doc/man/dar.html#COMMANDS%20AND%20OPTIONS
"""
    print(examples)

def main():
    global logger 

    MIN_PYTHON_VERSION = (3, 7)
    if sys.version_info < MIN_PYTHON_VERSION:
        sys.stderr.write(f"Error: This script requires Python {'.'.join(map(str, MIN_PYTHON_VERSION))} or higher.\n")
        sys.exit(1)

    parser = argparse.ArgumentParser(description="Backup and verify using dar backup definitions.")
    parser.add_argument('--full-backup', action='store_true', help="Perform a full backup.")
    parser.add_argument('--differential-backup', action='store_true', help="Perform differential backup.")
    parser.add_argument('--incremental-backup', action='store_true', help="Perform incremental backup.")
    parser.add_argument('-d', '--backup-definition', help="Specific 'recipe' to select directories and files.")
    parser.add_argument('--config-file', '-c', type=str, help="Path to 'dar-backup.conf'", default=os.path.join(os.path.dirname(__file__), '../conf/dar-backup.conf'))
    parser.add_argument('--examples', action="store_true", help="Examples of using dar-backup.py.")
    parser.add_argument('--list', action='store_true', help="List available archives.")
    parser.add_argument('--list-contents', help="List the contents of the specified archive.")
    parser.add_argument('--selection', help="dar file selection for listing/restoring specific files/directories.")
    parser.add_argument('--restore', help="Restore specified archive.")
    parser.add_argument('--restore-dir', help="Directory to restore files to.")
    parser.add_argument('--verbose', action='store_true', help="Print various status messages to screen")
    parser.add_argument('--log-level', type=str, help="`debug` or `trace`")
    parser.add_argument('--do-not-compare', action='store_true', help="do not compare restores to file system")
    parser.add_argument('--version', '-v', action='store_true', help="Show version information.")
    args = parser.parse_args()

    if args.version:
        show_version()
        sys.exit(0)

    if args.examples:
        show_examples()
        sys.exit(0)

    #logfile_location, backup_dir, test_restore_dir, backup_d, min_size_verification_mb, max_size_verification_mb, no_files_verification = read_config_old(args.config_file)
    config_settings = read_config(args.config_file)

    logger = setup_logging(config_settings.logfile_location, args.log_level)
    try:
        start_time=int(time())
        logger.info(f"=====================================")
        logger.info(f"dar-backup.py started, version: {VERSION}")
        logger.info(f"START TIME: {start_time}")
        logger.debug(f"`args`:\n{args}")
        logger.debug(f"`config_settings`:\n{config_settings}")

        if not config_settings.backup_d_dir.startswith("/"):
            backup_d = os.path.normpath(os.path.join(os.path.dirname(__file__), backup_d))
        current_dir =  os.path.normpath(os.path.dirname(__file__))
        args.verbose and (print(f"Current directory: {current_dir}"))
        args.verbose and args.full_backup         and (print(f"Type of backup: FULL"))
        args.verbose and args.differential_backup and (print(f"Type of backup: DIFF"))
        args.verbose and args.incremental_backup  and (print(f"Type of backup: INCR"))
        args.verbose and (print(f"Backup.d:          {config_settings.backup_d_dir}"))
        args.verbose and (print(f"Backup dir:        {config_settings.backup_dir}"))
        args.verbose and (print(f"Test restore dir:  {config_settings.test_restore_dir}"))
        args.verbose and (print(f"Logfile location:  {config_settings.logfile_location}"))
        args.verbose and (print(f"--do-not-compare:  {args.do_not_compare}"))
    
        if args.full_backup and not args.differential_backup and not args.incremental_backup:
            perform_backup(args, config_settings, "FULL")
        elif args.differential_backup and not args.full_backup and not args.incremental_backup:
            perform_backup(args, config_settings, "DIFF")
        elif args.incremental_backup  and not args.full_backup and not args.differential_backup:
            perform_backup(args, config_settings, "INCR")
        elif args.list:
            list_backups(config_settings.backup_dir, args.backup_definition)
        elif args.list_contents:
            list_contents(args.list_contents, config_settings.backup_dir, args.selection)
        elif args.restore:
            restore_dir = args.restore_dir if args.restore_dir else config_settings.test_restore_dir
            restore_backup(args.restore, config_settings.backup_dir, restore_dir, args.selection)
        else:
            parser.print_help()
    except Exception as e:
        logger.exception("An error occurred during the backup process.", e)
        sys.exit(1)

    end_time=int(time())
    logger.info(f"END TIME: {end_time}")

    error_lines = extract_error_lines(config_settings.logfile_location, start_time, end_time)
    if len(error_lines) > 0:
        args.verbose and print("Errors encountered")
        for line in error_lines:
            print(line)
        sys.exit(1)
    else:
        args.verbose and print("No errors encountered")
        sys.exit(0)


if __name__ == "__main__":
    main()
